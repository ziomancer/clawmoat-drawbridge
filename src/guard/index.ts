import type { EscalationTier } from "../types/frequency.js";
import type { DrawbridgePipeline } from "../pipeline/index.js";
import type { FrequencyTracker } from "../frequency/index.js";
import type {
  ToolCallInput,
  ToolCallGuardConfig,
  ToolCallGuardResult,
  ClawMoatPolicyEngine,
  ToolPolicyResult,
} from "./types.js";
import { sha256 } from "../lib/sha256.js";
import { safeStringify } from "../lib/safe-stringify.js";

const TOOL_NAME_MAP: Record<string, string> = {
  bash: "exec",
  shell: "exec",
  execute: "exec",
  run_command: "exec",
  file_read: "read",
  file_write: "write",
  file_edit: "write",
  edit: "write",
  apply_patch: "write",
  web_fetch: "browser",
  web_search: "browser",
  navigate: "browser",
};

function normalizeForPolicy(rawToolName: string): string {
  const sep = rawToolName.lastIndexOf("__");
  const unprefixed = sep >= 0 ? rawToolName.slice(sep + 2) : rawToolName;
  const lower = unprefixed.toLowerCase();
  return TOOL_NAME_MAP[lower] ?? lower;
}

function deriveTier(
  tracker: FrequencyTracker,
  sessionId: string,
): EscalationTier {
  const state = tracker.getState(sessionId);
  if (!state) return "none";
  if (state.terminated) return "tier3";
  const thresholds = tracker.thresholds;
  if (state.lastScore >= thresholds.tier3) return "tier3";
  if (state.lastScore >= thresholds.tier2) return "tier2";
  if (state.lastScore >= thresholds.tier1) return "tier1";
  return "none";
}

export class ToolCallGuard {
  private readonly pipeline: DrawbridgePipeline;
  private readonly tracker: FrequencyTracker;
  private readonly engine: ClawMoatPolicyEngine | null;
  private readonly policies: Record<string, unknown>;
  private readonly exemptTools: Set<string>;
  private readonly restrictedTools: Set<string>;
  private readonly escalateWarnings: boolean;
  private readonly scanParams: boolean;

  constructor(config: ToolCallGuardConfig) {
    this.pipeline = config.pipeline;
    this.tracker = config.tracker;
    this.policies = config.policies ?? {};
    this.escalateWarnings = config.escalateWarnings ?? true;
    this.scanParams = config.scanParams ?? true;

    this.exemptTools = new Set(
      (config.exemptTools ?? []).map((t) => t.toLowerCase()),
    );
    this.restrictedTools = new Set(
      (config.restrictedTools ?? ["read"]).map((t) => t.toLowerCase()),
    );

    if (
      config.engine &&
      typeof (config.engine as unknown as Record<string, unknown>).evaluateTool ===
        "function"
    ) {
      this.engine = config.engine;
    } else {
      this.engine = null;
      if (config.engine) {
        console.warn(
          "[drawbridge:guard] ClawMoat engine lacks evaluateTool — policy evaluation disabled",
        );
      }
    }
  }

  evaluate(input: ToolCallInput): ToolCallGuardResult {
    try {
      return this.evaluateInternal(input);
    } catch (err) {
      console.warn("[drawbridge:guard] Fail-open:", (err as Error).message ?? err);
      const normalized = normalizeForPolicy(input.toolName);
      return {
        block: false,
        audit: {
          toolName: normalized,
          paramsHash: sha256(input.params ? safeStringify(input.params) : ""),
          policyDecision: "allow",
          policyReason: "fail-open: guard error",
          escalationApplied: false,
          sessionTier: "none",
          paramScanUnsafe: false,
          paramScanFindingCount: 0,
        },
      };
    }
  }

  private evaluateInternal(input: ToolCallInput): ToolCallGuardResult {
    const normalized = normalizeForPolicy(input.toolName);
    const paramsHash = sha256(
      input.params ? safeStringify(input.params) : "",
    );
    const sessionTier = deriveTier(this.tracker, input.sessionId);

    // Step 1: Terminated session → block unconditionally
    if (sessionTier === "tier3") {
      return {
        block: true,
        blockReason: "Session terminated — all tool calls blocked",
        audit: {
          toolName: normalized,
          paramsHash,
          policyDecision: "deny",
          policyReason: "session terminated (tier3)",
          escalationApplied: false,
          sessionTier,
          paramScanUnsafe: false,
          paramScanFindingCount: 0,
        },
      };
    }

    // Step 2: Exempt tools → skip evaluation
    if (this.exemptTools.has(normalized)) {
      return {
        block: false,
        audit: {
          toolName: normalized,
          paramsHash,
          policyDecision: "allow",
          policyReason: "exempt tool",
          escalationApplied: false,
          sessionTier,
          paramScanUnsafe: false,
          paramScanFindingCount: 0,
        },
      };
    }

    // Step 3: Parameter content scan
    let paramScanUnsafe = false;
    let paramScanFindingCount = 0;
    if (this.scanParams && input.params) {
      const content = safeStringify(input.params);
      const result = this.pipeline.inspect({
        content,
        sessionId: input.sessionId,
        source: "tool_params",
        toolName: input.toolName,
      });
      paramScanUnsafe = !result.safe;
      paramScanFindingCount = result.scanResult?.findings?.length ?? 0;

      if (!result.safe) {
        return {
          block: true,
          blockReason: `Tool parameter content flagged as unsafe (${paramScanFindingCount} finding(s))`,
          audit: {
            toolName: normalized,
            paramsHash,
            policyDecision: "deny",
            policyReason: "parameter content scan unsafe",
            escalationApplied: false,
            sessionTier,
            paramScanUnsafe,
            paramScanFindingCount,
          },
        };
      }
    }

    // Step 4: ClawMoat policy evaluation
    let policyResult: ToolPolicyResult = {
      decision: "allow",
      reason: "No policy engine",
    };
    if (this.engine) {
      policyResult = this.engine.evaluateTool(
        normalized,
        input.params ?? {},
      );
    }

    let block = false;
    let blockReason: string | undefined;
    let escalationApplied = false;

    if (
      policyResult.decision === "deny" ||
      policyResult.decision === "review"
    ) {
      block = true;
      blockReason =
        policyResult.decision === "deny"
          ? `Tool "${normalized}" denied by policy: ${policyResult.reason ?? "no reason"}`
          : `Tool "${normalized}" requires review (auto-blocked in agent pipeline)`;
    } else if (policyResult.decision === "warn") {
      // Step 5: Frequency-aware escalation — promote warn at tier1+
      if (
        this.escalateWarnings &&
        (sessionTier === "tier1" ||
          sessionTier === "tier2")
      ) {
        block = true;
        blockReason = `Tool "${normalized}" warning escalated to block (session at ${sessionTier})`;
        escalationApplied = true;
      }
    }

    // Step 5 continued: tier2+ restricted tools check
    if (
      !block &&
      (sessionTier === "tier2") &&
      !this.restrictedTools.has(normalized)
    ) {
      block = true;
      blockReason = `Tool "${normalized}" not in restricted allowlist (session at tier2)`;
      escalationApplied = true;
    }

    return {
      block,
      blockReason,
      audit: {
        toolName: normalized,
        paramsHash,
        policyDecision: policyResult.decision,
        policyReason: policyResult.reason,
        policySeverity: policyResult.severity,
        escalationApplied,
        sessionTier,
        paramScanUnsafe,
        paramScanFindingCount,
      },
    };
  }
}
