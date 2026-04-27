/**
 * before_tool_call hook — tool call policy guard.
 * Priority 10 (runs before enricher at 50).
 * Fail-open: errors → allow, log warning.
 */

import type { PluginState } from "../pipeline-factory.js";
import { deriveSessionId } from "../session.js";
import type {
  BeforeToolCallEvent,
  BeforeToolCallContext,
  BeforeToolCallResult,
} from "../types/openclaw.js";

const PASS: BeforeToolCallResult = Object.freeze({});

export function handleBeforeToolCallGuard(
  state: PluginState,
  event: BeforeToolCallEvent,
  ctx: BeforeToolCallContext,
): BeforeToolCallResult {
  try {
    if (!state.config.toolGuardEnabled) return PASS;
    if (!state.guard) return PASS;

    const normalizedLower = event.toolName.toLowerCase();
    const exemptTools = state.config.exemptTools;
    if (exemptTools.some((t) => normalizedLower.includes(t.toLowerCase()))) {
      return PASS;
    }

    const sessionId = deriveSessionId(ctx);

    const result = state.guard.evaluate({
      toolName: event.toolName,
      params: event.params,
      sessionId,
      toolCallId: event.toolCallId,
      agentId: ctx.agentId,
    });

    // Emit audit event via audit sink
    if (state.auditSink) {
      const eventType = result.block
        ? ("tool_policy_block" as const)
        : ("tool_policy_allow" as const);
      state.auditSink.emit({
        event: eventType,
        timestamp: new Date().toISOString(),
        sessionId,
        toolName: result.audit.toolName,
        paramsHash: result.audit.paramsHash,
        policyDecision: result.audit.policyDecision,
        policyReason: result.audit.policyReason,
        policySeverity: result.audit.policySeverity,
        escalationApplied: result.audit.escalationApplied,
        sessionTier: result.audit.sessionTier,
        paramScanUnsafe: result.audit.paramScanUnsafe,
        paramScanFindingCount: result.audit.paramScanFindingCount,
        agentId: ctx.agentId,
        toolCallId: event.toolCallId,
      } as import("@vigil-harbor/clawmoat-drawbridge").ToolPolicyAuditEvent);
    }

    // If blocked write tool, also emit write_failed
    if (result.block && isWriteTool(result.audit.toolName) && state.auditSink) {
      state.auditSink.emit({
        event: "write_failed",
        timestamp: new Date().toISOString(),
        sessionId,
        toolName: result.audit.toolName,
        cause: "policy_block",
        errorCategory: "policy",
        errorSummary: result.blockReason ?? "blocked by guard",
        agentId: ctx.agentId,
        toolCallId: event.toolCallId,
      } as import("@vigil-harbor/clawmoat-drawbridge").WriteFailedAuditEvent);
    }

    if (result.block) {
      return { block: true, blockReason: result.blockReason };
    }

    return PASS;
  } catch (err) {
    console.warn(
      "[drawbridge:guard] Fail-open in before_tool_call:",
      (err as Error).message ?? err,
    );
    return PASS;
  }
}

function isWriteTool(normalizedName: string): boolean {
  return normalizedName === "write";
}
