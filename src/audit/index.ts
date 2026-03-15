/**
 * Emits structured audit events gated by verbosity tiers.
 *
 * Callback-based — the consumer decides where events go.
 * Audit failures are swallowed (onError callback if provided).
 * The emitter must NEVER throw or crash the pipeline.
 *
 * Thread-safety: same as FrequencyTracker — not thread-safe,
 * designed for single-threaded Node.js event loop.
 */

import { createHash } from "node:crypto";

import type {
  AuditEmitterConfig,
  TypedAuditEvent,
  ScanAuditEvent,
  SyntacticAuditEvent,
  FrequencyAuditEvent,
  SanitizeAuditEvent,
  ProfileAuditEvent,
  AuditConfigEvent,
  FlagsSummaryEvent,
  RuleTriggeredEvent,
  OutputDiffEvent,
  RawCaptureEvent,
} from "../types/audit.js";

import {
  EVENT_MIN_VERBOSITY,
  meetsVerbosity,
  DEFAULT_AUDIT_CONFIG,
} from "../types/audit.js";

/** Compute SHA-256 hash of a string (convenience for output_diff) */
export function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

export class AuditEmitter {
  private readonly config: AuditEmitterConfig;
  private emitCount = 0;
  private dropCount = 0;
  private errorCount = 0;

  constructor(config?: Partial<AuditEmitterConfig>) {
    this.config = { ...DEFAULT_AUDIT_CONFIG, ...config };
    this.emitConfigLoaded();
  }

  // ---------------------------------------------------------------------------
  // Core emit
  // ---------------------------------------------------------------------------

  /**
   * Gate and deliver an event.
   * Returns true if the event was emitted, false if dropped.
   */
  emit(event: TypedAuditEvent): boolean {
    if (!this.config.enabled) {
      this.dropCount++;
      return false;
    }

    const requiredVerbosity = EVENT_MIN_VERBOSITY[event.event];

    // Special case: syntactic_pass force-emitted when alerting is enabled
    if (event.event === "syntactic_pass" && this.config.alertingEnabled) {
      // Emit regardless of verbosity
    } else if (!meetsVerbosity(this.config.verbosity, requiredVerbosity)) {
      this.dropCount++;
      return false;
    }

    // Special case: flags_summary suppressed at high+ (replaced by rule_triggered)
    if (
      event.event === "flags_summary" &&
      meetsVerbosity(this.config.verbosity, "high")
    ) {
      this.dropCount++;
      return false;
    }

    // Deliver to consumer
    try {
      this.config.onEvent?.(event);
      this.emitCount++;
      return true;
    } catch (error) {
      this.errorCount++;
      try {
        this.config.onError?.(error, event);
      } catch {
        // onError itself threw — swallow completely
      }
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Convenience emitters
  // ---------------------------------------------------------------------------

  /** Emit a scanner result event */
  emitScan(params: {
    sessionId: string;
    safe: boolean;
    findingCount: number;
    blockingFindingCount: number;
    ruleIds: string[];
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): ScanAuditEvent | null {
    const event: ScanAuditEvent = {
      ...params,
      event: params.safe ? "scan_pass" : "scan_block",
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /** Emit a syntactic pre-filter result event */
  emitSyntactic(params: {
    sessionId: string;
    pass: boolean;
    ruleIds: string[];
    flags: string[];
    hasFlags: boolean;
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): SyntacticAuditEvent | null {
    const eventType = !params.pass
      ? "syntactic_fail"
      : params.hasFlags
        ? "syntactic_flags"
        : "syntactic_pass";

    // Strip hasFlags from spread — not part of SyntacticAuditEvent
    const { hasFlags: _, ...rest } = params;
    const event: SyntacticAuditEvent = {
      ...rest,
      event: eventType,
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /** Emit a frequency escalation event */
  emitFrequency(params: {
    sessionId: string;
    previousScore: number;
    currentScore: number;
    tier: "tier1" | "tier2" | "tier3";
    terminated: boolean;
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): FrequencyAuditEvent | null {
    const event: FrequencyAuditEvent = {
      ...params,
      event:
        `frequency_escalation_${params.tier}` as FrequencyAuditEvent["event"],
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /** Emit a sanitization result event */
  emitSanitize(params: {
    sessionId: string;
    redactionCount: number;
    charactersRemoved: number;
    redactedRuleIds: string[];
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): SanitizeAuditEvent | null {
    const event: SanitizeAuditEvent = {
      ...params,
      event: "content_sanitized",
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /** Emit profile loaded event */
  emitProfileLoaded(params: {
    sessionId: string;
    profileId: string;
    baseProfileId: string;
    suppressedRules: string[];
    frequencyOverrides: Record<string, number>;
    agentId?: string;
  }): ProfileAuditEvent | null {
    const event: ProfileAuditEvent = {
      ...params,
      event: "profile_loaded",
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /** Emit flags summary (standard tier — auto-suppressed at high+) */
  emitFlagsSummary(params: {
    sessionId: string;
    stage: "scanner" | "syntactic";
    ruleIds: string[];
    flagCount: number;
    blocked: boolean;
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): FlagsSummaryEvent | null {
    const event: FlagsSummaryEvent = {
      ...params,
      event: "flags_summary",
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /**
   * Emit per-rule triggered events (high tier).
   * Fans out a ruleIds array into individual events.
   */
  emitRuleTriggered(params: {
    sessionId: string;
    ruleIds: string[];
    severities: Record<string, "block" | "flag">;
    stage: "scanner" | "syntactic";
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): RuleTriggeredEvent[] {
    const emitted: RuleTriggeredEvent[] = [];
    for (const ruleId of params.ruleIds) {
      const category = ruleId.split(".").slice(0, -1).join(".");
      const event: RuleTriggeredEvent = {
        event: "rule_triggered",
        timestamp: new Date().toISOString(),
        sessionId: params.sessionId,
        ruleId,
        ruleCategory: category,
        severity: params.severities[ruleId] ?? "flag",
        stage: params.stage,
        messageId: params.messageId,
        agentId: params.agentId,
        profile: params.profile,
      };
      if (this.emit(event)) {
        emitted.push(event);
      }
    }
    return emitted;
  }

  /** Emit output diff event (high tier) */
  emitOutputDiff(params: {
    sessionId: string;
    removals: OutputDiffEvent["removals"];
    replacements: OutputDiffEvent["replacements"];
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): OutputDiffEvent | null {
    const event: OutputDiffEvent = {
      ...params,
      event: "output_diff",
      timestamp: new Date().toISOString(),
    };
    return this.emit(event) ? event : null;
  }

  /** Emit raw content capture (maximum tier) */
  emitRawCapture(params: {
    sessionId: string;
    type: "input" | "output";
    content: string;
    messageId?: string;
    agentId?: string;
    profile?: string;
  }): RawCaptureEvent | null {
    const event: RawCaptureEvent = {
      event:
        params.type === "input"
          ? "raw_input_captured"
          : "raw_output_captured",
      timestamp: new Date().toISOString(),
      sessionId: params.sessionId,
      content: params.content,
      contentLength: params.content.length,
      sha256: sha256(params.content),
      messageId: params.messageId,
      agentId: params.agentId,
      profile: params.profile,
    };
    return this.emit(event) ? event : null;
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  /** Number of events successfully emitted */
  get emitted(): number {
    return this.emitCount;
  }

  /** Number of events dropped (disabled, below verbosity, or suppressed) */
  get dropped(): number {
    return this.dropCount;
  }

  /** Number of events where onEvent threw */
  get errors(): number {
    return this.errorCount;
  }

  /** Check if this emitter's configured verbosity meets the given tier */
  meetsVerbosity(required: import("../types/audit.js").AuditVerbosity): boolean {
    return meetsVerbosity(this.config.verbosity, required);
  }

  /** Reset counters (useful for testing) */
  resetStats(): void {
    this.emitCount = 0;
    this.dropCount = 0;
    this.errorCount = 0;
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  /** Emit audit_config_loaded on construction */
  private emitConfigLoaded(): void {
    if (!this.config.enabled) return;

    const event: AuditConfigEvent = {
      event: "audit_config_loaded",
      timestamp: new Date().toISOString(),
      sessionId: "__init__",
      verbosity: this.config.verbosity,
      enabled: this.config.enabled,
    };
    this.emit(event);
  }
}
