/**
 * Structured audit trail with configurable verbosity tiers.
 * Callback-based — the consumer decides where events go.
 *
 * Spec reference: Audit Trail Enhancement v2.2
 */

import type { AuditVerbosity } from "./common.js";

/** Verbosity tier (re-exported from common for convenience) */
export type { AuditVerbosity };

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/** All audit event types in the Drawbridge pipeline */
export type AuditEventType =
  // Scanner events
  | "scan_pass"
  | "scan_block"
  // Pre-filter events
  | "syntactic_pass"
  | "syntactic_fail"
  | "syntactic_flags"
  // Schema validation events
  | "schema_pass"
  | "schema_fail"
  // Frequency events
  | "frequency_escalation_tier1"
  | "frequency_escalation_tier2"
  | "frequency_escalation_tier3"
  // Sanitize events
  | "content_sanitized"
  // Profile events
  | "profile_loaded"
  // Audit lifecycle events
  | "audit_config_loaded"
  // Standard-tier rollup
  | "flags_summary"
  // High-tier detail
  | "rule_triggered"
  | "output_diff"
  // Maximum-tier raw capture
  | "raw_input_captured"
  | "raw_output_captured";

// ---------------------------------------------------------------------------
// Verbosity gating
// ---------------------------------------------------------------------------

const VERBOSITY_RANK: Record<AuditVerbosity, number> = {
  minimal: 1,
  standard: 2,
  high: 3,
  maximum: 4,
};

/**
 * Minimum verbosity required to emit each event type.
 * Events are emitted when the configured verbosity >= the event's minimum.
 */
export const EVENT_MIN_VERBOSITY: Record<AuditEventType, AuditVerbosity> = Object.freeze({
  // Minimal tier — security-relevant outcomes only
  scan_block: "minimal",
  syntactic_fail: "minimal",
  frequency_escalation_tier1: "minimal",
  frequency_escalation_tier2: "minimal",
  frequency_escalation_tier3: "minimal",
  profile_loaded: "minimal",
  audit_config_loaded: "minimal",

  schema_fail: "minimal",

  // Standard tier — pass events and summaries
  scan_pass: "standard",
  syntactic_pass: "standard",
  schema_pass: "standard",
  syntactic_flags: "standard",
  flags_summary: "standard",
  content_sanitized: "standard",

  // High tier — per-rule detail and diff
  rule_triggered: "high",
  output_diff: "high",

  // Maximum tier — raw content capture
  raw_input_captured: "maximum",
  raw_output_captured: "maximum",
});

/** Check if a verbosity level meets or exceeds a required minimum */
export function meetsVerbosity(
  configured: AuditVerbosity,
  required: AuditVerbosity,
): boolean {
  return VERBOSITY_RANK[configured] >= VERBOSITY_RANK[required];
}

// ---------------------------------------------------------------------------
// Event shapes
// ---------------------------------------------------------------------------

/** Base fields present on every audit event */
export interface AuditEvent {
  event: AuditEventType;
  timestamp: string;
  sessionId: string;
  /** Optional — Drawbridge doesn't assume agent architecture */
  agentId?: string;
  /** Correlates events for the same input */
  messageId?: string;
  toolCallId?: string;
  /** Active context profile when event was produced */
  profile?: string;
}

/** scan_pass / scan_block */
export interface ScanAuditEvent extends AuditEvent {
  event: "scan_pass" | "scan_block";
  safe: boolean;
  findingCount: number;
  blockingFindingCount: number;
  ruleIds: string[];
}

/** syntactic_pass / syntactic_fail / syntactic_flags */
export interface SyntacticAuditEvent extends AuditEvent {
  event: "syntactic_pass" | "syntactic_fail" | "syntactic_flags";
  pass: boolean;
  ruleIds: string[];
  flags: string[];
}

/** schema_pass / schema_fail */
export interface SchemaAuditEvent extends AuditEvent {
  event: "schema_pass" | "schema_fail";
  pass: boolean;
  violations: string[];
  ruleIds: string[];
  serverName: string;
  toolName: string;
  trusted?: boolean;
}

/** frequency_escalation_tier1/2/3 */
export interface FrequencyAuditEvent extends AuditEvent {
  event:
    | "frequency_escalation_tier1"
    | "frequency_escalation_tier2"
    | "frequency_escalation_tier3";
  previousScore: number;
  currentScore: number;
  tier: string;
  terminated: boolean;
}

/** content_sanitized */
export interface SanitizeAuditEvent extends AuditEvent {
  event: "content_sanitized";
  redactionCount: number;
  charactersRemoved: number;
  redactedRuleIds: string[];
}

/** profile_loaded */
export interface ProfileAuditEvent extends AuditEvent {
  event: "profile_loaded";
  profileId: string;
  baseProfileId: string;
  suppressedRules: string[];
  frequencyOverrides: Record<string, number>;
}

/** audit_config_loaded */
export interface AuditConfigEvent extends AuditEvent {
  event: "audit_config_loaded";
  verbosity: AuditVerbosity;
  enabled: boolean;
}

/** flags_summary (standard tier — suppressed at high+) */
export interface FlagsSummaryEvent extends AuditEvent {
  event: "flags_summary";
  stage: "scanner" | "syntactic";
  ruleIds: string[];
  flagCount: number;
  blocked: boolean;
}

/** rule_triggered (high tier) */
export interface RuleTriggeredEvent extends AuditEvent {
  event: "rule_triggered";
  ruleId: string;
  ruleCategory: string;
  severity: "block" | "flag";
  stage: "scanner" | "syntactic";
}

/**
 * output_diff (high tier).
 *
 * `removals` and `replacements` are parallel arrays — `removals[i]` and
 * `replacements[i]` describe the same physical redaction. Do not filter
 * or reorder one array independently without applying the same operation
 * to the other.
 */
export interface OutputDiffEvent extends AuditEvent {
  event: "output_diff";
  removals: Array<{
    ruleId: string;
    position: number;
    matchedLength: number;
    /** HMAC-SHA256 of removed content if hashRedactions + hmacKey configured, otherwise empty string */
    contentHash: string;
    fallback: boolean;
  }>;
  replacements: Array<{
    ruleId: string;
    lengthBefore: number;
    lengthAfter: number;
    /** HMAC-SHA256 of content before replacement if hashRedactions + hmacKey configured, otherwise empty string */
    contentHash: string;
  }>;
}

/** raw_input_captured / raw_output_captured (maximum tier) */
export interface RawCaptureEvent extends AuditEvent {
  event: "raw_input_captured" | "raw_output_captured";
  /** The raw content itself — consumer handles storage/encryption */
  content: string;
  contentLength: number;
  sha256: string;
}

/** Discriminated union of all typed audit events */
export type TypedAuditEvent =
  | ScanAuditEvent
  | SyntacticAuditEvent
  | SchemaAuditEvent
  | FrequencyAuditEvent
  | SanitizeAuditEvent
  | ProfileAuditEvent
  | AuditConfigEvent
  | FlagsSummaryEvent
  | RuleTriggeredEvent
  | OutputDiffEvent
  | RawCaptureEvent;

// ---------------------------------------------------------------------------
// Emitter config
// ---------------------------------------------------------------------------

/** Audit emitter configuration */
export interface AuditEmitterConfig {
  /** Master toggle. When false, all emit calls are no-ops. Default: true */
  enabled: boolean;

  /** Verbosity tier. Controls which events are emitted. Default: "standard" */
  verbosity: AuditVerbosity;

  /**
   * Event handler. Called for every event that passes verbosity gating.
   * If not provided, events are silently dropped (useful for testing with emit counting).
   */
  onEvent?: (event: TypedAuditEvent) => void;

  /**
   * Error handler. Called if onEvent throws.
   * If not provided, errors are silently swallowed (audit must never crash the pipeline).
   */
  onError?: (error: unknown, event: TypedAuditEvent) => void;

  /**
   * Whether to force-emit syntactic_pass at all verbosity tiers.
   * Required when alerting is enabled (for Rule 4 correlation).
   * Default: false
   */
  alertingEnabled: boolean;
}

/** Default audit emitter configuration */
export const DEFAULT_AUDIT_CONFIG: AuditEmitterConfig = {
  enabled: true,
  verbosity: "standard",
  alertingEnabled: false,
};
