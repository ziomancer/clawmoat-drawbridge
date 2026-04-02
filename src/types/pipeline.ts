/**
 * Pipeline orchestration types: routes content through validation stages,
 * scanner, frequency tracking, and audit emission.
 *
 * v1.0 — full pipeline orchestration.
 */

import type { DrawbridgeScanResult, DrawbridgeScannerConfig, SanitizeConfig, SanitizeResult } from "./scanner.js";
import type { FrequencyTrackerConfig, FrequencyUpdateResult, EscalationTier } from "./frequency.js";
import type { FrequencyTracker } from "../frequency/index.js";
import type { BuiltInProfileId, CustomProfileDefinition } from "./profiles.js";
import type { SyntacticFilterConfig, SyntacticFilterResult, SchemaValidationConfig, SchemaValidationResult, TwoPassConfig } from "./validation.js";
import type { AuditEmitterConfig, TypedAuditEvent } from "./audit.js";
import type { AlertManagerConfig, AlertPayload } from "./alerting.js";
import type { ContentSource } from "./common.js";

/** Content source type (re-exported from common for convenience) */
export type { ContentSource };

/** Trust classification for MCP servers */
export type TrustTier = "trusted" | "untrusted";

/** Input to the pipeline */
export interface PipelineInput {
  /** The raw content to inspect */
  content: string | unknown;
  /** Where the content came from */
  source: ContentSource;
  /**
   * For MCP sources: which server produced this result.
   *
   * @security CALLER MUST verify server identity at the transport layer.
   * If sourced from message content, attackers can spoof trusted servers
   * to bypass all inspection.
   * Configure `validateServerName` on DrawbridgePipelineConfig for runtime validation.
   */
  serverName?: string;
  /** For MCP sources: which tool was called */
  toolName?: string;
  /**
   * Session identifier for frequency tracking.
   *
   * @security CALLER MUST derive this from authenticated transport state
   * (e.g., server-signed session token). If sourced from client input,
   * attackers can poison other sessions' frequency scores.
   * Configure `validateSessionId` on DrawbridgePipelineConfig for runtime validation.
   */
  sessionId: string;
  /** Turn identifier for audit correlation */
  messageId?: string;
  toolCallId?: string;
}

/** Full pipeline result */
export interface PipelineResult {
  /**
   * Overall safety verdict — false if ANY injection-detection stage blocked.
   * Does not reflect schema validation results — check `schemaResult.pass`
   * independently for structural validity.
   */
  safe: boolean;

  /** Was content from a trusted source? (bypassed full inspection) */
  trusted: boolean;

  /** Pre-filter result (null if trusted fast-path or pre-filter disabled) */
  preFilterResult: SyntacticFilterResult | null;

  /** Schema validation result (null if disabled, source is not MCP, or content was hard-blocked by two-pass gate) */
  schemaResult: SchemaValidationResult | null;

  /** Scanner result (null if trusted fast-path, or skipped by two-pass) */
  scanResult: DrawbridgeScanResult | null;

  /** Sanitize result (null if nothing to redact or trusted fast-path) */
  sanitizeResult: SanitizeResult | null;

  /** Current session escalation tier after this inspection */
  escalationTier: EscalationTier;

  /** Frequency update result (null if tracker disabled or trusted) */
  frequencyResult: FrequencyUpdateResult | null;

  /** Whether the session is terminated (tier3 reached) */
  terminated: boolean;

  /** Audit events produced during this inspection */
  auditEvents: TypedAuditEvent[];

  /** Alerts fired during this inspection (may be empty) */
  alerts: AlertPayload[];

  /** Convenience shorthand for sanitizeResult.sanitized */
  sanitizedContent: string | null;

  /** The content that was inspected (stringified if object) */
  inspectedContent: string;
}

/** Full Drawbridge pipeline configuration */
export interface DrawbridgePipelineConfig {
  /** Scanner (ClawMoat) config. Omit to use defaults. */
  scanner?: DrawbridgeScannerConfig;

  /** Injected ClawMoat engine instance (for testing or custom setup) */
  engine?: unknown;

  /** Frequency tracker config. Omit to use defaults. Ignored when `tracker` is provided. */
  frequency?: Partial<FrequencyTrackerConfig>;

  /**
   * Optional injected FrequencyTracker — enables shared state across multiple
   * pipelines. When provided, `frequency` config is ignored; the injected
   * tracker's config takes precedence. Both pipelines must be on the same
   * event loop; mutations are visible cross-pipeline immediately.
   */
  tracker?: FrequencyTracker;

  /** Context profile selection. Default: "general" */
  profile?: BuiltInProfileId | CustomProfileDefinition;

  /** Syntactic pre-filter config. Omit to use defaults. */
  syntactic?: Partial<SyntacticFilterConfig> & { enabled?: boolean };

  /** Schema validation config. Omit to use defaults (disabled). */
  schema?: Partial<SchemaValidationConfig>;

  /** Two-pass gating config. Default: disabled */
  twoPass?: Partial<TwoPassConfig>;

  /** Sanitize/redaction config. Omit to use defaults. */
  sanitize?: Partial<SanitizeConfig> & {
    /** Whether to redact content. Default: true */
    enabled?: boolean;
    /** Redact all findings or only blocking ones. Default: false (blocking only) */
    redactAll?: boolean;
  };

  /** Audit emitter config. Omit to use defaults. */
  audit?: Partial<AuditEmitterConfig>;

  /** Alert manager config. Omit to use defaults. */
  alerting?: Partial<AlertManagerConfig>;

  /** MCP servers that bypass full inspection. Default: [] */
  trustedServers?: string[];

  /**
   * Optional callback to validate session IDs before they're used for
   * frequency tracking. If provided, called with the raw sessionId from
   * PipelineInput. Return true to accept, false to reject.
   *
   * @security sessionId is caller-provided and unvalidated by default.
   * Without this callback, an attacker who knows a victim's session ID
   * can poison their frequency score. Derive sessionId from your
   * authenticated transport layer (e.g., server-signed session token),
   * not from client-provided input.
   */
  validateSessionId?: (sessionId: string) => boolean;

  /**
   * Optional callback to validate server names before trust resolution.
   * If provided, called with the serverName from PipelineInput.
   * Return true to accept the claimed identity, false to reject.
   *
   * @security serverName is caller-provided and unvalidated by default.
   * Without this callback, an attacker can spoof a trusted server name
   * to bypass all inspection. Verify server identity at the transport
   * layer (e.g., mTLS, signed tokens) before trusting serverName.
   */
  validateServerName?: (serverName: string) => boolean;
}
