/**
 * Pipeline orchestration: routes content through validation stages,
 * scanner, frequency tracking, and audit emission.
 *
 * The pipeline is the main entry point for consumers who want the
 * full Drawbridge experience. For scanner-only usage, import
 * DrawbridgeScanner directly.
 *
 * NOT IMPLEMENTED in v0.1. Types exported for API stability.
 */

import type { DrawbridgeScanResult, DrawbridgeScannerConfig } from "./scanner.js";
import type { FrequencyConfig, EscalationTier } from "./frequency.js";
import type { ContextProfile, BuiltInProfileId, CustomProfileDefinition } from "./profiles.js";
import type { TwoPassConfig, PreFilterResult } from "./validation.js";
import type { AuditConfig, AuditEvent } from "./audit.js";
import type { AlertingConfig } from "./alerting.js";
import type { ContentSource } from "./common.js";

// Re-export for convenience
export type { ContentSource };

/** Trust classification for MCP servers */
export type TrustTier = "trusted" | "untrusted";

/** Input to the pipeline */
export interface PipelineInput {
  /** The raw content to inspect */
  content: string | unknown;
  /** Where the content came from */
  source: ContentSource;
  /** For MCP sources: which server produced this result */
  serverName?: string;
  /** For MCP sources: which tool was called */
  toolName?: string;
  /** Session identifier for frequency tracking */
  sessionId: string;
  /** Turn identifier for audit correlation */
  messageId?: string;
  toolCallId?: string;
}

/** Full pipeline result */
export interface PipelineResult {
  /** Overall safety verdict */
  safe: boolean;
  /** Was content from a trusted source? (bypassed full inspection) */
  trusted: boolean;
  /** Scanner result (null if trusted fast-path) */
  scanResult: DrawbridgeScanResult | null;
  /** Pre-filter result (null if not yet implemented) */
  preFilterResult: PreFilterResult | null;
  /** Current session escalation tier */
  escalationTier: EscalationTier;
  /** Audit events produced during this inspection */
  auditEvents: AuditEvent[];
}

/** Full Drawbridge pipeline configuration */
export interface DrawbridgePipelineConfig {
  scanner?: DrawbridgeScannerConfig;
  frequency?: Partial<FrequencyConfig>;
  profile?: BuiltInProfileId | CustomProfileDefinition;
  validation?: {
    syntactic?: { enabled: boolean; maxPayloadBytes?: number; maxJsonDepth?: number };
    schema?: { enabled: boolean };
    twoPass?: Partial<TwoPassConfig>;
  };
  audit?: Partial<AuditConfig>;
  alerting?: Partial<AlertingConfig>;
  /** MCP servers that bypass full inspection */
  trustedServers?: string[];
}
