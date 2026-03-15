/**
 * Structured audit trail with configurable verbosity tiers.
 *
 * Spec reference: Audit Trail Enhancement v2.2
 *
 * NOT IMPLEMENTED in v0.1. Types exported for pipeline type stability.
 */

import type { AuditVerbosity } from "./common.js";

/** All audit event types across the pipeline */
export type AuditEventType =
  // Existing session memory events
  | "sanitized_pass"
  | "sanitized_block"
  | "write_failed"
  | "signal_failed"
  // Input validation events
  | "syntactic_pass"
  | "syntactic_fail"
  | "syntactic_flags"
  | "schema_pass"
  | "schema_fail"
  | "twopass_hard_block"
  // Frequency events
  | "frequency_escalation_tier1"
  | "frequency_escalation_tier2"
  | "frequency_escalation_tier3"
  // Context profile events
  | "context_profile_loaded"
  // Audit config events
  | "audit_config_loaded"
  // High-verbosity events
  | "rule_triggered"
  | "flags_summary"
  | "output_diff"
  // Maximum-verbosity events
  | "raw_input_captured"
  | "raw_output_captured";

/** Base audit event shape */
export interface AuditEvent {
  event: AuditEventType;
  timestamp: string;
  sessionId: string;
  agentId?: string;
  messageId?: string;
  toolCallId?: string;
  contextProfile?: string;
  [key: string]: unknown;
}

/** Audit emitter configuration */
export interface AuditConfig {
  enabled: boolean;
  verbosity: AuditVerbosity;
  retentionDays: number;
  rawRetentionDays?: number;
}
