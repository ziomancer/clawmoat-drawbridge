/**
 * Context profiles modulate sanitization behavior per deployment type.
 * Profiles tune emphasis within stages — they do NOT disable stages or bypass validation.
 *
 * Spec reference: Context-Aware Sanitization v2.1
 *
 * NOT IMPLEMENTED in v0.1. Types exported for pipeline type stability.
 */

import type { AuditVerbosity } from "./common.js";

// Re-export for convenience
export type { AuditVerbosity };

/** Built-in profile identifiers */
export type BuiltInProfileId =
  | "general"
  | "customer-service"
  | "code-generation"
  | "research"
  | "admin";

/** Schema strictness levels */
export type SchemaStrictness = "strict" | "lenient";

/** Per-source schema strictness (e.g. customer-service: strict MCP, lenient transcript) */
export type SchemaStrictnessConfig =
  | SchemaStrictness
  | { transcript: SchemaStrictness; mcp: SchemaStrictness };

/** Syntactic emphasis configuration */
export interface SyntacticEmphasis {
  /** Additional rule IDs to activate. Must exist in RULE_TAXONOMY. */
  addRules: string[];
  /** Rule IDs to suppress to flags-only (does not remove detection, only changes fail→flag) */
  suppressRules: string[];
}

/** Resolved context profile (frozen for session lifetime) */
export interface ContextProfile {
  id: string;
  name: string;
  syntacticEmphasis: SyntacticEmphasis;
  schemaStrictness: SchemaStrictnessConfig;
  /** Frequency weight overrides (merged with global defaults) */
  frequencyWeightOverrides: Record<string, number>;
  /** Frequency threshold overrides (per-profile escalation sensitivity) */
  frequencyThresholdOverrides?: Partial<{ tier1: number; tier2: number; tier3: number }>;
  /** Minimum audit verbosity for this profile (floor, not ceiling) */
  auditVerbosityFloor: AuditVerbosity;
}

/** Custom profile definition (loaded from operator-provided JSON file) */
export interface CustomProfileDefinition {
  id: string;
  name: string;
  baseProfile: BuiltInProfileId;
  syntacticEmphasis?: Partial<SyntacticEmphasis>;
  schemaStrictness?: SchemaStrictnessConfig;
  frequencyWeightOverrides?: Record<string, number>;
  frequencyThresholdOverrides?: Partial<{ tier1: number; tier2: number; tier3: number }>;
  auditVerbosityFloor?: AuditVerbosity;
  /** Appended to the base profile's sub-agent prompt. Max 4096 bytes. No template variables. */
  subAgentPromptAppend?: string;
}
