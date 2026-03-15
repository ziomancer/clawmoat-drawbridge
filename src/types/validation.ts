/**
 * Two-stage input validation: syntactic pre-filter + schema validation.
 * Both stages run before any semantic/LLM inspection.
 *
 * Spec reference: Input Validation Layers v2.3
 *
 * NOT IMPLEMENTED in v0.1. Types exported for pipeline type stability.
 */

/** Syntactic pre-filter result */
export interface SyntacticFilterResult {
  pass: boolean;
  flags: string[];
  ruleIds: string[];
}

/** Schema validation result */
export interface SchemaValidationResult {
  pass: boolean;
  violations: string[];
  ruleIds: string[];
}

/** Merged pre-filter result (syntactic + schema) */
export interface PreFilterResult {
  syntactic: SyntacticFilterResult;
  schema: SchemaValidationResult;
  /** Overall: true only if both pass */
  pass: boolean;
  /** Combined ruleIds from both stages */
  allRuleIds: string[];
}

/** Two-pass gating configuration */
export interface TwoPassConfig {
  enabled: boolean;
  /** Rule IDs that trigger definitive block without semantic pass */
  hardBlockRules: string[];
}

/** Default hard block rules */
export const DEFAULT_HARD_BLOCK_RULES = [
  "injection.ignore-previous",
  "injection.system-override",
  "injection.role-switch-capability",
] as const;
