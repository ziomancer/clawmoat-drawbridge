/**
 * Two-stage input validation: syntactic pre-filter + schema validation.
 * Both stages run before any semantic/LLM inspection.
 *
 * Spec reference: Input Validation Layers v2.3
 */

/** Syntactic pre-filter configuration */
export interface SyntacticFilterConfig {
  /** Maximum raw payload size in bytes before structural block. Default: 524288 (512KB) */
  maxPayloadBytes: number;
  /** Maximum nested JSON depth before structural block. Default: 10 */
  maxJsonDepth: number;
  /**
   * Rule IDs to suppress to flags-only (from profile emphasis).
   * These rules still produce ruleIds in the output but do not set pass=false.
   * Does NOT override structural rules (which always fail).
   */
  suppressRules: string[];
}

/** Default syntactic pre-filter configuration */
export const DEFAULT_SYNTACTIC_CONFIG: SyntacticFilterConfig = {
  maxPayloadBytes: 524_288,
  maxJsonDepth: 10,
  suppressRules: [],
};

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
  /**
   * Rule IDs associated with this result.
   *
   * On **fail** events these identify which rules caused the failure
   * (e.g. `"schema.missing-field"`, `"schema.type-mismatch"`).
   *
   * On **pass** events this may contain informational IDs such as
   * `"schema.no-schema-registered"` to indicate no schema was matched —
   * consumers should not treat a non-empty array as an error signal
   * without also checking `pass`.
   */
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

// ---------------------------------------------------------------------------
// Schema validation types
// ---------------------------------------------------------------------------

/**
 * Tool output schema declaration.
 *
 * Registered schemas only validate object-typed tool outputs. Tools that
 * return top-level arrays will fail with `schema.type-mismatch` — leave
 * such tools unregistered to use `validateDefault` instead.
 */
export interface ToolOutputSchema {
  /**
   * Discriminant field name for polymorphic responses (e.g. "type", "status").
   * The field's value in the content object must be a string matching one of
   * the keys in `variants`. Non-string discriminant values (e.g. numeric
   * status codes) are not supported and will produce a type-mismatch violation.
   */
  discriminant?: string;
  /** Schema variants keyed by discriminant value. If no discriminant, use a single-key map. */
  variants: Record<string, FieldSchema>;
}

/**
 * Field-level schema (simple validation, not full JSON Schema).
 *
 * Fields listed in `fields` but not in `required` are optional: their absence
 * produces no violation, but if present their type is checked. There is no way
 * to express "must be present AND must be type X" other than including the field
 * in both `required` and `fields`.
 */
export interface FieldSchema {
  /** Required field names */
  required?: string[];
  /** Field type expectations: field name → expected type (checked only when field is present) */
  fields?: Record<string, "string" | "number" | "boolean" | "object" | "array" | "null">;
  /** Whether extra fields beyond those declared are allowed. Default: false */
  allowExtra?: boolean;
}

/** Schema validation configuration */
export interface SchemaValidationConfig {
  enabled: boolean;
  /**
   * Registered tool schemas. Key is "serverName:toolName".
   * Used by the pipeline to validate MCP tool results.
   */
  toolSchemas: Record<string, ToolOutputSchema>;
  /**
   * Default behavior for tools without a registered schema.
   * "strict" = reject bare primitives, require JSON object/array
   * "lenient" = accept any JSON value and pass (ruleIds: ["schema.no-schema-registered"])
   * Default: "strict"
   */
  defaultBehavior: "strict" | "lenient";
}

/** Default schema validation configuration (disabled by default) */
export const DEFAULT_SCHEMA_CONFIG: SchemaValidationConfig = {
  enabled: false,
  toolSchemas: {},
  defaultBehavior: "strict",
};

/** Two-pass gating configuration */
export interface TwoPassConfig {
  enabled: boolean;
  /** Rule IDs that trigger definitive block without semantic pass */
  hardBlockRules: string[];
}

/** Default hard block rules (Drawbridge-prefixed) */
export const DEFAULT_HARD_BLOCK_RULES = [
  "drawbridge.syntactic.injection.ignore-previous",
  "drawbridge.syntactic.injection.system-override",
  "drawbridge.syntactic.injection.role-switch-capability",
] as const;
