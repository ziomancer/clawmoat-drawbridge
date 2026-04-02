/**
 * PreFilter: syntactic pre-filter for known injection patterns,
 * structural anomalies, and encoding tricks.
 *
 * Pure function — no I/O, no model calls, deterministic.
 * Catches lazy/automated attacks cheaply. Sophisticated obfuscation
 * will bypass it — that's what the scanner (ClawMoat) handles.
 *
 * Spec reference: Input Validation Layers v2.3, §Stage 1A
 */

import type { SyntacticFilterConfig, SyntacticFilterResult, SchemaValidationConfig, SchemaValidationResult } from "../types/validation.js";
import { DEFAULT_SYNTACTIC_CONFIG, DEFAULT_SCHEMA_CONFIG } from "../types/validation.js";
import { safeStringify } from "../lib/safe-stringify.js";
import { normalizeForDetection } from "./normalize.js";

// ---------------------------------------------------------------------------
// Frozen rule set — prevents config-injection on the filter itself
// ---------------------------------------------------------------------------

/** Frozen rule set — prevents config-injection on the filter itself */
export const SYNTACTIC_RULES = Object.freeze({
  injectionPatterns: Object.freeze([
    Object.freeze({ pattern: /ignore previous instructions/i, ruleId: "drawbridge.syntactic.injection.ignore-previous" }),
    Object.freeze({ pattern: /ignore all instructions/i, ruleId: "drawbridge.syntactic.injection.ignore-all" }),
    Object.freeze({ pattern: /disregard your/i, ruleId: "drawbridge.syntactic.injection.disregard" }),
    Object.freeze({ pattern: /you are now/i, ruleId: "drawbridge.syntactic.injection.you-are-now" }),
    Object.freeze({ pattern: /new instructions\s*:/i, ruleId: "drawbridge.syntactic.injection.new-instructions" }),
    Object.freeze({ pattern: /system override/i, ruleId: "drawbridge.syntactic.injection.system-override" }),
    Object.freeze({ pattern: /^SYSTEM:/m, ruleId: "drawbridge.syntactic.injection.system-prefix" }),
    Object.freeze({ pattern: /\[INST\]|<\/INST>/i, ruleId: "drawbridge.syntactic.injection.inst-delimiter" }),
  ]),
  roleSwitchTriggers: Object.freeze([/you are a/i, /act as/i, /pretend you are/i, /roleplay as/i]),
  capabilityGrants: Object.freeze([/no restrictions/i, /no limits/i, /without filters/i, /DAN mode/i, /developer mode/i]),
  structuralRuleIds: Object.freeze({
    oversizedPayload: "drawbridge.syntactic.structural.oversized-payload",
    excessiveDepth: "drawbridge.syntactic.structural.excessive-depth",
    binaryContent: "drawbridge.syntactic.structural.binary-content",
  }),
  encodingRuleIds: Object.freeze({
    base64InText: "drawbridge.syntactic.encoding.base64-in-text",
    invisibleChars: "drawbridge.syntactic.encoding.invisible-chars",
    homoglyphSubstitution: "drawbridge.syntactic.encoding.homoglyph-substitution",
    rtlOverride: "drawbridge.syntactic.encoding.rtl-override",
  }),
} as const);

/** All valid syntactic rule IDs — used by profiles for validation */
export const SYNTACTIC_RULE_TAXONOMY: ReadonlySet<string> = Object.freeze(new Set([
  "drawbridge.syntactic.injection.ignore-previous",
  "drawbridge.syntactic.injection.ignore-all",
  "drawbridge.syntactic.injection.disregard",
  "drawbridge.syntactic.injection.you-are-now",
  "drawbridge.syntactic.injection.new-instructions",
  "drawbridge.syntactic.injection.system-override",
  "drawbridge.syntactic.injection.system-prefix",
  "drawbridge.syntactic.injection.inst-delimiter",
  "drawbridge.syntactic.injection.role-switch-capability",
  "drawbridge.syntactic.injection.role-switch-only",
  "drawbridge.syntactic.structural.oversized-payload",
  "drawbridge.syntactic.structural.excessive-depth",
  "drawbridge.syntactic.structural.binary-content",
  "drawbridge.syntactic.encoding.base64-in-text",
  "drawbridge.syntactic.encoding.homoglyph-substitution",
  "drawbridge.syntactic.encoding.invisible-chars",
  "drawbridge.syntactic.encoding.rtl-override",
]));

// ---------------------------------------------------------------------------
// JSON depth measurement
// ---------------------------------------------------------------------------

function measureJsonDepth(value: unknown, current = 0, limit = 100): number {
  if (typeof value !== "object" || value === null) return current;
  // Hard safety cap at 2x limit — still short-circuits deep bombs but reports
  // a more informative depth than just limit+1 for diagnostics/triage.
  if (current + 1 > limit * 2) return current + 1;
  let max = current + 1;
  if (Array.isArray(value)) {
    for (const item of value) {
      max = Math.max(max, measureJsonDepth(item, current + 1, limit));
      if (max > limit * 2) return max;
    }
  } else {
    for (const v of Object.values(value as Record<string, unknown>)) {
      max = Math.max(max, measureJsonDepth(v, current + 1, limit));
      if (max > limit * 2) return max;
    }
  }
  return max;
}

// ---------------------------------------------------------------------------
// PreFilter
// ---------------------------------------------------------------------------

/** Syntactic pre-filter: pattern matching and structural checks before semantic analysis */
export class PreFilter {
  private readonly config: SyntacticFilterConfig;

  constructor(config?: Partial<SyntacticFilterConfig>) {
    this.config = { ...DEFAULT_SYNTACTIC_CONFIG, ...config };

    const MAX_ALLOWED_DEPTH = 1_000; // 2x cap in measureJsonDepth → max ~2k frames, well within stack
    if (!Number.isFinite(this.config.maxJsonDepth) || this.config.maxJsonDepth <= 0) {
      throw new Error(
        `PreFilter: maxJsonDepth must be a positive finite number. Got ${this.config.maxJsonDepth}`,
      );
    }
    if (this.config.maxJsonDepth > MAX_ALLOWED_DEPTH) {
      throw new Error(
        `PreFilter: maxJsonDepth ${this.config.maxJsonDepth} exceeds maximum allowed value ${MAX_ALLOWED_DEPTH}`,
      );
    }
    if (!Number.isFinite(this.config.maxPayloadBytes) || this.config.maxPayloadBytes <= 0) {
      throw new Error(
        `PreFilter: maxPayloadBytes must be a positive finite number. Got ${this.config.maxPayloadBytes}`,
      );
    }
  }

  /**
   * Run syntactic pre-filter on content.
   * Pure function — no I/O, no model calls, deterministic.
   */
  run(content: string): SyntacticFilterResult {
    const ruleIds: string[] = [];
    const flags: string[] = [];
    const fails = new Set<string>(); // ruleIds that cause pass=false

    // ----- 0. Payload size (before normalization — avoid processing oversized input) -----
    const byteLength = Buffer.byteLength(content, "utf8");
    if (byteLength > this.config.maxPayloadBytes) {
      const ruleId = SYNTACTIC_RULES.structuralRuleIds.oversizedPayload;
      ruleIds.push(ruleId);
      flags.push(`Payload ${byteLength} bytes exceeds limit ${this.config.maxPayloadBytes}`);
      fails.add(ruleId);
      return { pass: false, flags, ruleIds };
    }

    // ----- 1. Input normalization -----
    // Strip invisibles, apply NFKC + homoglyph mapping. Pattern matching
    // below runs against `normalized`; structural checks use raw `content`.
    const norm = normalizeForDetection(content);
    const normalized = norm.normalized;
    let injectionMatchedOnNormalized = false;

    // ----- 2. Structural checks -----

    // JSON depth
    try {
      const parsed = JSON.parse(content);
      const depth = measureJsonDepth(parsed, 0, this.config.maxJsonDepth);
      if (depth > this.config.maxJsonDepth) {
        const ruleId = SYNTACTIC_RULES.structuralRuleIds.excessiveDepth;
        ruleIds.push(ruleId);
        flags.push(`JSON depth ${depth} exceeds limit ${this.config.maxJsonDepth}`);
        fails.add(ruleId); // structural always fails
      }
    } catch {
      // Not valid JSON — skip depth check
    }

    // Binary content (control chars excluding \t \n \r; \0 handled by normalization)
    // eslint-disable-next-line no-control-regex
    if (/[\x01-\x08\x0E-\x1F]/.test(content)) {
      const ruleId = SYNTACTIC_RULES.structuralRuleIds.binaryContent;
      ruleIds.push(ruleId);
      flags.push("Binary/control characters detected in text content");
      fails.add(ruleId); // structural always fails
    }

    // ----- 3. Injection pattern scan -----

    for (const rule of SYNTACTIC_RULES.injectionPatterns) {
      if (rule.pattern.test(normalized)) {
        ruleIds.push(rule.ruleId);
        flags.push(`Injection pattern matched: ${rule.ruleId}`);
        injectionMatchedOnNormalized = true;
        if (!this.isSuppressed(rule.ruleId)) {
          fails.add(rule.ruleId);
        }
      }
    }

    // Role-switching detection
    const hasTrigger = SYNTACTIC_RULES.roleSwitchTriggers.some((r) => r.test(normalized));
    const hasGrant = SYNTACTIC_RULES.capabilityGrants.some((r) => r.test(normalized));

    if (hasTrigger && hasGrant) {
      const ruleId = "drawbridge.syntactic.injection.role-switch-capability";
      ruleIds.push(ruleId);
      flags.push("Role-switch with capability grant detected");
      injectionMatchedOnNormalized = true;
      if (!this.isSuppressed(ruleId)) {
        fails.add(ruleId);
      }
    } else if (hasTrigger) {
      const ruleId = "drawbridge.syntactic.injection.role-switch-only";
      ruleIds.push(ruleId);
      flags.push("Role-switch trigger detected (flag only)");
      // role-switch-only is ALWAYS flag-only, never fails
    }

    // ----- 4. Encoding checks -----

    // Invisible characters (zero-width, null bytes, bidi controls)
    if (norm.invisibleCharsStripped > 0) {
      const ruleId = SYNTACTIC_RULES.encodingRuleIds.invisibleChars;
      ruleIds.push(ruleId);
      flags.push(`${norm.invisibleCharsStripped} invisible/zero-width character(s) stripped before analysis`);
      // Escalation: obfuscation + injection = intentional attack.
      // Even if the injection rule is suppressed by a profile, the
      // presence of invisible chars alongside an injection phrase fails.
      if (injectionMatchedOnNormalized) {
        fails.add(ruleId);
      }
    }

    // Base64 in text (check raw content — base64 is content-level, not a confusable)
    if (/[A-Za-z0-9+/]{40,}={0,2}/.test(content)) {
      const ruleId = SYNTACTIC_RULES.encodingRuleIds.base64InText;
      ruleIds.push(ruleId);
      flags.push("Potential base64-encoded content detected in text field");
      // encoding = flag only
    }

    // Homoglyph / confusable substitution (NFKC + homoglyph map changed content
    // AND injection patterns matched — the confusables may have enabled the match)
    if (norm.confusablesNormalized && injectionMatchedOnNormalized) {
      const ruleId = SYNTACTIC_RULES.encodingRuleIds.homoglyphSubstitution;
      ruleIds.push(ruleId);
      flags.push("Unicode confusable characters normalized (homoglyph/fullwidth/compatibility substitution)");
      // encoding = flag only
    }

    // RTL override characters
    if (norm.rtlOverridesDetected) {
      const ruleId = SYNTACTIC_RULES.encodingRuleIds.rtlOverride;
      ruleIds.push(ruleId);
      flags.push("RTL/LTR override characters detected");
      // encoding = flag only
    }

    // ----- 5. Compute pass -----
    // Structural rules cannot be suppressed. Injection rules respect suppressRules.
    // Encoding rules and role-switch-only are always flag-only.

    return {
      pass: fails.size === 0,
      flags,
      ruleIds,
    };
  }

  /**
   * Convenience: run on arbitrary content (stringifies objects).
   * Same circular-ref safety as DrawbridgeScanner.scanObject.
   */
  runObject(content: unknown): SyntacticFilterResult {
    return this.run(typeof content === "string" ? content : safeStringify(content));
  }

  private isSuppressed(ruleId: string): boolean {
    return this.config.suppressRules.includes(ruleId);
  }
}

// ---------------------------------------------------------------------------
// SchemaValidator
// ---------------------------------------------------------------------------

/**
 * Map a JS value to the closest JSON type name for schema validation.
 *
 * Non-JSON types (undefined, function, symbol, bigint) return "null" so they
 * fail any type check except an explicit "null" declaration. This is intentional:
 * JSON-parsed payloads never contain these types, and raw JS objects reaching
 * the validator via input.content should not silently match "object" or any
 * other structural type.
 */
function jsType(value: unknown): "string" | "number" | "boolean" | "object" | "array" | "null" {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return "array";
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean" || t === "object") return t;
  return "null";
}

/** Validates MCP tool output against registered schemas with discriminated union support */
export class SchemaValidator {
  private readonly config: SchemaValidationConfig;

  constructor(config?: Partial<SchemaValidationConfig>) {
    this.config = {
      ...DEFAULT_SCHEMA_CONFIG,
      ...config,
      // Deep copy — prevent post-construction mutation of nested schema objects
      toolSchemas: Object.fromEntries(
        Object.entries(config?.toolSchemas ?? DEFAULT_SCHEMA_CONFIG.toolSchemas).map(
          ([k, v]) => [k, structuredClone(v)],
        ),
      ),
    };

    // Validate registered schemas at construction time so misconfigurations
    // surface immediately rather than at first validate() call.
    for (const [key, schema] of Object.entries(this.config.toolSchemas ?? {})) {
      const parts = key.split(":");
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        throw new Error(
          `SchemaValidator: invalid toolSchemas key "${key}" — must be "serverName:toolName" with exactly one colon and non-empty components`,
        );
      }
      if (Object.keys(schema.variants).length === 0) {
        throw new Error(
          `SchemaValidator: toolSchema for "${key}" has an empty variants map — at least one variant is required`,
        );
      }
    }
  }

  validate(
    content: unknown,
    serverName: string,
    toolName: string,
  ): SchemaValidationResult {
    if (!this.config.enabled) {
      return { pass: true, violations: [], ruleIds: [] };
    }

    if (serverName.includes(":") || toolName.includes(":")) {
      return {
        pass: false,
        violations: [
          `Invalid schema lookup: serverName or toolName contains ":" which collides with the composite key separator`,
        ],
        ruleIds: ["schema.invalid-key"],
      };
    }

    const key = `${serverName}:${toolName}`;
    const schema = this.config.toolSchemas?.[key];

    // No schema registered — apply defaultBehavior
    if (!schema) {
      return this.validateDefault(content);
    }

    return this.validateAgainstSchema(content, schema);
  }

  private validateDefault(content: unknown): SchemaValidationResult {
    if (this.config.defaultBehavior === "lenient") {
      return { pass: true, violations: [], ruleIds: ["schema.no-schema-registered"] };
    }

    // strict: content must be object or array
    const type = jsType(content);
    if (type !== "object" && type !== "array") {
      return {
        pass: false,
        violations: [`Expected object or array, got ${type}`],
        ruleIds: ["schema.type-mismatch"],
      };
    }
    return { pass: true, violations: [], ruleIds: ["schema.no-schema-registered"] };
  }

  private validateAgainstSchema(
    content: unknown,
    schema: import("../types/validation.js").ToolOutputSchema,
  ): SchemaValidationResult {
    const violations: string[] = [];
    const ruleIds = new Set<string>();

    // Content must be an object to validate against a schema
    if (typeof content !== "object" || content === null || Array.isArray(content)) {
      return {
        pass: false,
        violations: [`Expected object, got ${jsType(content)}`],
        ruleIds: ["schema.type-mismatch"],
      };
    }

    const obj = content as Record<string, unknown>;

    // Select variant
    let variant: import("../types/validation.js").FieldSchema | undefined;

    if (schema.discriminant) {
      const discriminantValue = obj[schema.discriminant];
      if (discriminantValue === undefined) {
        return {
          pass: false,
          violations: [`Missing discriminant field "${schema.discriminant}"`],
          ruleIds: ["schema.missing-field"],
        };
      }
      if (typeof discriminantValue !== "string") {
        return {
          pass: false,
          violations: [`Discriminant field "${schema.discriminant}" must be a string, got ${jsType(discriminantValue)}`],
          ruleIds: ["schema.type-mismatch"],
        };
      }
      if (!Object.hasOwn(schema.variants, discriminantValue)) {
        return {
          pass: false,
          violations: [`Unknown discriminant value "${discriminantValue}" for field "${schema.discriminant}"`],
          ruleIds: ["schema.type-mismatch"],
        };
      }
      variant = schema.variants[discriminantValue];
    } else {
      // No discriminant — expect a single-key variant map
      const keys = Object.keys(schema.variants);
      if (keys.length > 1) {
        return {
          pass: false,
          violations: [
            `Schema misconfiguration: ${keys.length} variants defined but no discriminant field set`,
          ],
          ruleIds: ["schema.misconfiguration"],
        };
      }
      variant = keys.length > 0 ? schema.variants[keys[0]!] : undefined;
    }

    if (!variant) {
      return {
        pass: false,
        violations: ["Schema misconfiguration: no applicable variant found"],
        ruleIds: ["schema.misconfiguration"],
      };
    }

    // Check required fields — reject both absent keys and keys set to undefined
    // (JSON-parsed objects never have undefined values, but raw JS objects passed
    // via input.content can)
    const missingFields = new Set<string>();
    if (variant.required) {
      for (const field of variant.required) {
        if (!Object.hasOwn(obj, field) || obj[field] === undefined) {
          violations.push(`Missing required field "${field}"`);
          ruleIds.add("schema.missing-field");
          missingFields.add(field);
        }
      }
    }

    // Check field types (skip fields already flagged as missing to avoid double-violation)
    if (variant.fields) {
      for (const [field, expectedType] of Object.entries(variant.fields)) {
        if (Object.hasOwn(obj, field) && !missingFields.has(field)) {
          const actualType = jsType(obj[field]);
          if (actualType !== expectedType) {
            violations.push(`Field "${field}" expected ${expectedType}, got ${actualType}`);
            ruleIds.add("schema.type-mismatch");
          }
        }
      }
    }

    // Check extra fields
    if (variant.allowExtra !== true) {
      const declaredFields = new Set<string>([
        ...(variant.required ?? []),
        ...Object.keys(variant.fields ?? {}),
      ]);
      if (schema.discriminant) {
        declaredFields.add(schema.discriminant);
      }
      for (const field of Object.keys(obj)) {
        if (!declaredFields.has(field)) {
          violations.push(`Unexpected field "${field}"`);
          ruleIds.add("schema.extra-field");
        }
      }
    }

    const ruleIdArray = [...ruleIds];
    return {
      pass: ruleIdArray.length === 0,
      violations,
      ruleIds: ruleIdArray,
    };
  }
}
