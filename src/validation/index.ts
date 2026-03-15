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

import type { SyntacticFilterConfig, SyntacticFilterResult } from "../types/validation.js";
import { DEFAULT_SYNTACTIC_CONFIG } from "../types/validation.js";
import { safeStringify } from "../lib/safe-stringify.js";

// ---------------------------------------------------------------------------
// Frozen rule set — prevents config-injection on the filter itself
// ---------------------------------------------------------------------------

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
    nullByte: "drawbridge.syntactic.encoding.null-byte",
    homoglyphSubstitution: "drawbridge.syntactic.encoding.homoglyph-substitution",
  }),
} as const);

/** All valid syntactic rule IDs — used by profiles for validation */
export const SYNTACTIC_RULE_TAXONOMY: ReadonlySet<string> = new Set([
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
  "drawbridge.syntactic.encoding.null-byte",
  "drawbridge.syntactic.encoding.homoglyph-substitution",
]);

// ---------------------------------------------------------------------------
// Homoglyph normalization table (Cyrillic/Greek → Latin)
// ---------------------------------------------------------------------------

const HOMOGLYPH_MAP: ReadonlyMap<string, string> = new Map([
  ["\u0430", "a"], // Cyrillic а → a
  ["\u0435", "e"], // Cyrillic е → e
  ["\u043E", "o"], // Cyrillic о → o
  ["\u0440", "p"], // Cyrillic р → p
  ["\u0441", "c"], // Cyrillic с → c
  ["\u0443", "y"], // Cyrillic у → y
  ["\u0456", "i"], // Cyrillic і → i
  ["\u0455", "s"], // Cyrillic ѕ → s
  ["\u0261", "g"], // Latin ɡ → g
]);

function normalizeHomoglyphs(text: string): string {
  let result = "";
  for (const ch of text) {
    result += HOMOGLYPH_MAP.get(ch) ?? ch;
  }
  return result;
}

function contentHasHomoglyphs(text: string): boolean {
  for (const ch of text) {
    if (HOMOGLYPH_MAP.has(ch)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// JSON depth measurement
// ---------------------------------------------------------------------------

function measureJsonDepth(value: unknown, current = 0): number {
  if (typeof value !== "object" || value === null) return current;
  let max = current + 1;
  if (Array.isArray(value)) {
    for (const item of value) {
      max = Math.max(max, measureJsonDepth(item, current + 1));
    }
  } else {
    for (const v of Object.values(value as Record<string, unknown>)) {
      max = Math.max(max, measureJsonDepth(v, current + 1));
    }
  }
  return max;
}

// ---------------------------------------------------------------------------
// PreFilter
// ---------------------------------------------------------------------------

export class PreFilter {
  private readonly config: SyntacticFilterConfig;

  constructor(config?: Partial<SyntacticFilterConfig>) {
    this.config = { ...DEFAULT_SYNTACTIC_CONFIG, ...config };
  }

  /**
   * Run syntactic pre-filter on content.
   * Pure function — no I/O, no model calls, deterministic.
   */
  run(content: string): SyntacticFilterResult {
    const ruleIds: string[] = [];
    const flags: string[] = [];
    const fails = new Set<string>(); // ruleIds that cause pass=false

    // ----- 1. Structural checks -----

    // Payload size
    const byteLength = Buffer.byteLength(content, "utf8");
    if (byteLength > this.config.maxPayloadBytes) {
      const ruleId = SYNTACTIC_RULES.structuralRuleIds.oversizedPayload;
      ruleIds.push(ruleId);
      flags.push(`Payload ${byteLength} bytes exceeds limit ${this.config.maxPayloadBytes}`);
      fails.add(ruleId); // structural always fails
    }

    // JSON depth
    try {
      const parsed = JSON.parse(content);
      const depth = measureJsonDepth(parsed);
      if (depth > this.config.maxJsonDepth) {
        const ruleId = SYNTACTIC_RULES.structuralRuleIds.excessiveDepth;
        ruleIds.push(ruleId);
        flags.push(`JSON depth ${depth} exceeds limit ${this.config.maxJsonDepth}`);
        fails.add(ruleId); // structural always fails
      }
    } catch {
      // Not valid JSON — skip depth check
    }

    // Binary content (control chars excluding \t \n \r and \0 which is checked separately)
    // eslint-disable-next-line no-control-regex
    if (/[\x01-\x08\x0E-\x1F]/.test(content)) {
      const ruleId = SYNTACTIC_RULES.structuralRuleIds.binaryContent;
      ruleIds.push(ruleId);
      flags.push("Binary/control characters detected in text content");
      fails.add(ruleId); // structural always fails
    }

    // ----- 2. Injection pattern scan -----

    for (const rule of SYNTACTIC_RULES.injectionPatterns) {
      if (rule.pattern.test(content)) {
        ruleIds.push(rule.ruleId);
        flags.push(`Injection pattern matched: ${rule.ruleId}`);
        if (!this.isSuppressed(rule.ruleId)) {
          fails.add(rule.ruleId);
        }
      }
    }

    // Role-switching detection
    const hasTrigger = SYNTACTIC_RULES.roleSwitchTriggers.some((r) => r.test(content));
    const hasGrant = SYNTACTIC_RULES.capabilityGrants.some((r) => r.test(content));

    if (hasTrigger && hasGrant) {
      const ruleId = "drawbridge.syntactic.injection.role-switch-capability";
      ruleIds.push(ruleId);
      flags.push("Role-switch with capability grant detected");
      if (!this.isSuppressed(ruleId)) {
        fails.add(ruleId);
      }
    } else if (hasTrigger) {
      const ruleId = "drawbridge.syntactic.injection.role-switch-only";
      ruleIds.push(ruleId);
      flags.push("Role-switch trigger detected (flag only)");
      // role-switch-only is ALWAYS flag-only, never fails
    }

    // ----- 3. Encoding checks -----

    // Null byte
    if (content.includes("\0")) {
      const ruleId = SYNTACTIC_RULES.encodingRuleIds.nullByte;
      ruleIds.push(ruleId);
      flags.push("Null byte detected in content");
      // encoding = flag only (does not fail at PreFilter level)
    }

    // Base64 in text
    if (/[A-Za-z0-9+/]{40,}={0,2}/.test(content)) {
      const ruleId = SYNTACTIC_RULES.encodingRuleIds.base64InText;
      ruleIds.push(ruleId);
      flags.push("Potential base64-encoded content detected in text field");
      // encoding = flag only
    }

    // Homoglyph substitution
    if (contentHasHomoglyphs(content)) {
      const normalized = normalizeHomoglyphs(content);
      // Check if normalization reveals injection patterns not found in original
      const originalMatches = new Set<string>();
      for (const rule of SYNTACTIC_RULES.injectionPatterns) {
        if (rule.pattern.test(content)) originalMatches.add(rule.ruleId);
      }

      let homoglyphFound = false;
      for (const rule of SYNTACTIC_RULES.injectionPatterns) {
        if (rule.pattern.test(normalized) && !originalMatches.has(rule.ruleId)) {
          homoglyphFound = true;
          break;
        }
      }

      // Also check role-switch triggers with normalized content
      if (!homoglyphFound) {
        const normalizedTrigger = SYNTACTIC_RULES.roleSwitchTriggers.some((r) => r.test(normalized));
        const normalizedGrant = SYNTACTIC_RULES.capabilityGrants.some((r) => r.test(normalized));
        if ((normalizedTrigger && !hasTrigger) || (normalizedGrant && !hasGrant)) {
          homoglyphFound = true;
        }
      }

      if (homoglyphFound) {
        const ruleId = SYNTACTIC_RULES.encodingRuleIds.homoglyphSubstitution;
        ruleIds.push(ruleId);
        flags.push("Unicode homoglyph substitution detected in injection phrase");
        // encoding = flag only
      }
    }

    // ----- 4. Compute pass -----
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

  // Schema validation: v1.0

  private isSuppressed(ruleId: string): boolean {
    return this.config.suppressRules.includes(ruleId);
  }
}
