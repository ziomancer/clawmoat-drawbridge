/**
 * ProfileResolver: resolves context profiles for deployment-specific tuning.
 *
 * A profile produces a frozen ResolvedProfile object at construction time.
 * It does NOT change at runtime. No user input ever selects a profile.
 *
 * Spec reference: Context-Aware Sanitization v2.1
 */

import type {
  BuiltInProfileId,
  CustomProfileDefinition,
  ResolvedProfile,
} from "../types/profiles.js";
import type { SyntacticFilterConfig } from "../types/validation.js";
import type { FrequencyTrackerConfig } from "../types/frequency.js";

import { DEFAULT_SYNTACTIC_CONFIG } from "../types/validation.js";
import { DEFAULT_FREQUENCY_CONFIG, DEFAULT_MEMORY_CONFIG } from "../types/frequency.js";
import { BUILTIN_PROFILES } from "./builtin.js";
import { SYNTACTIC_RULE_TAXONOMY } from "../validation/index.js";

export { BUILTIN_PROFILES } from "./builtin.js";

export class ProfileResolver {
  private readonly resolved: ResolvedProfile;

  constructor(profile?: BuiltInProfileId | CustomProfileDefinition) {
    if (!profile || typeof profile === "string") {
      this.resolved = this.resolveBuiltIn(profile ?? "general");
    } else {
      this.resolved = this.resolveCustom(profile);
    }

    // Deep-freeze — profile must not change after construction
    Object.freeze(this.resolved.syntacticEmphasis.addRules);
    Object.freeze(this.resolved.syntacticEmphasis.suppressRules);
    Object.freeze(this.resolved.syntacticEmphasis);
    Object.freeze(this.resolved.frequencyWeightOverrides);
    Object.freeze(this.resolved.frequencyThresholdOverrides);
    Object.freeze(this.resolved);
  }

  /** Get the resolved profile */
  get profile(): ResolvedProfile {
    return this.resolved;
  }

  /**
   * Apply this profile's tuning to a PreFilter config.
   * Returns a new SyntacticFilterConfig with suppressRules applied.
   */
  applySyntacticConfig(base?: Partial<SyntacticFilterConfig>): SyntacticFilterConfig {
    return {
      ...DEFAULT_SYNTACTIC_CONFIG,
      ...base,
      suppressRules: [
        ...(base?.suppressRules ?? []),
        ...this.resolved.syntacticEmphasis.suppressRules,
      ],
    };
  }

  /**
   * Apply this profile's tuning to a FrequencyTracker config.
   * Merges weight overrides and threshold overrides with defaults.
   */
  applyFrequencyConfig(base?: Partial<FrequencyTrackerConfig>): FrequencyTrackerConfig {
    const baseConfig = { ...DEFAULT_FREQUENCY_CONFIG, ...base };

    return {
      ...baseConfig,
      weights: {
        ...baseConfig.weights,
        ...this.resolved.frequencyWeightOverrides,
      },
      thresholds: {
        ...baseConfig.thresholds,
        ...this.resolved.frequencyThresholdOverrides,
      },
      memory: {
        ...DEFAULT_MEMORY_CONFIG,
        ...base?.memory,
      },
    };
  }

  private resolveBuiltIn(id: string): ResolvedProfile {
    const profile = BUILTIN_PROFILES[id];
    if (!profile) {
      throw new Error(
        `ProfileResolver: unknown profile "${id}". ` +
          `Valid profiles: ${Object.keys(BUILTIN_PROFILES).join(", ")}`,
      );
    }
    return { ...profile };
  }

  private resolveCustom(def: CustomProfileDefinition): ResolvedProfile {
    // 1. Resolve base profile
    const base = this.resolveBuiltIn(def.baseProfile);

    // 2. Validate id doesn't collide with built-in
    if (BUILTIN_PROFILES[def.id]) {
      throw new Error(
        `ProfileResolver: custom profile id "${def.id}" collides with built-in profile`,
      );
    }

    // 3. Validate addRules/suppressRules exist in SYNTACTIC_RULE_TAXONOMY
    const emphasis = def.syntacticEmphasis ?? {};
    for (const ruleId of emphasis.addRules ?? []) {
      if (!SYNTACTIC_RULE_TAXONOMY.has(ruleId)) {
        throw new Error(
          `ProfileResolver: addRules contains unknown ruleId "${ruleId}"`,
        );
      }
    }
    for (const ruleId of emphasis.suppressRules ?? []) {
      if (!SYNTACTIC_RULE_TAXONOMY.has(ruleId)) {
        throw new Error(
          `ProfileResolver: suppressRules contains unknown ruleId "${ruleId}"`,
        );
      }
    }

    // 4. Validate frequency threshold ordering if overrides provided
    const thresholds = {
      ...base.frequencyThresholdOverrides,
      ...def.frequencyThresholdOverrides,
    };
    if (
      thresholds.tier1 !== undefined &&
      thresholds.tier2 !== undefined &&
      thresholds.tier1 >= thresholds.tier2
    ) {
      throw new Error("ProfileResolver: tier1 must be < tier2");
    }
    if (
      thresholds.tier2 !== undefined &&
      thresholds.tier3 !== undefined &&
      thresholds.tier2 >= thresholds.tier3
    ) {
      throw new Error("ProfileResolver: tier2 must be < tier3");
    }

    // 5. Merge
    return {
      id: def.id,
      name: def.name,
      baseProfileId: def.baseProfile,
      syntacticEmphasis: {
        addRules: [
          ...base.syntacticEmphasis.addRules,
          ...(emphasis.addRules ?? []),
        ],
        suppressRules: [
          ...base.syntacticEmphasis.suppressRules,
          ...(emphasis.suppressRules ?? []),
        ],
      },
      frequencyWeightOverrides: {
        ...base.frequencyWeightOverrides,
        ...def.frequencyWeightOverrides,
      },
      frequencyThresholdOverrides: thresholds,
      auditVerbosityFloor: def.auditVerbosityFloor ?? base.auditVerbosityFloor,
      schemaStrictness: def.schemaStrictness ?? base.schemaStrictness,
    };
  }
}
