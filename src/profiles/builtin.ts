/**
 * Built-in profile definitions — frozen registry.
 * These profiles are adapted from the OpenClaw Context-Aware Sanitization spec
 * for Drawbridge standalone (no sub-agent prompt, no schema enforcement yet).
 */

import type { ResolvedProfile } from "../types/profiles.js";

export const BUILTIN_PROFILES: Readonly<Record<string, ResolvedProfile>> = Object.freeze({
  general: {
    id: "general",
    name: "General",
    baseProfileId: "general",
    syntacticEmphasis: { addRules: [], suppressRules: [] },
    frequencyWeightOverrides: {},
    frequencyThresholdOverrides: {},
    auditVerbosityFloor: "minimal",
    schemaStrictness: "strict",
  },
  "customer-service": {
    id: "customer-service",
    name: "Customer Service",
    baseProfileId: "customer-service",
    syntacticEmphasis: { addRules: [], suppressRules: [] },
    frequencyWeightOverrides: {
      "drawbridge.credential.*": 15,
    },
    frequencyThresholdOverrides: {},
    auditVerbosityFloor: "high",
    schemaStrictness: { transcript: "lenient", mcp: "strict" },
  },
  "code-generation": {
    id: "code-generation",
    name: "Code Generation",
    baseProfileId: "code-generation",
    syntacticEmphasis: {
      addRules: [],
      suppressRules: ["drawbridge.syntactic.encoding.base64-in-text"],
    },
    frequencyWeightOverrides: {
      "drawbridge.syntactic.encoding.*": 1,
      "drawbridge.credential.*": 12,
    },
    frequencyThresholdOverrides: {},
    auditVerbosityFloor: "standard",
    schemaStrictness: "lenient",
  },
  research: {
    id: "research",
    name: "Research",
    baseProfileId: "research",
    syntacticEmphasis: {
      addRules: [],
      suppressRules: ["drawbridge.syntactic.injection.role-switch-only"],
    },
    frequencyWeightOverrides: {
      "drawbridge.syntactic.injection.role-switch-only": 2,
    },
    frequencyThresholdOverrides: {},
    auditVerbosityFloor: "standard",
    schemaStrictness: "lenient",
  },
  admin: {
    id: "admin",
    name: "Admin",
    baseProfileId: "admin",
    syntacticEmphasis: { addRules: [], suppressRules: [] },
    frequencyWeightOverrides: {
      "drawbridge.syntactic.injection.*": 15,
      "drawbridge.credential.*": 15,
    },
    frequencyThresholdOverrides: {
      tier1: 10,
      tier2: 20,
      tier3: 35,
    },
    auditVerbosityFloor: "maximum",
    schemaStrictness: "strict",
  },
});
