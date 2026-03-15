/**
 * Session suspicion tracking with exponential decay scoring.
 * Accumulates findings across turns within a session and escalates
 * through tiers when sustained suspicious patterns are detected.
 *
 * Spec reference: Input Validation Layers v2.3, §Within-Session Frequency Tracking
 *
 * NOT IMPLEMENTED in v0.1. Types exported for pipeline type stability.
 */

/** Escalation tier resulting from frequency score evaluation */
export type EscalationTier = "none" | "tier1" | "tier2" | "tier3";

/** Per-session suspicion state (O(1) storage — two floats + one boolean) */
export interface SessionSuspicionState {
  /** Cumulative decayed score */
  lastScore: number;
  /** Timestamp of last score update (ms since epoch) */
  lastUpdateMs: number;
  /** Set to true when score crosses tier3 threshold. Irreversible for session. */
  terminated?: boolean;
}

/** Frequency tracker configuration */
export interface FrequencyConfig {
  enabled: boolean;
  /** Half-life for exponential decay in milliseconds. Default: 60000 */
  halfLifeMs: number;
  /** Weight assigned to each rule category. Supports glob patterns (e.g. "injection.*") */
  weights: Record<string, number>;
  /** Score thresholds for each escalation tier */
  thresholds: {
    tier1: number;
    tier2: number;
    tier3: number;
  };
}

/** Default frequency configuration */
export const DEFAULT_FREQUENCY_CONFIG: FrequencyConfig = {
  enabled: true,
  halfLifeMs: 60_000,
  weights: {
    "injection.*": 10,
    "structural.*": 5,
    "schema.extra-field": 8,
    "schema.type-mismatch": 6,
    "schema.missing-field": 4,
    "schema.undeclared-admin-reject": 4,
  },
  thresholds: {
    tier1: 15,
    tier2: 30,
    tier3: 50,
  },
};

/** Result of a frequency score update */
export interface FrequencyUpdateResult {
  previousScore: number;
  currentScore: number;
  tier: EscalationTier;
  terminated: boolean;
}
