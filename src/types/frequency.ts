/**
 * Session suspicion tracking with exponential decay scoring.
 * Accumulates findings across turns within a session and escalates
 * through tiers when sustained suspicious patterns are detected.
 *
 * Spec reference: Input Validation Layers v2.3, §Within-Session Frequency Tracking
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
  /** Weight assigned to each rule category. Supports glob patterns (e.g. "drawbridge.prompt_injection.*") */
  weights: Record<string, number>;
  /** Score thresholds for each escalation tier */
  thresholds: {
    tier1: number;
    tier2: number;
    tier3: number;
  };
}

/** Memory management configuration */
export interface FrequencyMemoryConfig {
  /**
   * Sessions with no updates for this duration are evicted on next access.
   * Default: 3_600_000 (1 hour)
   */
  sessionTtlMs: number;

  /**
   * Maximum number of tracked sessions. When exceeded, oldest sessions
   * (by lastUpdateMs) are evicted first.
   * Default: 10_000
   */
  maxSessions: number;
}

/** Full configuration including memory management */
export interface FrequencyTrackerConfig extends FrequencyConfig {
  memory: FrequencyMemoryConfig;
}

/** Default frequency configuration */
export const DEFAULT_FREQUENCY_CONFIG: FrequencyConfig = {
  enabled: true,
  halfLifeMs: 60_000,
  weights: {
    "drawbridge.prompt_injection.*": 10,
    "drawbridge.credential.*": 10,
    "drawbridge.structural.*": 5,
    "drawbridge.schema.extra-field": 8,
    "drawbridge.schema.type-mismatch": 6,
    "drawbridge.schema.missing-field": 4,
    "drawbridge.schema.undeclared-admin-reject": 4,
  },
  thresholds: {
    tier1: 15,
    tier2: 30,
    tier3: 50,
  },
};

/** Defaults for memory management */
export const DEFAULT_MEMORY_CONFIG: FrequencyMemoryConfig = {
  sessionTtlMs: 3_600_000,
  maxSessions: 10_000,
};

/** Result of a frequency score update */
export interface FrequencyUpdateResult {
  previousScore: number;
  currentScore: number;
  tier: EscalationTier;
  terminated: boolean;
}
