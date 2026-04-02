/**
 * Tracks per-session suspicion scores using exponential decay.
 * Escalates through tiers when sustained suspicious patterns are detected.
 *
 * NOT thread-safe. Designed for single-threaded Node.js event loop.
 * For worker thread isolation, each thread needs its own FrequencyTracker
 * instance.
 *
 * Standalone usage (v0.2):
 *   const tracker = new FrequencyTracker();
 *   const scanResult = scanner.scan(content);
 *   const freqResult = tracker.update(sessionId, scanResult.findings.map(f => f.ruleId));
 *
 * Pipeline usage (v1.0):
 *   The DrawbridgePipeline will wire scanner → tracker automatically.
 */

import type {
  EscalationTier,
  FrequencyTrackerConfig,
  FrequencyUpdateResult,
  SessionSuspicionState,
} from "../types/frequency.js";

import { DEFAULT_FREQUENCY_CONFIG, DEFAULT_MEMORY_CONFIG } from "../types/frequency.js";

/** Static "disabled" result — returned when tracker is not enabled */
const DISABLED_RESULT: FrequencyUpdateResult = Object.freeze({
  previousScore: 0,
  currentScore: 0,
  tier: "none" as const,
  terminated: false,
});

/** Static "rate-limited" result — returned when new session creation is throttled */
const RATE_LIMITED_RESULT: FrequencyUpdateResult = Object.freeze({
  previousScore: 0,
  currentScore: 0,
  tier: "none" as const,
  terminated: false,
});

export class FrequencyTracker {
  private readonly config: FrequencyTrackerConfig;
  private readonly sessions: Map<string, SessionSuspicionState>;
  private readonly globKeys: ReadonlyArray<{ prefix: string; weight: number }>;
  private readonly exactKeys: ReadonlyMap<string, number>;

  /** Rolling timestamps of new session creations (for rate limiting, Finding #7) */
  private readonly sessionCreationTimestamps: number[] = [];

  constructor(config?: Partial<FrequencyTrackerConfig>) {
    this.config = {
      ...DEFAULT_FREQUENCY_CONFIG,
      ...config,
      memory: {
        ...DEFAULT_MEMORY_CONFIG,
        ...config?.memory,
      },
    };

    // Validate thresholds are strictly ascending
    const { tier1, tier2, tier3 } = this.config.thresholds;
    if (tier1 >= tier2 || tier2 >= tier3) {
      throw new Error(
        `FrequencyTracker: thresholds must be strictly ascending. ` +
          `Got tier1=${tier1}, tier2=${tier2}, tier3=${tier3}`,
      );
    }

    // Validate halfLifeMs — NaN or non-positive silently disables decay (#4)
    if (!Number.isFinite(this.config.halfLifeMs) || this.config.halfLifeMs <= 0) {
      throw new Error(
        `FrequencyTracker: halfLifeMs must be a positive finite number. Got ${this.config.halfLifeMs}`,
      );
    }

    this.sessions = new Map();

    // Pre-partition weight keys into exact and glob for fast matching
    const exact = new Map<string, number>();
    const globs: Array<{ prefix: string; weight: number }> = [];

    for (const [key, weight] of Object.entries(this.config.weights)) {
      // Validate weights are non-negative — negative weights would reduce suspicion (#5)
      if (!Number.isFinite(weight) || weight < 0) {
        throw new Error(
          `FrequencyTracker: weight for "${key}" must be a non-negative finite number. Got ${weight}`,
        );
      }
      if (key.endsWith(".*")) {
        globs.push({ prefix: key.slice(0, -2), weight });
      } else {
        exact.set(key, weight);
      }
    }

    // Sort glob keys by prefix length descending (most specific first)
    globs.sort((a, b) => b.prefix.length - a.prefix.length);

    this.exactKeys = exact;
    this.globKeys = globs;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  update(sessionId: string, ruleIds: string[]): FrequencyUpdateResult {
    if (!this.config.enabled) return DISABLED_RESULT;

    // 1. Lazy eviction
    this.evictStale();

    // 2. Get or create session state
    let state = this.sessions.get(sessionId);
    const isNew = !state;

    if (!state) {
      // Rate-limit new session creation when at capacity (Finding #7).
      // Only enforced when sessions are at max — prevents flood-eviction attacks
      // while allowing normal operation well under capacity.
      if (
        this.sessions.size >= this.config.memory.maxSessions &&
        this.isSessionCreationRateLimited()
      ) {
        return RATE_LIMITED_RESULT;
      }
      state = { lastScore: 0, lastUpdateMs: Date.now(), rollingFindings: [] };
      this.sessions.set(sessionId, state);
      this.sessionCreationTimestamps.push(Date.now());
    }

    // Backward compatibility: initialize rollingFindings if missing
    state.rollingFindings ??= [];

    // 3. Enforce max-sessions cap (only after creating a new entry)
    if (isNew && this.sessions.size > this.config.memory.maxSessions) {
      this.evictOldest(sessionId);
    }

    // 4. Terminated sessions return immediately without updating score
    if (state.terminated) {
      return {
        previousScore: state.lastScore,
        currentScore: state.lastScore,
        tier: "tier3",
        terminated: true,
      };
    }

    // 5. Compute total weight for this update
    let totalWeight = 0;
    for (const ruleId of ruleIds) {
      totalWeight += this.matchWeight(ruleId);
    }

    // 6. Decay previous score (true half-life: score halves every halfLifeMs)
    const now = Date.now();
    const elapsed = now - state.lastUpdateMs;
    const decayed = state.lastScore * Math.exp((-elapsed * Math.LN2) / this.config.halfLifeMs);

    // 7. previousScore = decayed (before new findings); currentScore = decayed + new weight
    const previousScore = decayed;
    const currentScore = decayed + totalWeight;

    // 8. Record rolling window findings (for low-and-slow detection, Finding #6)
    if (ruleIds.length > 0) {
      state.rollingFindings!.push(now);
    }
    const windowStart = now - this.config.rollingWindowMs;
    state.rollingFindings = state.rollingFindings!.filter(t => t >= windowStart);

    // 9. Determine tier — rolling counter can promote to at least tier1
    let tier = this.evaluateTier(currentScore);
    if (tier === "none" && state.rollingFindings.length >= this.config.rollingThreshold) {
      tier = "tier1";
    }

    // 10. Update state
    state.lastScore = currentScore;
    state.lastUpdateMs = now;
    if (tier === "tier3") {
      state.terminated = true;
    }

    return {
      previousScore,
      currentScore,
      tier,
      terminated: state.terminated ?? false,
    };
  }

  /** Returns the tracker's threshold configuration (defensive copy). */
  get thresholds(): { tier1: number; tier2: number; tier3: number } {
    return { ...this.config.thresholds };
  }

  /** Returns a snapshot of the session's suspicion state, or null if unknown. */
  getState(sessionId: string): SessionSuspicionState | null {
    const state = this.sessions.get(sessionId);
    if (!state) return null;
    return {
      ...state,
      rollingFindings: state.rollingFindings ? [...state.rollingFindings] : undefined,
    };
  }

  reset(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  clear(): void {
    this.sessions.clear();
  }

  get size(): number {
    return this.sessions.size;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Match a ruleId against the weight map.
   * 1. Exact match wins
   * 2. Glob match (longest prefix wins)
   * 3. No match → 0
   */
  private matchWeight(ruleId: string): number {
    // Exact match first
    const exact = this.exactKeys.get(ruleId);
    if (exact !== undefined) return exact;

    // Glob match — globKeys are pre-sorted by prefix length descending,
    // so the first match is the most specific
    for (const { prefix, weight } of this.globKeys) {
      if (ruleId.startsWith(prefix + ".")) return weight;
    }

    return 0;
  }

  private evaluateTier(score: number): EscalationTier {
    if (score >= this.config.thresholds.tier3) return "tier3";
    if (score >= this.config.thresholds.tier2) return "tier2";
    if (score >= this.config.thresholds.tier1) return "tier1";
    return "none";
  }

  /**
   * Passive TTL eviction — remove sessions that haven't been updated
   * within sessionTtlMs. O(n) full scan; sub-ms for <10k sessions.
   */
  private evictStale(): void {
    const cutoff = Date.now() - this.config.memory.sessionTtlMs;
    for (const [id, state] of this.sessions) {
      if (state.lastUpdateMs < cutoff) {
        this.sessions.delete(id);
      }
    }
  }

  /**
   * Max-sessions cap — evict terminated sessions first, then the oldest
   * session (by lastUpdateMs) that is NOT the session we just created.
   */
  private evictOldest(excludeSessionId: string): void {
    // Prefer evicting a terminated session
    for (const [id, state] of this.sessions) {
      if (id !== excludeSessionId && state.terminated) {
        this.sessions.delete(id);
        return;
      }
    }

    // Fall back to oldest by lastUpdateMs
    let oldestId: string | null = null;
    let oldestTs = Infinity;

    for (const [id, state] of this.sessions) {
      if (id !== excludeSessionId && state.lastUpdateMs < oldestTs) {
        oldestTs = state.lastUpdateMs;
        oldestId = id;
      }
    }

    if (oldestId) {
      this.sessions.delete(oldestId);
    }
  }

  /** Check if new session creation exceeds the per-minute rate limit */
  private isSessionCreationRateLimited(): boolean {
    const now = Date.now();
    const oneMinuteAgo = now - 60_000;

    // Evict old timestamps
    while (
      this.sessionCreationTimestamps.length > 0 &&
      this.sessionCreationTimestamps[0]! < oneMinuteAgo
    ) {
      this.sessionCreationTimestamps.shift();
    }

    return this.sessionCreationTimestamps.length >= this.config.memory.maxNewSessionsPerMinute;
  }
}
