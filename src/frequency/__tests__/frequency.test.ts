import { describe, it, expect, vi } from "vitest";
import { FrequencyTracker } from "../index.js";
import type { FrequencyTrackerConfig } from "../../types/frequency.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a tracker with short half-life for fast testing.
 * Default test config: 100ms half-life, low thresholds.
 */
function createTestTracker(
  overrides?: Partial<FrequencyTrackerConfig>,
): FrequencyTracker {
  return new FrequencyTracker({
    enabled: true,
    halfLifeMs: 100,
    weights: {
      "drawbridge.prompt_injection.*": 10,
      "drawbridge.credential.*": 10,
      "drawbridge.structural.*": 5,
      "drawbridge.schema.extra-field": 8,
    },
    thresholds: {
      tier1: 15,
      tier2: 30,
      tier3: 50,
    },
    memory: {
      sessionTtlMs: 500,
      maxSessions: 5,
    },
    ...overrides,
  });
}

// All time-dependent tests use mocked Date.now for determinism

// ---------------------------------------------------------------------------
// Weight matching
// ---------------------------------------------------------------------------

describe("FrequencyTracker — weight matching", () => {
  // 1. Exact match
  it("matches exact weight keys", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.schema.extra-field",
    ]);
    expect(result.currentScore).toBe(8);
  });

  // 2. Glob match
  it("matches glob weight keys", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result.currentScore).toBe(10);
  });

  // 3. Most specific glob wins
  it("most specific glob wins when multiple globs match", () => {
    const tracker = new FrequencyTracker({
      enabled: true,
      halfLifeMs: 100,
      weights: {
        "drawbridge.*": 1,
        "drawbridge.prompt_injection.*": 10,
      },
      thresholds: { tier1: 15, tier2: 30, tier3: 50 },
      memory: { sessionTtlMs: 500, maxSessions: 5 },
    });
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result.currentScore).toBe(10);
  });

  // 4. No match = zero weight
  it("returns zero weight for unmatched ruleIds", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.unknown.category",
    ]);
    expect(result.currentScore).toBe(0);
  });

  // 5. Exact beats glob
  it("exact match takes priority over glob", () => {
    const tracker = new FrequencyTracker({
      enabled: true,
      halfLifeMs: 100,
      weights: {
        "drawbridge.prompt_injection.instruction_override": 20,
        "drawbridge.prompt_injection.*": 10,
      },
      thresholds: { tier1: 15, tier2: 30, tier3: 50 },
      memory: { sessionTtlMs: 500, maxSessions: 5 },
    });
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result.currentScore).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

describe("FrequencyTracker — core algorithm", () => {
  // 6. Single finding updates score
  it("single finding sets score to matched weight", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result.currentScore).toBe(10);
    expect(result.previousScore).toBe(0);
  });

  // 7. Multiple findings in one update
  it("sums weights for multiple findings", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
      "drawbridge.credential.api_key",
      "drawbridge.structural.malformed_json",
    ]);
    // 10 + 10 + 5 = 25
    expect(result.currentScore).toBe(25);
  });

  // 8. previousScore reflects decayed state
  it("previousScore reflects decay since last update", () => {
    const tracker = createTestTracker();
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    const first = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(first.currentScore).toBe(10);

    now += 50;

    const second = tracker.update("s1", []);
    expect(second.previousScore).toBeLessThan(first.currentScore);
    expect(second.previousScore).toBeGreaterThan(0);

    vi.restoreAllMocks();
  });

  // 9. Score decays to ~50% after one half-life
  it("score decays to approximately 50% after one half-life", () => {
    const tracker = createTestTracker(); // halfLife = 100ms
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]); // Score = 10

    now += 100; // exactly one half-life

    const result = tracker.update("s1", []);
    // 10 × 2^(-1) = 5.0
    expect(result.previousScore).toBeCloseTo(5, 2);

    vi.restoreAllMocks();
  });

  // 10. Rapid updates accumulate
  it("rapid updates accumulate without significant decay", () => {
    const tracker = createTestTracker();
    tracker.update("s1", ["drawbridge.structural.malformed_json"]); // +5
    tracker.update("s1", ["drawbridge.structural.malformed_json"]); // +5
    tracker.update("s1", ["drawbridge.structural.malformed_json"]); // +5
    const result = tracker.update("s1", [
      "drawbridge.structural.malformed_json",
    ]); // +5
    // ~20 total (minimal decay within same tick)
    expect(result.currentScore).toBeGreaterThan(18);
  });

  // 11. First update on new session
  it("first update has previousScore of 0", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result.previousScore).toBe(0);
    expect(result.currentScore).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// Tier escalation
// ---------------------------------------------------------------------------

describe("FrequencyTracker — tier escalation", () => {
  // 12. Below tier1
  it("single low-weight finding stays at tier none", () => {
    const tracker = createTestTracker();
    const result = tracker.update("s1", [
      "drawbridge.structural.malformed_json",
    ]); // weight 5
    expect(result.tier).toBe("none");
  });

  // 13. Tier1 escalation
  it("escalates to tier1 when score crosses threshold", () => {
    const tracker = createTestTracker(); // tier1 = 15
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override", // 10
      "drawbridge.structural.malformed_json", // 5
      "drawbridge.structural.malformed_json", // 5
    ]);
    // score = 20, above tier1(15)
    expect(result.tier).toBe("tier1");
    expect(result.terminated).toBe(false);
  });

  // 14. Tier2 escalation
  it("escalates to tier2 when score crosses threshold", () => {
    const tracker = createTestTracker(); // tier2 = 30
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override", // 10
      "drawbridge.prompt_injection.instruction_override", // 10
      "drawbridge.credential.api_key", // 10
      "drawbridge.structural.malformed_json", // 5
    ]);
    // score = 35, above tier2(30)
    expect(result.tier).toBe("tier2");
    expect(result.terminated).toBe(false);
  });

  // 15. Tier3 escalation and termination
  it("escalates to tier3 and terminates session", () => {
    const tracker = createTestTracker(); // tier3 = 50
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override", // 10
      "drawbridge.prompt_injection.instruction_override", // 10
      "drawbridge.credential.api_key", // 10
      "drawbridge.credential.api_key", // 10
      "drawbridge.schema.extra-field", // 8
      "drawbridge.structural.malformed_json", // 5
    ]);
    // score = 53, above tier3(50)
    expect(result.tier).toBe("tier3");
    expect(result.terminated).toBe(true);
  });

  // 16. Terminated session is permanent
  it("terminated session stays at tier3 on subsequent updates", () => {
    const tracker = createTestTracker();
    // Push past tier3
    tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
      "drawbridge.prompt_injection.instruction_override",
      "drawbridge.credential.api_key",
      "drawbridge.credential.api_key",
      "drawbridge.schema.extra-field",
      "drawbridge.structural.malformed_json",
    ]);
    const result = tracker.update("s1", []);
    expect(result.tier).toBe("tier3");
    expect(result.terminated).toBe(true);
  });

  // 17. Terminated session does not update score
  it("terminated session returns unchanged score", () => {
    const tracker = createTestTracker();
    const first = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
      "drawbridge.prompt_injection.instruction_override",
      "drawbridge.credential.api_key",
      "drawbridge.credential.api_key",
      "drawbridge.schema.extra-field",
      "drawbridge.structural.malformed_json",
    ]);
    const second = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(second.currentScore).toBe(first.currentScore);
    expect(second.previousScore).toBe(first.currentScore);
  });
});

// ---------------------------------------------------------------------------
// Decay properties (security-relevant)
// ---------------------------------------------------------------------------

describe("FrequencyTracker — decay properties", () => {
  // 18. No cliff effect
  it("partial decay at half a half-life (~70.7%)", () => {
    const tracker = createTestTracker(); // halfLife = 100ms
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]); // score = 10

    now += 50; // half a half-life

    const result = tracker.update("s1", []);
    // 2^(-0.5) ≈ 0.7071, so 10 × 0.7071 ≈ 7.071
    expect(result.previousScore).toBeCloseTo(7.071, 2);
    expect(result.previousScore).toBeGreaterThan(5);
    expect(result.previousScore).toBeLessThan(10);

    vi.restoreAllMocks();
  });

  // 19. Sustained probing detected
  it("sustained probing crosses tier1", () => {
    const tracker = createTestTracker(); // tier1 = 15, halfLife = 100ms
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    let result;
    for (let i = 0; i < 8; i++) {
      result = tracker.update("s1", [
        "drawbridge.structural.malformed_json",
      ]); // weight 5 each
      now += 50;
    }
    // With decay, sustained weight-5 findings at 50ms intervals accumulate past tier1
    expect(result!.tier).not.toBe("none");
    expect(result!.currentScore).toBeGreaterThanOrEqual(15);

    vi.restoreAllMocks();
  });

  // 20. One-off forgiven
  it("one-off finding decays below 2 after two half-lives", () => {
    const tracker = createTestTracker(); // halfLife = 100ms
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    tracker.update("s1", [
      "drawbridge.structural.malformed_json",
    ]); // weight 5

    now += 200; // two half-lives

    const result = tracker.update("s1", []);
    // 5 × 2^(-2) = 5 × 0.25 = 1.25
    expect(result.previousScore).toBeCloseTo(1.25, 2);
    expect(result.previousScore).toBeLessThan(2);

    vi.restoreAllMocks();
  });
});

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

describe("FrequencyTracker — memory management", () => {
  // 21. Passive TTL eviction
  it("evicts stale sessions past TTL", () => {
    const tracker = createTestTracker(); // sessionTtlMs = 500
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    tracker.update("stale-session", [
      "drawbridge.structural.malformed_json",
    ]);
    expect(tracker.getState("stale-session")).not.toBeNull();

    now += 600; // past TTL

    // Trigger eviction via update on a different session
    tracker.update("fresh-session", []);
    expect(tracker.getState("stale-session")).toBeNull();

    vi.restoreAllMocks();
  });

  // 22. Max sessions cap
  it("evicts oldest session when cap is exceeded", () => {
    const tracker = createTestTracker(); // maxSessions = 5

    // Create 5 sessions
    for (let i = 0; i < 5; i++) {
      tracker.update(`session-${i}`, [
        "drawbridge.structural.malformed_json",
      ]);
    }
    expect(tracker.size).toBe(5);

    // 6th session should evict the oldest (session-0)
    tracker.update("session-new", [
      "drawbridge.structural.malformed_json",
    ]);
    expect(tracker.size).toBe(5);
    expect(tracker.getState("session-0")).toBeNull();
    expect(tracker.getState("session-new")).not.toBeNull();
  });

  // 23. reset() removes session
  it("reset removes a session", () => {
    const tracker = createTestTracker();
    tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(tracker.getState("s1")).not.toBeNull();
    tracker.reset("s1");
    expect(tracker.getState("s1")).toBeNull();
  });

  // 24. clear() removes all
  it("clear removes all sessions", () => {
    const tracker = createTestTracker();
    tracker.update("s1", ["drawbridge.structural.malformed_json"]);
    tracker.update("s2", ["drawbridge.structural.malformed_json"]);
    tracker.update("s3", ["drawbridge.structural.malformed_json"]);
    expect(tracker.size).toBe(3);
    tracker.clear();
    expect(tracker.size).toBe(0);
  });

  // 25. size property
  it("size reflects tracked session count", () => {
    const tracker = createTestTracker();
    expect(tracker.size).toBe(0);
    tracker.update("s1", []);
    tracker.update("s2", []);
    tracker.update("s3", []);
    expect(tracker.size).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

describe("FrequencyTracker — configuration", () => {
  // 26. Threshold ordering validated
  it("throws on non-ascending thresholds", () => {
    expect(
      () =>
        new FrequencyTracker({
          thresholds: { tier1: 30, tier2: 20, tier3: 50 },
        }),
    ).toThrow("thresholds must be strictly ascending");
  });

  // 27. Partial config merges with defaults
  it("partial config merges with defaults", () => {
    const tracker = new FrequencyTracker({ halfLifeMs: 200 });
    // Should not throw — all other fields come from defaults
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result.currentScore).toBe(10); // default weight
  });

  // 28. Custom weights override defaults
  it("custom weights fully replace defaults", () => {
    const tracker = new FrequencyTracker({
      weights: { "custom.rule.*": 7 },
    });
    // Default weight keys should not exist
    const r1 = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(r1.currentScore).toBe(0); // no match

    const r2 = tracker.update("s2", ["custom.rule.test"]);
    expect(r2.currentScore).toBe(7);
  });

  // 29. Disabled tracker
  it("disabled tracker returns static result without tracking", () => {
    const tracker = createTestTracker({ enabled: false });
    const result = tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]);
    expect(result).toEqual({
      previousScore: 0,
      currentScore: 0,
      tier: "none",
      terminated: false,
    });
    expect(tracker.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("FrequencyTracker — edge cases", () => {
  // 30. Empty ruleIds array
  it("empty ruleIds decays score without adding weight", () => {
    const tracker = createTestTracker();
    let now = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]); // 10

    now += 50;

    const result = tracker.update("s1", []);
    expect(result.currentScore).toBeLessThan(10);
    expect(result.currentScore).toBe(result.previousScore); // no weight added

    vi.restoreAllMocks();
  });

  // 31. Unknown ruleIds only
  it("unknown ruleIds add zero weight", () => {
    const tracker = createTestTracker();
    tracker.update("s1", [
      "drawbridge.prompt_injection.instruction_override",
    ]); // 10
    const result = tracker.update("s1", [
      "drawbridge.unknown.category",
      "completely.unknown",
    ]);
    // currentScore ≈ 10 (decayed) + 0 = ~10
    expect(result.currentScore).toBeCloseTo(10, 0);
  });

  // 32. Multiple updates same millisecond
  it("same-tick updates accumulate without decay", () => {
    const tracker = createTestTracker();
    // Mock Date.now to return fixed timestamp
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now);

    tracker.update("s1", ["drawbridge.structural.malformed_json"]); // 5
    tracker.update("s1", ["drawbridge.structural.malformed_json"]); // 5
    const result = tracker.update("s1", [
      "drawbridge.structural.malformed_json",
    ]); // 5

    // No decay at elapsed=0: e^0 = 1, so scores accumulate perfectly
    expect(result.currentScore).toBe(15);

    vi.restoreAllMocks();
  });
});
