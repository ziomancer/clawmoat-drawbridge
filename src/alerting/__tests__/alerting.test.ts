import { describe, it, expect, vi, beforeEach } from "vitest";
import { AlertManager } from "../index.js";
import type { AlertManagerConfig, AlertPayload } from "../../types/alerting.js";
import type { TypedAuditEvent, SyntacticAuditEvent } from "../../types/audit.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTestManager(
  overrides?: Partial<AlertManagerConfig>,
): { manager: AlertManager; alerts: AlertPayload[] } {
  const alerts: AlertPayload[] = [];
  const manager = new AlertManager({
    enabled: true,
    onAlert: (a) => alerts.push(a),
    ...overrides,
  });
  return { manager, alerts };
}

/** Build a minimal typed audit event */
function makeEvent(
  type: string,
  sessionId: string = "session-1",
  extra: Record<string, unknown> = {},
): TypedAuditEvent {
  return {
    event: type as any,
    timestamp: new Date().toISOString(),
    sessionId,
    ...extra,
  } as TypedAuditEvent;
}

// ---------------------------------------------------------------------------
// Rule 1: Syntactic fail burst
// ---------------------------------------------------------------------------

describe("Rule 1: syntactic fail burst", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("1 — 4 events below threshold → no alert", () => {
    const { manager, alerts } = createTestManager();
    for (let i = 0; i < 4; i++) {
      manager.evaluate(makeEvent("syntactic_fail"));
    }
    expect(alerts).toHaveLength(0);
  });

  it("2 — 5 events within window → alert fires, severity=medium", () => {
    const { manager, alerts } = createTestManager();
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail"));
    }
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("syntacticFailBurst");
    expect(alerts[0]!.severity).toBe("medium");
  });

  it("3 — 5 events across different sessions → still triggers", () => {
    const { manager, alerts } = createTestManager();
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail", `session-${i}`));
    }
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("syntacticFailBurst");
  });

  it("4 — events outside window don't count", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        syntacticFailBurst: { enabled: true, count: 5, windowMinutes: 10 },
        frequencyEscalation: { tier2Enabled: true, tier3Enabled: true },
        scanBlockAfterSyntacticPass: { enabled: true, escalateAfter: 3 },
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      },
      // Disable dedup so we can see all alerts
      suppressionWindowMinutes: 0.001,
    });

    // Feed 3 events at t=0
    for (let i = 0; i < 3; i++) {
      manager.evaluate(makeEvent("syntactic_fail"));
    }

    // Jump past window (11 min)
    now += 11 * 60_000;

    // Feed 2 more — total in window is only 2
    for (let i = 0; i < 2; i++) {
      manager.evaluate(makeEvent("syntactic_fail"));
    }
    expect(alerts).toHaveLength(0);
  });

  it("5 — rule disabled → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        syntacticFailBurst: { enabled: false, count: 5, windowMinutes: 10 },
        frequencyEscalation: { tier2Enabled: true, tier3Enabled: true },
        scanBlockAfterSyntacticPass: { enabled: true, escalateAfter: 3 },
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      },
    });
    for (let i = 0; i < 10; i++) {
      manager.evaluate(makeEvent("syntactic_fail"));
    }
    expect(alerts).toHaveLength(0);
  });

  it("6 — alert summary includes count and window", () => {
    const { manager, alerts } = createTestManager();
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail"));
    }
    expect(alerts[0]!.summary).toMatch(/5.*syntactic failures/);
    expect(alerts[0]!.summary).toMatch(/10.*minutes/);
  });
});

// ---------------------------------------------------------------------------
// Rule 3: Frequency escalation
// ---------------------------------------------------------------------------

describe("Rule 3: frequency escalation", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockImplementation(() => 1_700_000_000_000);
  });

  it("7 — tier2 event → alert with severity=high", () => {
    const { manager, alerts } = createTestManager();
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("frequencyEscalationTier2");
    expect(alerts[0]!.severity).toBe("high");
  });

  it("8 — tier3 event → alert with severity=critical", () => {
    const { manager, alerts } = createTestManager();
    manager.evaluate(
      makeEvent("frequency_escalation_tier3", "session-1", {
        currentScore: 55.0,
        previousScore: 40.0,
        tier: "tier3",
        terminated: true,
      }),
    );
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("frequencyEscalationTier3");
    expect(alerts[0]!.severity).toBe("critical");
  });

  it("9 — tier2 disabled → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        syntacticFailBurst: { enabled: true, count: 5, windowMinutes: 10 },
        frequencyEscalation: { tier2Enabled: false, tier3Enabled: true },
        scanBlockAfterSyntacticPass: { enabled: true, escalateAfter: 3 },
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      },
    });
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    expect(alerts).toHaveLength(0);
  });

  it("10 — tier3 cannot be disabled", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        syntacticFailBurst: { enabled: true, count: 5, windowMinutes: 10 },
        frequencyEscalation: {
          tier2Enabled: true,
          tier3Enabled: false as any, // Consumer tries to disable
        },
        scanBlockAfterSyntacticPass: { enabled: true, escalateAfter: 3 },
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      },
    });
    manager.evaluate(
      makeEvent("frequency_escalation_tier3", "session-1", {
        currentScore: 55.0,
        previousScore: 40.0,
        tier: "tier3",
        terminated: true,
      }),
    );
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("frequencyEscalationTier3");
  });

  it("11 — alert includes suspicion score", () => {
    const { manager, alerts } = createTestManager();
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    expect(alerts[0]!.details.sessionSuspicionScore).toBe(25.5);
  });
});

// ---------------------------------------------------------------------------
// Rule 4: Scan block after syntactic pass
// ---------------------------------------------------------------------------

describe("Rule 4: scan block after syntactic pass", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("12 — syntactic_pass (no flags) then scan_block with same messageId → alert", () => {
    const { manager, alerts } = createTestManager();

    // Syntactic pass with no flags
    manager.evaluate(
      makeEvent("syntactic_pass", "session-1", {
        messageId: "msg-1",
        pass: true,
        ruleIds: [],
        flags: [],
      }),
    );

    // Scan block on same message
    manager.evaluate(
      makeEvent("scan_block", "session-1", {
        messageId: "msg-1",
        safe: false,
        findingCount: 1,
        blockingFindingCount: 1,
        ruleIds: ["prompt_injection"],
      }),
    );

    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("scanBlockAfterSyntacticPass");
    expect(alerts[0]!.severity).toBe("medium");
  });

  it("13 — syntactic_pass with flags then scan_block → no alert", () => {
    const { manager, alerts } = createTestManager();

    manager.evaluate(
      makeEvent("syntactic_pass", "session-1", {
        messageId: "msg-1",
        pass: true,
        ruleIds: ["base64-encoded-content"],
        flags: ["base64-encoded-content"],
      }),
    );

    manager.evaluate(
      makeEvent("scan_block", "session-1", {
        messageId: "msg-1",
        safe: false,
        findingCount: 1,
        blockingFindingCount: 1,
        ruleIds: ["prompt_injection"],
      }),
    );

    expect(alerts).toHaveLength(0);
  });

  it("14 — scan_block without prior syntactic_pass → no alert", () => {
    const { manager, alerts } = createTestManager();

    manager.evaluate(
      makeEvent("scan_block", "session-1", {
        messageId: "msg-1",
        safe: false,
        findingCount: 1,
        blockingFindingCount: 1,
        ruleIds: ["prompt_injection"],
      }),
    );

    expect(alerts).toHaveLength(0);
  });

  it("15 — events without messageId or toolCallId → no correlation", () => {
    const { manager, alerts } = createTestManager();

    manager.evaluate(
      makeEvent("syntactic_pass", "session-1", {
        pass: true,
        ruleIds: [],
        flags: [],
      }),
    );

    manager.evaluate(
      makeEvent("scan_block", "session-1", {
        safe: false,
        findingCount: 1,
        blockingFindingCount: 1,
        ruleIds: ["prompt_injection"],
      }),
    );

    expect(alerts).toHaveLength(0);
  });

  it("16 — after escalateAfter occurrences, severity escalates to high", () => {
    const { manager, alerts } = createTestManager({
      suppressionWindowMinutes: 0.001, // Disable dedup for this test
    });

    for (let i = 0; i < 4; i++) {
      manager.evaluate(
        makeEvent("syntactic_pass", `session-${i}`, {
          messageId: `msg-${i}`,
          pass: true,
          ruleIds: [],
          flags: [],
        }),
      );

      manager.evaluate(
        makeEvent("scan_block", `session-${i}`, {
          messageId: `msg-${i}`,
          safe: false,
          findingCount: 1,
          blockingFindingCount: 1,
          ruleIds: ["prompt_injection"],
        }),
      );
    }

    // First 2 should be medium, after escalateAfter (3) should be high
    expect(alerts).toHaveLength(4);
    expect(alerts[0]!.severity).toBe("medium");
    expect(alerts[1]!.severity).toBe("medium");
    expect(alerts[2]!.severity).toBe("high"); // occurrence 3 >= escalateAfter(3)
    expect(alerts[3]!.severity).toBe("high");
  });

  it("17 — rule disabled → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        syntacticFailBurst: { enabled: true, count: 5, windowMinutes: 10 },
        frequencyEscalation: { tier2Enabled: true, tier3Enabled: true },
        scanBlockAfterSyntacticPass: { enabled: false, escalateAfter: 3 },
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      },
    });

    manager.evaluate(
      makeEvent("syntactic_pass", "session-1", {
        messageId: "msg-1",
        pass: true,
        ruleIds: [],
        flags: [],
      }),
    );
    manager.evaluate(
      makeEvent("scan_block", "session-1", {
        messageId: "msg-1",
        safe: false,
        findingCount: 1,
        blockingFindingCount: 1,
        ruleIds: ["prompt_injection"],
      }),
    );

    expect(alerts).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Rule 5: Write fail spike (v1.3 — unblocked)
// ---------------------------------------------------------------------------

describe("Rule 5: write fail spike", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("18 — 3 write_failed events in window → alert fires", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      } as any,
    });
    manager.evaluate(makeEvent("write_failed", "s1"));
    manager.evaluate(makeEvent("write_failed", "s1"));
    expect(alerts).toHaveLength(0);
    manager.evaluate(makeEvent("write_failed", "s1"));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("writeFailSpike");
    expect(alerts[0]!.severity).toBe("medium");
  });

  it("18b — 2 write_failed events (below threshold) → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      } as any,
    });
    manager.evaluate(makeEvent("write_failed", "s1"));
    manager.evaluate(makeEvent("write_failed", "s1"));
    expect(alerts).toHaveLength(0);
  });

  it("18c — writeFailSpike disabled → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        writeFailSpike: { enabled: false, count: 3, windowMinutes: 5 },
      } as any,
    });
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("write_failed", "s1"));
    }
    expect(alerts).toHaveLength(0);
  });

  it("18d — events outside window → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        writeFailSpike: { enabled: true, count: 3, windowMinutes: 5 },
      } as any,
    });
    manager.evaluate(makeEvent("write_failed", "s1"));
    manager.evaluate(makeEvent("write_failed", "s1"));
    now += 6 * 60_000; // advance past window
    manager.evaluate(makeEvent("write_failed", "s1"));
    // Only 1 event in the current window
    expect(alerts).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Rule 6: Tool policy block (v1.3)
// ---------------------------------------------------------------------------

describe("Rule 6: tool policy block", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("19 — 1 tool_policy_block event (default count=1) → alert fires", () => {
    const { manager, alerts } = createTestManager();
    manager.evaluate(makeEvent("tool_policy_block", "s1"));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.ruleId).toBe("toolPolicyBlock");
    expect(alerts[0]!.severity).toBe("high");
  });

  it("19b — toolPolicyBlock disabled → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        toolPolicyBlock: { enabled: false, count: 1, windowMinutes: 10 },
      } as any,
    });
    manager.evaluate(makeEvent("tool_policy_block", "s1"));
    expect(alerts).toHaveLength(0);
  });

  it("19c — event outside window → no alert", () => {
    const { manager, alerts } = createTestManager({
      rules: {
        toolPolicyBlock: { enabled: true, count: 2, windowMinutes: 10 },
      } as any,
    });
    manager.evaluate(makeEvent("tool_policy_block", "s1"));
    now += 11 * 60_000;
    manager.evaluate(makeEvent("tool_policy_block", "s1"));
    // Each window only has 1 event, count is 2
    expect(alerts).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe("Deduplication", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("19 — same rule + same session within window → second suppressed", () => {
    const { manager, alerts } = createTestManager({
      suppressionWindowMinutes: 5,
    });

    // Fire 5 to trigger burst → first alert
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }
    expect(alerts).toHaveLength(1);

    // 6th event triggers rule again but should be suppressed
    manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    expect(alerts).toHaveLength(1);
  });

  it("20 — same rule + different session → both fire", () => {
    const { manager, alerts } = createTestManager();

    // Two tier2 events from different sessions
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-2", {
        currentScore: 30.0,
        previousScore: 20.0,
        tier: "tier2",
        terminated: false,
      }),
    );

    expect(alerts).toHaveLength(2);
  });

  it("21 — same rule + same session after window expires → fires again", () => {
    const { manager, alerts } = createTestManager({
      suppressionWindowMinutes: 5,
    });

    // First batch → alert
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }
    expect(alerts).toHaveLength(1);

    // Jump past suppression window
    now += 6 * 60_000;

    // Trigger again → should fire
    manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    expect(alerts).toHaveLength(2);
  });

  it("22 — suppressed count increments correctly", () => {
    const { manager } = createTestManager({
      suppressionWindowMinutes: 5,
    });

    // Trigger burst
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }
    // Suppressed
    manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    manager.evaluate(makeEvent("syntactic_fail", "session-1"));

    expect(manager.suppressed).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

describe("Rate limiting", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("23 — 21st alert in one minute is rate limited (limit=20)", () => {
    const { manager, alerts } = createTestManager({
      rateLimit: { maxPerMinute: 20, maxPerHour: 100 },
      suppressionWindowMinutes: 0.001, // Disable dedup
    });

    // Fire 21 distinct alerts (use tier2 from different sessions)
    for (let i = 0; i < 21; i++) {
      manager.evaluate(
        makeEvent("frequency_escalation_tier2", `session-${i}`, {
          currentScore: 25.5,
          previousScore: 14.0,
          tier: "tier2",
          terminated: false,
        }),
      );
    }

    expect(alerts).toHaveLength(20);
    expect(manager.rateLimited).toBe(1);
  });

  it("24 — rate-limited alerts are not delivered", () => {
    const onAlert = vi.fn();
    const manager = new AlertManager({
      enabled: true,
      onAlert,
      rateLimit: { maxPerMinute: 2, maxPerHour: 100 },
      suppressionWindowMinutes: 0.001,
    });

    for (let i = 0; i < 4; i++) {
      manager.evaluate(
        makeEvent("frequency_escalation_tier2", `session-${i}`, {
          currentScore: 25.5,
          previousScore: 14.0,
          tier: "tier2",
          terminated: false,
        }),
      );
    }

    expect(onAlert).toHaveBeenCalledTimes(2);
  });

  it("25 — rate limit resets after 1 minute", () => {
    const { manager, alerts } = createTestManager({
      rateLimit: { maxPerMinute: 2, maxPerHour: 100 },
      suppressionWindowMinutes: 0.001,
    });

    // Fill minute limit
    for (let i = 0; i < 2; i++) {
      manager.evaluate(
        makeEvent("frequency_escalation_tier2", `session-${i}`, {
          currentScore: 25.5,
          previousScore: 14.0,
          tier: "tier2",
          terminated: false,
        }),
      );
    }
    expect(alerts).toHaveLength(2);

    // Next is rate limited
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-99", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    expect(alerts).toHaveLength(2);

    // Jump past 1 minute
    now += 61_000;

    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-100", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    expect(alerts).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("Error handling", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockImplementation(() => 1_700_000_000_000);
  });

  it("26 — onAlert throws → swallowed, no crash", () => {
    const manager = new AlertManager({
      enabled: true,
      onAlert: () => {
        throw new Error("boom");
      },
      suppressionWindowMinutes: 0.001,
    });

    expect(() => {
      manager.evaluate(
        makeEvent("frequency_escalation_tier2", "session-1", {
          currentScore: 25.5,
          previousScore: 14.0,
          tier: "tier2",
          terminated: false,
        }),
      );
    }).not.toThrow();
  });

  it("27 — onAlert throws + onError provided → onError called", () => {
    const onError = vi.fn();
    const manager = new AlertManager({
      enabled: true,
      onAlert: () => {
        throw new Error("delivery failed");
      },
      onError,
      suppressionWindowMinutes: 0.001,
    });

    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]![0]).toBeInstanceOf(Error);
  });

  it("28 — both onAlert and onError throw → swallowed, no crash", () => {
    const manager = new AlertManager({
      enabled: true,
      onAlert: () => {
        throw new Error("delivery failed");
      },
      onError: () => {
        throw new Error("error handler also failed");
      },
      suppressionWindowMinutes: 0.001,
    });

    expect(() => {
      manager.evaluate(
        makeEvent("frequency_escalation_tier2", "session-1", {
          currentScore: 25.5,
          previousScore: 14.0,
          tier: "tier2",
          terminated: false,
        }),
      );
    }).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Integration flow
// ---------------------------------------------------------------------------

describe("Integration flow", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("29 — realistic sequence fires correct alerts", () => {
    const { manager, alerts } = createTestManager({
      suppressionWindowMinutes: 0.001,
    });

    // 3 syntactic_pass events (indexed for Rule 4 correlation)
    for (let i = 0; i < 3; i++) {
      manager.evaluate(
        makeEvent("syntactic_pass", "session-1", {
          messageId: `msg-${i}`,
          pass: true,
          ruleIds: [],
          flags: [],
        }),
      );
    }

    // 5 syntactic_fail events → burst alert
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }

    // 1 frequency_tier2 → escalation alert
    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );

    // 1 scan_block correlating with msg-0 → Rule 4 alert
    manager.evaluate(
      makeEvent("scan_block", "session-1", {
        messageId: "msg-0",
        safe: false,
        findingCount: 1,
        blockingFindingCount: 1,
        ruleIds: ["prompt_injection"],
      }),
    );

    expect(alerts).toHaveLength(3);

    const ruleIds = alerts.map((a) => a.ruleId);
    expect(ruleIds).toContain("syntacticFailBurst");
    expect(ruleIds).toContain("frequencyEscalationTier2");
    expect(ruleIds).toContain("scanBlockAfterSyntacticPass");

    const burstAlert = alerts.find((a) => a.ruleId === "syntacticFailBurst")!;
    expect(burstAlert.severity).toBe("medium");

    const freqAlert = alerts.find((a) => a.ruleId === "frequencyEscalationTier2")!;
    expect(freqAlert.severity).toBe("high");

    const rule4Alert = alerts.find((a) => a.ruleId === "scanBlockAfterSyntacticPass")!;
    expect(rule4Alert.severity).toBe("medium");
  });
});

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

describe("Stats", () => {
  let now: number;

  beforeEach(() => {
    now = 1_700_000_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
  });

  it("30 — alerts count matches deliveries", () => {
    const { manager, alerts } = createTestManager({
      suppressionWindowMinutes: 0.001,
    });

    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );
    manager.evaluate(
      makeEvent("frequency_escalation_tier3", "session-2", {
        currentScore: 55.0,
        previousScore: 40.0,
        tier: "tier3",
        terminated: true,
      }),
    );

    expect(manager.alerts).toBe(2);
    expect(manager.alerts).toBe(alerts.length);
  });

  it("31 — suppressed count matches dedup suppressions", () => {
    const { manager } = createTestManager({
      suppressionWindowMinutes: 5,
    });

    // 5 to trigger, then 2 suppressed
    for (let i = 0; i < 7; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }

    expect(manager.alerts).toBe(1);
    expect(manager.suppressed).toBe(2);
  });

  it("32 — rateLimited count matches rate limit drops", () => {
    const { manager } = createTestManager({
      rateLimit: { maxPerMinute: 3, maxPerHour: 100 },
      suppressionWindowMinutes: 0.001,
    });

    for (let i = 0; i < 5; i++) {
      manager.evaluate(
        makeEvent("frequency_escalation_tier2", `session-${i}`, {
          currentScore: 25.5,
          previousScore: 14.0,
          tier: "tier2",
          terminated: false,
        }),
      );
    }

    expect(manager.alerts).toBe(3);
    expect(manager.rateLimited).toBe(2);
  });

  it("33 — clear() resets all state and counters", () => {
    const { manager, alerts } = createTestManager({
      suppressionWindowMinutes: 0.001,
    });

    // Build up some state
    for (let i = 0; i < 5; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }
    expect(alerts).toHaveLength(1);

    manager.clear();

    expect(manager.alerts).toBe(0);
    expect(manager.suppressed).toBe(0);
    expect(manager.rateLimited).toBe(0);

    // After clear, burst counter is reset — need 5 again
    for (let i = 0; i < 4; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }
    expect(alerts).toHaveLength(1); // Still only the pre-clear alert
  });
});

// ---------------------------------------------------------------------------
// Enabled toggle
// ---------------------------------------------------------------------------

describe("Enabled toggle", () => {
  it("34 — enabled=false → evaluate returns null for all events", () => {
    const { manager, alerts } = createTestManager({ enabled: false });

    const result = manager.evaluate(
      makeEvent("frequency_escalation_tier3", "session-1", {
        currentScore: 55.0,
        previousScore: 40.0,
        tier: "tier3",
        terminated: true,
      }),
    );

    expect(result).toBeNull();
    expect(alerts).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Alert payload shape
// ---------------------------------------------------------------------------

describe("Alert payload shape", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockImplementation(() => 1_700_000_000_000);
  });

  it("35 — alertId is a valid UUID", () => {
    const { manager, alerts } = createTestManager();

    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );

    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(alerts[0]!.alertId).toMatch(uuidRegex);
  });

  it("36 — timestamp is ISO 8601", () => {
    const { manager, alerts } = createTestManager();

    manager.evaluate(
      makeEvent("frequency_escalation_tier2", "session-1", {
        currentScore: 25.5,
        previousScore: 14.0,
        tier: "tier2",
        terminated: false,
      }),
    );

    expect(new Date(alerts[0]!.timestamp).toISOString()).toBe(
      alerts[0]!.timestamp,
    );
  });

  it("37 — recentContext capped at recentContextMax", () => {
    const { manager, alerts } = createTestManager({
      recentContextMax: 3,
      suppressionWindowMinutes: 0.001,
    });

    // Feed 10 events into session, then trigger an alert
    for (let i = 0; i < 10; i++) {
      manager.evaluate(makeEvent("syntactic_fail", "session-1"));
    }

    // The burst alert should have recentContext capped at 3
    expect(alerts.length).toBeGreaterThanOrEqual(1);
    expect(alerts[0]!.details.recentContext.length).toBeLessThanOrEqual(3);
  });

  it("38 — triggeringEvents contains the events that caused the alert", () => {
    const { manager, alerts } = createTestManager();

    const triggerEvent = makeEvent("frequency_escalation_tier2", "session-1", {
      currentScore: 25.5,
      previousScore: 14.0,
      tier: "tier2",
      terminated: false,
    });

    manager.evaluate(triggerEvent);

    expect(alerts[0]!.details.triggeringEvents).toHaveLength(1);
    expect(alerts[0]!.details.triggeringEvents[0]).toBe(triggerEvent);
  });
});
