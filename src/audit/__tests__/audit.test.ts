import { describe, it, expect, vi } from "vitest";
import { AuditEmitter, sha256 } from "../index.js";
import { meetsVerbosity } from "../../types/audit.js";
import type { AuditEmitterConfig, TypedAuditEvent } from "../../types/audit.js";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function createTestEmitter(
  overrides?: Partial<AuditEmitterConfig>,
): { emitter: AuditEmitter; events: TypedAuditEvent[] } {
  const events: TypedAuditEvent[] = [];
  const emitter = new AuditEmitter({
    enabled: true,
    verbosity: "maximum",
    onEvent: (e) => events.push(e),
    alertingEnabled: false,
    ...overrides,
  });
  return { emitter, events };
}

// ---------------------------------------------------------------------------
// Verbosity gating (tests 1–8)
// ---------------------------------------------------------------------------

describe("AuditEmitter — verbosity gating", () => {
  // 1. minimal: scan_block emitted, scan_pass dropped
  it("minimal: scan_block emitted, scan_pass dropped", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "minimal" });
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1,
      blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0,
      blockingFindingCount: 0, ruleIds: [],
    });
    const scanEvents = events.filter((e) => e.event === "scan_block" || e.event === "scan_pass");
    expect(scanEvents).toHaveLength(1);
    expect(scanEvents[0]!.event).toBe("scan_block");
  });

  // 2. minimal: syntactic_fail emitted, syntactic_pass dropped
  it("minimal: syntactic_fail emitted, syntactic_pass dropped", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "minimal" });
    emitter.emitSyntactic({
      sessionId: "s1", pass: false, ruleIds: ["r.x"], flags: ["f"], hasFlags: false,
    });
    emitter.emitSyntactic({
      sessionId: "s1", pass: true, ruleIds: [], flags: [], hasFlags: false,
    });
    const syntacticEvents = events.filter(
      (e) => e.event === "syntactic_fail" || e.event === "syntactic_pass",
    );
    expect(syntacticEvents).toHaveLength(1);
    expect(syntacticEvents[0]!.event).toBe("syntactic_fail");
  });

  // 3. minimal: all frequency escalation events emitted
  it("minimal: frequency escalation events emitted", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "minimal" });
    for (const tier of ["tier1", "tier2", "tier3"] as const) {
      emitter.emitFrequency({
        sessionId: "s1", previousScore: 0, currentScore: 50, tier, terminated: tier === "tier3",
      });
    }
    const freqEvents = events.filter((e) => e.event.startsWith("frequency_"));
    expect(freqEvents).toHaveLength(3);
  });

  // 4. standard: includes pass events and flags_summary
  it("standard: includes pass events and flags_summary", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "standard" });
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0, ruleIds: [],
    });
    emitter.emitFlagsSummary({
      sessionId: "s1", stage: "scanner", ruleIds: [], flagCount: 0, blocked: false,
    });
    expect(events.some((e) => e.event === "scan_pass")).toBe(true);
    expect(events.some((e) => e.event === "flags_summary")).toBe(true);
  });

  // 5. high: includes rule_triggered and output_diff
  it("high: includes rule_triggered and output_diff", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "high" });
    emitter.emitRuleTriggered({
      sessionId: "s1", ruleIds: ["r.x"], severities: { "r.x": "block" }, stage: "scanner",
    });
    emitter.emitOutputDiff({
      sessionId: "s1", removals: [], replacements: [],
    });
    expect(events.some((e) => e.event === "rule_triggered")).toBe(true);
    expect(events.some((e) => e.event === "output_diff")).toBe(true);
  });

  // 6. high: flags_summary is suppressed
  it("high: flags_summary is suppressed", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "high" });
    const result = emitter.emitFlagsSummary({
      sessionId: "s1", stage: "scanner", ruleIds: ["r.x"], flagCount: 1, blocked: false,
    });
    expect(result).toBeNull();
    expect(events.some((e) => e.event === "flags_summary")).toBe(false);
  });

  // 7. maximum: raw captures emitted
  it("maximum: raw captures emitted", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "maximum" });
    emitter.emitRawCapture({ sessionId: "s1", type: "input", content: "hello" });
    emitter.emitRawCapture({ sessionId: "s1", type: "output", content: "world" });
    expect(events.some((e) => e.event === "raw_input_captured")).toBe(true);
    expect(events.some((e) => e.event === "raw_output_captured")).toBe(true);
  });

  // 8. each tier includes lower tier events (except flags_summary at high+)
  it("higher tiers include lower tier events", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "high" });
    // minimal event
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    // standard event
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0, ruleIds: [],
    });
    // high event
    emitter.emitRuleTriggered({
      sessionId: "s1", ruleIds: ["r.x"], severities: {}, stage: "scanner",
    });
    expect(events.some((e) => e.event === "scan_block")).toBe(true);
    expect(events.some((e) => e.event === "scan_pass")).toBe(true);
    expect(events.some((e) => e.event === "rule_triggered")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Alerting override (tests 9–10)
// ---------------------------------------------------------------------------

describe("AuditEmitter — alerting override", () => {
  // 9. alertingEnabled=true + minimal: syntactic_pass IS emitted
  it("alertingEnabled=true forces syntactic_pass at minimal", () => {
    const { emitter, events } = createTestEmitter({
      verbosity: "minimal", alertingEnabled: true,
    });
    emitter.emitSyntactic({
      sessionId: "s1", pass: true, ruleIds: [], flags: [], hasFlags: false,
    });
    expect(events.some((e) => e.event === "syntactic_pass")).toBe(true);
  });

  // 10. alertingEnabled=false + minimal: syntactic_pass NOT emitted
  it("alertingEnabled=false drops syntactic_pass at minimal", () => {
    const { emitter, events } = createTestEmitter({
      verbosity: "minimal", alertingEnabled: false,
    });
    emitter.emitSyntactic({
      sessionId: "s1", pass: true, ruleIds: [], flags: [], hasFlags: false,
    });
    expect(events.some((e) => e.event === "syntactic_pass")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Enabled toggle (tests 11–13)
// ---------------------------------------------------------------------------

describe("AuditEmitter — enabled toggle", () => {
  // 11. disabled: no events emitted, dropCount increments
  it("disabled: no events emitted", () => {
    const { emitter, events } = createTestEmitter({ enabled: false });
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    expect(events).toHaveLength(0);
    expect(emitter.dropped).toBeGreaterThan(0);
  });

  // 12. disabled: audit_config_loaded NOT emitted
  it("disabled: audit_config_loaded not emitted", () => {
    const { events } = createTestEmitter({ enabled: false });
    expect(events.some((e) => e.event === "audit_config_loaded")).toBe(false);
  });

  // 13. enabled: audit_config_loaded IS emitted on construction
  it("enabled: audit_config_loaded emitted on construction", () => {
    const { events } = createTestEmitter({ enabled: true });
    expect(events[0]!.event).toBe("audit_config_loaded");
  });
});

// ---------------------------------------------------------------------------
// Error handling (tests 14–17)
// ---------------------------------------------------------------------------

describe("AuditEmitter — error handling", () => {
  // 14. onEvent throws: swallowed, errorCount increments
  it("onEvent throw is swallowed, errorCount increments", () => {
    const emitter = new AuditEmitter({
      enabled: true, verbosity: "maximum",
      onEvent: () => { throw new Error("boom"); },
      alertingEnabled: false,
    });
    const result = emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    expect(result).toBeNull();
    // errorCount includes the audit_config_loaded event that also threw
    expect(emitter.errors).toBeGreaterThanOrEqual(1);
  });

  // 15. onEvent throws + onError provided: onError called
  it("onError called when onEvent throws", () => {
    const onError = vi.fn();
    const emitter = new AuditEmitter({
      enabled: true, verbosity: "maximum",
      onEvent: () => { throw new Error("boom"); },
      onError,
      alertingEnabled: false,
    });
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    expect(onError).toHaveBeenCalled();
  });

  // 16. onEvent AND onError both throw: no crash
  it("onError throwing is also swallowed", () => {
    expect(() => {
      const emitter = new AuditEmitter({
        enabled: true, verbosity: "maximum",
        onEvent: () => { throw new Error("boom"); },
        onError: () => { throw new Error("double boom"); },
        alertingEnabled: false,
      });
      emitter.emitScan({
        sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
      });
    }).not.toThrow();
  });

  // 17. No onEvent provided: events silently accepted, emitCount increments
  it("no onEvent: events accepted silently", () => {
    const emitter = new AuditEmitter({
      enabled: true, verbosity: "maximum", alertingEnabled: false,
    });
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    // audit_config_loaded + scan_block
    expect(emitter.emitted).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Convenience emitters (tests 18–31)
// ---------------------------------------------------------------------------

describe("AuditEmitter — convenience emitters", () => {
  // 18. emitScan safe=true → scan_pass
  it("emitScan safe=true → scan_pass", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0, ruleIds: [],
    });
    const scan = events.find((e) => e.event === "scan_pass");
    expect(scan).toBeDefined();
  });

  // 19. emitScan safe=false → scan_block
  it("emitScan safe=false → scan_block", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    const scan = events.find((e) => e.event === "scan_block");
    expect(scan).toBeDefined();
  });

  // 20. emitSyntactic pass=true, no flags → syntactic_pass
  it("emitSyntactic pass+noFlags → syntactic_pass", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitSyntactic({
      sessionId: "s1", pass: true, ruleIds: [], flags: [], hasFlags: false,
    });
    expect(events.some((e) => e.event === "syntactic_pass")).toBe(true);
  });

  // 21. emitSyntactic pass=true, hasFlags=true → syntactic_flags
  it("emitSyntactic pass+hasFlags → syntactic_flags", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitSyntactic({
      sessionId: "s1", pass: true, ruleIds: ["r.x"], flags: ["f"], hasFlags: true,
    });
    expect(events.some((e) => e.event === "syntactic_flags")).toBe(true);
  });

  // 22. emitSyntactic pass=false → syntactic_fail
  it("emitSyntactic pass=false → syntactic_fail", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitSyntactic({
      sessionId: "s1", pass: false, ruleIds: ["r.x"], flags: ["f"], hasFlags: false,
    });
    expect(events.some((e) => e.event === "syntactic_fail")).toBe(true);
  });

  // 23. emitFrequency tier2 → frequency_escalation_tier2
  it("emitFrequency tier2 → frequency_escalation_tier2", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitFrequency({
      sessionId: "s1", previousScore: 10, currentScore: 35, tier: "tier2", terminated: false,
    });
    expect(events.some((e) => e.event === "frequency_escalation_tier2")).toBe(true);
  });

  // 24. emitSanitize → content_sanitized with metadata
  it("emitSanitize → content_sanitized", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitSanitize({
      sessionId: "s1", redactionCount: 2, charactersRemoved: 50, redactedRuleIds: ["r.a", "r.b"],
    });
    const evt = events.find((e) => e.event === "content_sanitized");
    expect(evt).toBeDefined();
    expect((evt as { redactionCount: number }).redactionCount).toBe(2);
  });

  // 25. emitProfileLoaded → includes suppressedRules and frequencyOverrides
  it("emitProfileLoaded includes profile details", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitProfileLoaded({
      sessionId: "s1", profileId: "admin", baseProfileId: "admin",
      suppressedRules: ["r.x"], frequencyOverrides: { "r.y": 15 },
    });
    const evt = events.find((e) => e.event === "profile_loaded");
    expect(evt).toBeDefined();
    expect((evt as { suppressedRules: string[] }).suppressedRules).toContain("r.x");
  });

  // 26. emitFlagsSummary → includes stage, ruleIds, flagCount
  it("emitFlagsSummary includes fields", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "standard" });
    emitter.emitFlagsSummary({
      sessionId: "s1", stage: "syntactic", ruleIds: ["r.a"], flagCount: 1, blocked: false,
    });
    const evt = events.find((e) => e.event === "flags_summary");
    expect(evt).toBeDefined();
    expect((evt as { stage: string }).stage).toBe("syntactic");
  });

  // 27. emitRuleTriggered fans out
  it("emitRuleTriggered fans out to individual events", () => {
    const { emitter, events } = createTestEmitter();
    const result = emitter.emitRuleTriggered({
      sessionId: "s1",
      ruleIds: ["drawbridge.injection.a", "drawbridge.injection.b", "drawbridge.structural.c"],
      severities: { "drawbridge.injection.a": "block", "drawbridge.injection.b": "flag" },
      stage: "scanner",
    });
    expect(result).toHaveLength(3);
    const triggered = events.filter((e) => e.event === "rule_triggered");
    expect(triggered).toHaveLength(3);
  });

  // 28. emitRuleTriggered extracts ruleCategory
  it("emitRuleTriggered extracts ruleCategory from ruleId", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitRuleTriggered({
      sessionId: "s1",
      ruleIds: ["drawbridge.syntactic.injection.ignore-previous"],
      severities: {},
      stage: "syntactic",
    });
    const triggered = events.find((e) => e.event === "rule_triggered") as { ruleCategory: string };
    expect(triggered.ruleCategory).toBe("drawbridge.syntactic.injection");
  });

  // 29. emitOutputDiff → includes removals and replacements
  it("emitOutputDiff includes arrays", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitOutputDiff({
      sessionId: "s1",
      removals: [{ ruleId: "r.x", matchedLength: 10, sha256: "abc" }],
      replacements: [{ ruleId: "r.y", lengthBefore: 20, lengthAfter: 10, sha256Before: "def" }],
    });
    const evt = events.find((e) => e.event === "output_diff") as {
      removals: unknown[]; replacements: unknown[];
    };
    expect(evt.removals).toHaveLength(1);
    expect(evt.replacements).toHaveLength(1);
  });

  // 30. emitRawCapture input → raw_input_captured with sha256
  it("emitRawCapture input → raw_input_captured with sha256", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitRawCapture({ sessionId: "s1", type: "input", content: "test content" });
    const evt = events.find((e) => e.event === "raw_input_captured") as {
      sha256: string; contentLength: number;
    };
    expect(evt).toBeDefined();
    expect(evt.sha256).toBe(sha256("test content"));
    expect(evt.contentLength).toBe(12);
  });

  // 31. emitRawCapture output → raw_output_captured
  it("emitRawCapture output → raw_output_captured", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitRawCapture({ sessionId: "s1", type: "output", content: "response" });
    expect(events.some((e) => e.event === "raw_output_captured")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Event shape (tests 32–34)
// ---------------------------------------------------------------------------

describe("AuditEmitter — event shape", () => {
  // 32. All events have ISO timestamp
  it("events have ISO 8601 timestamp", () => {
    const { events } = createTestEmitter();
    for (const e of events) {
      expect(e.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  // 33. All events have sessionId
  it("events have sessionId", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitScan({
      sessionId: "test-session", safe: true, findingCount: 0,
      blockingFindingCount: 0, ruleIds: [],
    });
    const scan = events.find((e) => e.event === "scan_pass");
    expect(scan!.sessionId).toBe("test-session");
  });

  // 34. Optional fields present when provided, absent when not
  it("optional fields included when provided", () => {
    const { emitter, events } = createTestEmitter();
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0,
      ruleIds: [], agentId: "agent-1", messageId: "msg-1", profile: "admin",
    });
    const scan = events.find((e) => e.event === "scan_pass")!;
    expect(scan.agentId).toBe("agent-1");
    expect(scan.messageId).toBe("msg-1");
    expect(scan.profile).toBe("admin");
  });
});

// ---------------------------------------------------------------------------
// Stats (tests 35–38)
// ---------------------------------------------------------------------------

describe("AuditEmitter — stats", () => {
  // 35. emitted count
  it("emitted count matches successful emissions", () => {
    const { emitter } = createTestEmitter();
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0, ruleIds: [],
    });
    // audit_config_loaded (1) + scan_pass (1) = 2
    expect(emitter.emitted).toBe(2);
  });

  // 36. dropped count
  it("dropped count matches gated events", () => {
    const { emitter } = createTestEmitter({ verbosity: "minimal" });
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0, ruleIds: [],
    });
    // scan_pass requires standard, dropped at minimal
    expect(emitter.dropped).toBeGreaterThan(0);
  });

  // 37. errors count
  it("errors count matches onEvent failures", () => {
    const emitter = new AuditEmitter({
      enabled: true, verbosity: "maximum",
      onEvent: () => { throw new Error("fail"); },
      alertingEnabled: false,
    });
    // audit_config_loaded threw (1), plus manual call (2)
    emitter.emitScan({
      sessionId: "s1", safe: false, findingCount: 1, blockingFindingCount: 1, ruleIds: ["r.x"],
    });
    expect(emitter.errors).toBe(2);
  });

  // 38. resetStats zeroes all counters
  it("resetStats zeroes counters", () => {
    const { emitter } = createTestEmitter();
    emitter.emitScan({
      sessionId: "s1", safe: true, findingCount: 0, blockingFindingCount: 0, ruleIds: [],
    });
    expect(emitter.emitted).toBeGreaterThan(0);
    emitter.resetStats();
    expect(emitter.emitted).toBe(0);
    expect(emitter.dropped).toBe(0);
    expect(emitter.errors).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Tool policy + write_failed emitters (v1.3)
// ---------------------------------------------------------------------------

describe("AuditEmitter — tool policy emitter", () => {
  it("emitToolPolicy block → tool_policy_block at minimal", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "minimal" });
    const ev = emitter.emitToolPolicy({
      sessionId: "s1",
      block: true,
      toolName: "exec",
      paramsHash: "abc123",
      policyDecision: "deny",
      policyReason: "dangerous",
      policySeverity: "critical",
      escalationApplied: false,
      sessionTier: "none",
      paramScanUnsafe: false,
      paramScanFindingCount: 0,
    });
    expect(ev).not.toBeNull();
    expect(ev!.event).toBe("tool_policy_block");
    const emitted = events.filter((e) => e.event === "tool_policy_block");
    expect(emitted).toHaveLength(1);
  });

  it("emitToolPolicy allow → tool_policy_allow at high", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "high" });
    const ev = emitter.emitToolPolicy({
      sessionId: "s1",
      block: false,
      toolName: "read",
      paramsHash: "def456",
      policyDecision: "allow",
      escalationApplied: false,
      sessionTier: "none",
      paramScanUnsafe: false,
      paramScanFindingCount: 0,
    });
    expect(ev).not.toBeNull();
    expect(ev!.event).toBe("tool_policy_allow");
  });

  it("tool_policy_allow dropped at standard verbosity", () => {
    const { emitter } = createTestEmitter({ verbosity: "standard" });
    const ev = emitter.emitToolPolicy({
      sessionId: "s1",
      block: false,
      toolName: "read",
      paramsHash: "x",
      policyDecision: "allow",
      escalationApplied: false,
      sessionTier: "none",
      paramScanUnsafe: false,
      paramScanFindingCount: 0,
    });
    expect(ev).toBeNull();
  });

  it("tool_policy_block emitted even at minimal", () => {
    const { emitter } = createTestEmitter({ verbosity: "minimal" });
    const ev = emitter.emitToolPolicy({
      sessionId: "s1",
      block: true,
      toolName: "exec",
      paramsHash: "x",
      policyDecision: "deny",
      escalationApplied: false,
      sessionTier: "tier1",
      paramScanUnsafe: true,
      paramScanFindingCount: 2,
    });
    expect(ev).not.toBeNull();
    expect(ev!.sessionTier).toBe("tier1");
    expect(ev!.paramScanUnsafe).toBe(true);
    expect(ev!.paramScanFindingCount).toBe(2);
  });
});

describe("AuditEmitter — write_failed emitter", () => {
  it("emitWriteFailed → write_failed at minimal", () => {
    const { emitter, events } = createTestEmitter({ verbosity: "minimal" });
    const ev = emitter.emitWriteFailed({
      sessionId: "s1",
      toolName: "write",
      cause: "policy_block",
      errorCategory: "policy",
      errorSummary: "blocked by guard",
    });
    expect(ev).not.toBeNull();
    expect(ev!.event).toBe("write_failed");
    expect(ev!.cause).toBe("policy_block");
    const emitted = events.filter((e) => e.event === "write_failed");
    expect(emitted).toHaveLength(1);
  });

  it("write_failed includes all fields", () => {
    const { emitter } = createTestEmitter();
    const ev = emitter.emitWriteFailed({
      sessionId: "s1",
      toolName: "file_write",
      cause: "runtime_error",
      errorCategory: "timeout",
      errorSummary: "write timed out",
      agentId: "agent-1",
      toolCallId: "tc-1",
    });
    expect(ev!.toolName).toBe("file_write");
    expect(ev!.cause).toBe("runtime_error");
    expect(ev!.errorCategory).toBe("timeout");
    expect(ev!.agentId).toBe("agent-1");
    expect(ev!.toolCallId).toBe("tc-1");
  });
});

// ---------------------------------------------------------------------------
// meetsVerbosity utility (tests 39–41)
// ---------------------------------------------------------------------------

describe("meetsVerbosity", () => {
  // 39. high meets standard
  it("high >= standard → true", () => {
    expect(meetsVerbosity("high", "standard")).toBe(true);
  });

  // 40. standard does not meet high
  it("standard >= high → false", () => {
    expect(meetsVerbosity("standard", "high")).toBe(false);
  });

  // 41. equal meets
  it("minimal >= minimal → true", () => {
    expect(meetsVerbosity("minimal", "minimal")).toBe(true);
  });
});
