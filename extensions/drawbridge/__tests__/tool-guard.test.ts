import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  ToolCallGuard,
  FrequencyTracker,
  DrawbridgePipeline,
} from "@vigil-harbor/clawmoat-drawbridge";
import type { ClawMoatPolicyEngine, ToolPolicyResult } from "@vigil-harbor/clawmoat-drawbridge";
import { handleBeforeToolCallGuard } from "../src/hooks/before-tool-call-guard.js";
import { createDrawbridgePlugin } from "../src/index.js";
import { createToolErrorEnricher } from "../src/hooks/tool-error-enricher.js";
import { resolveConfig } from "../src/config.js";
import { LogSink } from "../src/audit-sink.js";
import type { PluginState } from "../src/pipeline-factory.js";
import {
  createMockEngine,
  createTestState,
  makeBeforeToolCallEvent,
  makeBeforeToolCallCtx,
} from "./helpers.js";

// ---------------------------------------------------------------------------
// Guard-enabled PluginState factory
// ---------------------------------------------------------------------------

function mockPolicyEngine(result?: Partial<ToolPolicyResult>): ClawMoatPolicyEngine {
  return {
    evaluateTool: vi.fn().mockReturnValue({
      decision: "allow",
      reason: "No policy defined",
      ...result,
    }),
  };
}

function createGuardState(
  overrides?: {
    configOverrides?: Parameters<typeof resolveConfig>[0];
    policyEngine?: ClawMoatPolicyEngine;
    guardEnabled?: boolean;
  },
): PluginState {
  const base = createTestState(overrides?.configOverrides);
  const config = resolveConfig({
    toolGuardEnabled: overrides?.guardEnabled ?? true,
    ...overrides?.configOverrides,
  });

  const guard = config.toolGuardEnabled
    ? new ToolCallGuard({
        pipeline: base.inbound,
        tracker: base.tracker,
        engine: overrides?.policyEngine,
        exemptTools: [...config.exemptTools],
        restrictedTools: [...config.restrictedTools],
        escalateWarnings: config.escalateWarnings,
        scanParams: config.scanParams,
      })
    : null;

  return { ...base, guard, config };
}

// ---------------------------------------------------------------------------
// Registration priority
// ---------------------------------------------------------------------------

describe("tool-guard hook — registration", () => {
  it("registers at priority 10", () => {
    const registrations: Array<{ hook: string; priority?: number }> = [];
    const api = {
      on: (hookName: string, _handler: unknown, opts?: { priority?: number }) => {
        registrations.push({ hook: hookName, priority: opts?.priority });
      },
    };

    const plugin = createDrawbridgePlugin({ config: { toolGuardEnabled: true } });
    plugin.register(api);

    const guardReg = registrations.find(
      (r) => r.hook === "before_tool_call" && r.priority === 10,
    );
    expect(guardReg).toBeDefined();
  });

  it("enricher registers before_tool_call without priority (default)", () => {
    const registrations: Array<{ hook: string; priority?: number }> = [];
    const api = {
      on: (hookName: string, _handler: unknown, opts?: { priority?: number }) => {
        registrations.push({ hook: hookName, priority: opts?.priority });
      },
    };

    const plugin = createDrawbridgePlugin();
    plugin.register(api);

    const enricherBtc = registrations.filter(
      (r) => r.hook === "before_tool_call" && r.priority === undefined,
    );
    expect(enricherBtc.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Guard disabled
// ---------------------------------------------------------------------------

describe("tool-guard hook — disabled", () => {
  it("toolGuardEnabled: false → returns {}", () => {
    const state = createGuardState({ guardEnabled: false });
    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );
    expect(result).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// PluginState null (guard absent)
// ---------------------------------------------------------------------------

describe("tool-guard hook — state.guard null", () => {
  it("guard is null → returns {}", () => {
    const state = createTestState();
    // state.guard is null from createTestState
    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );
    expect(result).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// Exemptions
// ---------------------------------------------------------------------------

describe("tool-guard hook — exemptions", () => {
  it("exempt tool passes through", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "bad" });
    const state = createGuardState({
      configOverrides: { exemptTools: ["exec"] },
      policyEngine: engine,
    });
    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "bash" }),
      makeBeforeToolCallCtx(),
    );
    expect(result).toEqual({});
    expect(engine.evaluateTool).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Session key derivation
// ---------------------------------------------------------------------------

describe("tool-guard hook — session key derivation", () => {
  it("uses ctx.sessionKey when available", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx({ sessionKey: "channel-1:conv-1" }),
    );
    expect(engine.evaluateTool).toHaveBeenCalled();
  });

  it("falls back to channelId:conversationId when no sessionKey", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx({
        sessionKey: undefined,
        channelId: "ch-1",
        conversationId: "conv-2",
      } as any),
    );
    expect(engine.evaluateTool).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Audit routing
// ---------------------------------------------------------------------------

describe("tool-guard hook — audit routing", () => {
  it("block emits tool_policy_block audit event", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "dangerous" });
    const state = createGuardState({ policyEngine: engine });
    const emitSpy = vi.spyOn(state.auditSink, "emit");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    const blockEvent = emitSpy.mock.calls.find(
      (call) => (call[0] as any).event === "tool_policy_block",
    );
    expect(blockEvent).toBeDefined();
    expect((blockEvent![0] as any).policyDecision).toBe("deny");
  });

  it("allow emits tool_policy_allow audit event", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    const emitSpy = vi.spyOn(state.auditSink, "emit");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx(),
    );

    const allowEvent = emitSpy.mock.calls.find(
      (call) => (call[0] as any).event === "tool_policy_allow",
    );
    expect(allowEvent).toBeDefined();
  });

  it("audit event includes sessionId, toolName, paramsHash", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    const emitSpy = vi.spyOn(state.auditSink, "emit");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read", params: { path: "/etc" } }),
      makeBeforeToolCallCtx({ sessionKey: "test-session" }),
    );

    const event = emitSpy.mock.calls[0]![0] as Record<string, unknown>;
    expect(event.sessionId).toBe("test-session");
    expect(event.toolName).toBe("read");
    expect(event.paramsHash).toMatch(/^[a-f0-9]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// Alert routing
// ---------------------------------------------------------------------------

describe("tool-guard hook — alert routing", () => {
  it("block emits audit event that AlertManager can evaluate", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "bad tool" });
    const state = createGuardState({ policyEngine: engine });
    const events: Array<Record<string, unknown>> = [];
    vi.spyOn(state.auditSink, "emit").mockImplementation((e: any) => events.push(e));

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    const blockEvents = events.filter((e) => e.event === "tool_policy_block");
    expect(blockEvents).toHaveLength(1);
    expect(blockEvents[0]!.policyDecision).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// write_failed emission
// ---------------------------------------------------------------------------

describe("tool-guard hook — write_failed emission", () => {
  it("blocked write tool emits write_failed alongside tool_policy_block", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "bad write" });
    const state = createGuardState({ policyEngine: engine });
    const events: Array<Record<string, unknown>> = [];
    vi.spyOn(state.auditSink, "emit").mockImplementation((e: any) => events.push(e));

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "file_write" }),
      makeBeforeToolCallCtx(),
    );

    const blockEvent = events.find((e) => e.event === "tool_policy_block");
    const writeFailEvent = events.find((e) => e.event === "write_failed");
    expect(blockEvent).toBeDefined();
    expect(writeFailEvent).toBeDefined();
    expect((writeFailEvent as any).cause).toBe("policy_block");
    expect((writeFailEvent as any).toolName).toBe("write");
    expect((writeFailEvent as any).errorCategory).toBe("policy");
  });

  it("blocked non-write tool does NOT emit write_failed", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "blocked" });
    const state = createGuardState({ policyEngine: engine });
    const events: Array<Record<string, unknown>> = [];
    vi.spyOn(state.auditSink, "emit").mockImplementation((e: any) => events.push(e));

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    const writeFailEvents = events.filter((e) => e.event === "write_failed");
    expect(writeFailEvents).toHaveLength(0);
  });

  it("allowed write tool does NOT emit write_failed", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    const events: Array<Record<string, unknown>> = [];
    vi.spyOn(state.auditSink, "emit").mockImplementation((e: any) => events.push(e));

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "file_write" }),
      makeBeforeToolCallCtx(),
    );

    const writeFailEvents = events.filter((e) => e.event === "write_failed");
    expect(writeFailEvents).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Coexistence with enricher
// ---------------------------------------------------------------------------

describe("tool-guard hook — coexistence with enricher", () => {
  it("guard blocks → enricher before_tool_call never fires (priority ordering)", () => {
    const handlers: Array<{
      hook: string;
      handler: (...args: unknown[]) => unknown;
      priority: number;
    }> = [];
    const api = {
      on: (
        hookName: string,
        handler: (...args: unknown[]) => unknown,
        opts?: { priority?: number },
      ) => {
        handlers.push({ hook: hookName, priority: opts?.priority ?? 100, handler });
      },
    };

    const plugin = createDrawbridgePlugin({
      config: { toolGuardEnabled: true },
    });
    plugin.register(api);

    const btcHandlers = handlers
      .filter((h) => h.hook === "before_tool_call")
      .sort((a, b) => a.priority - b.priority);

    // Guard at priority 10, enricher at default (100)
    expect(btcHandlers.length).toBeGreaterThanOrEqual(2);
    expect(btcHandlers[0]!.priority).toBe(10);
  });

  it("guard allows → enricher still registered and can run", () => {
    const enricher = createToolErrorEnricher();
    const handlers: Array<{
      hook: string;
      handler: (...args: unknown[]) => unknown;
    }> = [];
    const api = {
      on: (hookName: string, handler: (...args: unknown[]) => unknown) => {
        handlers.push({ hook: hookName, handler });
      },
    };

    enricher.registerHooks(api);

    const enricherBtc = handlers.find((h) => h.hook === "before_tool_call");
    expect(enricherBtc).toBeDefined();

    // Enricher should not block a clean tool call
    const result = enricherBtc!.handler(
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx(),
    );
    expect(result).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// Fail-open in hook
// ---------------------------------------------------------------------------

describe("tool-guard hook — fail-open", () => {
  it("guard.evaluate throws → returns {}", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const state = createGuardState();
    // Sabotage the guard to throw
    (state as any).guard = {
      evaluate: () => {
        throw new Error("guard boom");
      },
    };

    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );
    expect(result).toEqual({});
    warnSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Block result shape
// ---------------------------------------------------------------------------

describe("tool-guard hook — block result", () => {
  it("returns { block: true, blockReason } on deny", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "forbidden" });
    const state = createGuardState({ policyEngine: engine });

    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    expect(result.block).toBe(true);
    expect(result.blockReason).toBeDefined();
    expect(result.blockReason).toContain("denied");
  });

  it("returns {} on allow", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });

    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx(),
    );

    expect(result).toEqual({});
  });
});
