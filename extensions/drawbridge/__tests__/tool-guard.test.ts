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
    const result = handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );
    expect(result).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// Exemptions — guard handles them, not the hook
// ---------------------------------------------------------------------------

describe("tool-guard hook — exemptions", () => {
  it("exempt tool passes through and guard handles exemption", () => {
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
// Audit routing — events go through pipeline's AuditEmitter (verbosity gated)
// ---------------------------------------------------------------------------

describe("tool-guard hook — audit routing", () => {
  it("block calls inbound.emitToolPolicy with block=true", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "dangerous" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitToolPolicy");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0]![0]).toMatchObject({
      block: true,
      policyDecision: "deny",
      policyReason: "dangerous",
    });
  });

  it("allow calls inbound.emitToolPolicy with block=false", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitToolPolicy");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx(),
    );

    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0]![0]).toMatchObject({
      block: false,
      policyDecision: "allow",
    });
  });

  it("audit event includes sessionId, toolName, paramsHash", () => {
    const engine = mockPolicyEngine({ decision: "deny" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitToolPolicy");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read", params: { path: "/etc" } }),
      makeBeforeToolCallCtx({ sessionKey: "test-session" }),
    );

    const params = spy.mock.calls[0]![0];
    expect(params.sessionId).toBe("test-session");
    expect(params.toolName).toBe("read");
    expect(params.paramsHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("tool_policy_block passes verbosity gate at standard", () => {
    const engine = mockPolicyEngine({ decision: "deny" });
    const events: unknown[] = [];
    const config = resolveConfig({ toolGuardEnabled: true });
    const mockEngine = createMockEngine();
    const tracker = new FrequencyTracker({
      enabled: true, halfLifeMs: 100, rollingWindowMs: 60_000,
      rollingThreshold: 10,
      weights: { "drawbridge.prompt_injection.*": 20 },
      thresholds: { tier1: 15, tier2: 40, tier3: 80 },
      memory: { maxSessions: 100, sessionTtlMs: 300_000, maxNewSessionsPerMinute: 100 },
    });
    const inbound = new DrawbridgePipeline({
      profile: config.inboundProfile, engine: mockEngine, tracker,
      scanner: { blockThreshold: config.blockThreshold, direction: "inbound" },
      audit: { verbosity: "standard", onEvent: (e) => events.push(e) },
    });
    const guard = new ToolCallGuard({
      pipeline: inbound, tracker, engine,
      escalateWarnings: true, scanParams: true,
    });
    const state: PluginState = {
      inbound, outbound: inbound, tracker, guard, config,
      cache: new Map(), auditSink: new LogSink(), teardown: () => {},
    };

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    const blockEvents = events.filter((e: any) => e.event === "tool_policy_block");
    expect(blockEvents).toHaveLength(1);
  });

  it("tool_policy_allow dropped at standard verbosity (min: high)", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const events: unknown[] = [];
    const config = resolveConfig({ toolGuardEnabled: true });
    const mockEng = createMockEngine();
    const tracker = new FrequencyTracker({
      enabled: true, halfLifeMs: 100, rollingWindowMs: 60_000,
      rollingThreshold: 10,
      weights: { "drawbridge.prompt_injection.*": 20 },
      thresholds: { tier1: 15, tier2: 40, tier3: 80 },
      memory: { maxSessions: 100, sessionTtlMs: 300_000, maxNewSessionsPerMinute: 100 },
    });
    const inbound = new DrawbridgePipeline({
      profile: config.inboundProfile, engine: mockEng, tracker,
      scanner: { blockThreshold: config.blockThreshold, direction: "inbound" },
      audit: { verbosity: "standard", onEvent: (e) => events.push(e) },
    });
    const guard = new ToolCallGuard({
      pipeline: inbound, tracker, engine,
      escalateWarnings: true, scanParams: true,
    });
    const state: PluginState = {
      inbound, outbound: inbound, tracker, guard, config,
      cache: new Map(), auditSink: new LogSink(), teardown: () => {},
    };

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "read" }),
      makeBeforeToolCallCtx(),
    );

    const allowEvents = events.filter((e: any) => e.event === "tool_policy_allow");
    expect(allowEvents).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Alert routing — events reach AlertManager through pipeline
// ---------------------------------------------------------------------------

describe("tool-guard hook — alert routing", () => {
  it("block event reaches AlertManager via pipeline", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "bad tool" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitToolPolicy");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0]![0].block).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// write_failed emission
// ---------------------------------------------------------------------------

describe("tool-guard hook — write_failed emission", () => {
  it("blocked write tool calls inbound.emitWriteFailed", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "bad write" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitWriteFailed");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "file_write" }),
      makeBeforeToolCallCtx(),
    );

    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0]![0]).toMatchObject({
      cause: "policy_block",
      toolName: "write",
      errorCategory: "policy",
    });
  });

  it("blocked non-write tool does NOT call emitWriteFailed", () => {
    const engine = mockPolicyEngine({ decision: "deny", reason: "blocked" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitWriteFailed");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "exec" }),
      makeBeforeToolCallCtx(),
    );

    expect(spy).not.toHaveBeenCalled();
  });

  it("allowed write tool does NOT call emitWriteFailed", () => {
    const engine = mockPolicyEngine({ decision: "allow" });
    const state = createGuardState({ policyEngine: engine });
    const spy = vi.spyOn(state.inbound, "emitWriteFailed");

    handleBeforeToolCallGuard(
      state,
      makeBeforeToolCallEvent({ toolName: "file_write" }),
      makeBeforeToolCallCtx(),
    );

    expect(spy).not.toHaveBeenCalled();
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
