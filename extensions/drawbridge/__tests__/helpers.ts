/**
 * Shared test helpers — mock ClawMoat engine, plugin state factory, hook context builders.
 */

import {
  DrawbridgePipeline,
  FrequencyTracker,
} from "@vigil-harbor/clawmoat-drawbridge";
import type { PipelineResult } from "@vigil-harbor/clawmoat-drawbridge";
import type { ResolvedConfig } from "../src/config.js";
import { resolveConfig } from "../src/config.js";
import type { PluginState } from "../src/pipeline-factory.js";
import { LogSink } from "../src/audit-sink.js";
import type {
  HookContext,
  BeforeDispatchContext,
  BeforeDispatchEvent,
  MessageReceivedEvent,
  MessageSendingEvent,
  LlmOutputEvent,
  ToolResultPersistEvent,
  ToolResultPersistContext,
  AfterToolCallEvent,
  AfterToolCallContext,
  BeforeToolCallEvent,
  BeforeToolCallContext,
} from "../src/types/openclaw.js";

// ---------------------------------------------------------------------------
// Mock ClawMoat engine
// ---------------------------------------------------------------------------

interface ClawMoatFinding {
  type: string;
  subtype: string;
  severity: string;
  matched: string;
  position: number;
}

interface ClawMoatScanResult {
  safe: boolean;
  findings: ClawMoatFinding[];
  inbound: { findings: ClawMoatFinding[]; safe: boolean; severity: string; action: string };
  outbound: { findings: ClawMoatFinding[]; safe: boolean; severity: string; action: string };
}

export function createMockEngine(scanFn?: (text: string) => ClawMoatScanResult) {
  const cleanResult: ClawMoatScanResult = {
    safe: true,
    findings: [],
    inbound: { findings: [], safe: true, severity: "none", action: "allow" },
    outbound: { findings: [], safe: true, severity: "none", action: "allow" },
  };
  return { scan: scanFn ?? (() => cleanResult) };
}

export function injectionFinding(overrides?: Partial<ClawMoatFinding>): ClawMoatFinding {
  return {
    type: "prompt_injection",
    subtype: "instruction_override",
    severity: "critical",
    matched: "ignore previous instructions",
    position: 0,
    ...overrides,
  };
}

export function blockResult(findings?: ClawMoatFinding[]): ClawMoatScanResult {
  const f = findings ?? [injectionFinding()];
  return {
    safe: false,
    findings: f,
    inbound: { findings: f, safe: false, severity: f[0]!.severity, action: "block" },
    outbound: { findings: f, safe: false, severity: f[0]!.severity, action: "block" },
  };
}

export function cleanResult(): ClawMoatScanResult {
  return {
    safe: true,
    findings: [],
    inbound: { findings: [], safe: true, severity: "none", action: "allow" },
    outbound: { findings: [], safe: true, severity: "none", action: "allow" },
  };
}

// ---------------------------------------------------------------------------
// Plugin state factory (synchronous — bypasses async ClawMoat import)
// ---------------------------------------------------------------------------

export function createTestState(
  configOverrides?: Partial<Parameters<typeof resolveConfig>[0]>,
  engineScanFn?: (text: string) => ClawMoatScanResult,
): PluginState {
  const config = resolveConfig(configOverrides);
  const engine = createMockEngine(engineScanFn);

  const tracker = new FrequencyTracker({
    enabled: true,
    halfLifeMs: 100,
    rollingWindowMs: 60_000,
    rollingThreshold: 10,
    weights: {
      "drawbridge.prompt_injection.*": 20,
      "drawbridge.credential.*": 10,
      "drawbridge.structural.*": 5,
    },
    thresholds: { tier1: 15, tier2: 40, tier3: 80 },
    memory: {
      maxSessions: 100,
      sessionTtlMs: 300_000,
      maxNewSessionsPerMinute: 100,
    },
  });

  const inbound = new DrawbridgePipeline({
    profile: config.inboundProfile,
    engine,
    tracker,
    scanner: { blockThreshold: config.blockThreshold, direction: "inbound" },
    sanitize: { hashRedactions: config.hashRedactions },
  });

  const outbound = new DrawbridgePipeline({
    profile: config.outboundProfile,
    engine,
    tracker,
    scanner: { blockThreshold: config.blockThreshold, direction: "outbound" },
    sanitize: {
      enabled: config.redactOutbound,
      hashRedactions: config.hashRedactions,
    },
  });

  return {
    inbound,
    outbound,
    tracker,
    config,
    cache: new Map(),
    auditSink: new LogSink(),
    teardown: () => {},
  };
}

// ---------------------------------------------------------------------------
// Context/event builders
// ---------------------------------------------------------------------------

export function makeHookCtx(overrides?: Partial<HookContext>): HookContext {
  return {
    channelId: "test-channel",
    accountId: "test-account",
    conversationId: "test-conv",
    sessionKey: "test-channel:test-conv",
    senderId: "user-123",
    ...overrides,
  };
}

export function makeDispatchCtx(overrides?: Partial<BeforeDispatchContext>): BeforeDispatchContext {
  return {
    channelId: "test-channel",
    accountId: "test-account",
    conversationId: "test-conv",
    sessionKey: "test-channel:test-conv",
    senderId: "user-123",
    ...overrides,
  };
}

export function makeReceivedEvent(overrides?: Partial<MessageReceivedEvent>): MessageReceivedEvent {
  return {
    from: "user-123",
    content: "hello world",
    timestamp: Date.now(),
    ...overrides,
  };
}

export function makeDispatchEvent(overrides?: Partial<BeforeDispatchEvent>): BeforeDispatchEvent {
  return {
    content: "hello world",
    channel: "discord",
    sessionKey: "test-channel:test-conv",
    senderId: "user-123",
    isGroup: false,
    timestamp: Date.now(),
    ...overrides,
  };
}

export function makeSendingEvent(overrides?: Partial<MessageSendingEvent>): MessageSendingEvent {
  return {
    to: "user-123",
    content: "Here is my response.",
    ...overrides,
  };
}

export function makeLlmOutputEvent(overrides?: Partial<LlmOutputEvent>): LlmOutputEvent {
  return {
    runId: "run-1",
    sessionId: "test-session",
    provider: "lmstudio",
    model: "qwen/qwen3.5-35b-a3b",
    assistantTexts: ["Here is my response."],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tool error enricher event/context builders
// ---------------------------------------------------------------------------

export function makeToolResultPersistEvent(
  overrides?: Partial<ToolResultPersistEvent> & { message?: Record<string, unknown> },
): ToolResultPersistEvent {
  return {
    message: {
      isError: true,
      content: [{ type: "text", text: "Request timeout" }],
    },
    isSynthetic: false,
    ...overrides,
  };
}

export function makeToolResultPersistCtx(
  overrides?: Partial<ToolResultPersistContext>,
): ToolResultPersistContext {
  return {
    sessionKey: "test-session-key",
    toolName: "memory_search",
    ...overrides,
  };
}

export function makeAfterToolCallEvent(
  overrides?: Partial<AfterToolCallEvent>,
): AfterToolCallEvent {
  return {
    toolName: "memory_search",
    params: { query: "test query", namespace: "personal" },
    error: "Request timeout",
    ...overrides,
  };
}

export function makeAfterToolCallCtx(
  overrides?: Partial<AfterToolCallContext>,
): AfterToolCallContext {
  return {
    sessionKey: "test-session-key",
    ...overrides,
  };
}

export function makeBeforeToolCallEvent(
  overrides?: Partial<BeforeToolCallEvent>,
): BeforeToolCallEvent {
  return {
    toolName: "memory_search",
    ...overrides,
  };
}

export function makeBeforeToolCallCtx(
  overrides?: Partial<BeforeToolCallContext>,
): BeforeToolCallContext {
  return {
    sessionKey: "test-session-key",
    ...overrides,
  };
}
