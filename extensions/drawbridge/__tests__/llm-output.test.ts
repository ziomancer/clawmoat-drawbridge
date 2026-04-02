import { describe, it, expect, vi } from "vitest";
import { handleLlmOutput } from "../src/hooks/llm-output.js";
import { createTestState, makeHookCtx, makeLlmOutputEvent } from "./helpers.js";

describe("llm_output hook", () => {
  it("emits audit event with correct shape", () => {
    const state = createTestState();
    const emitSpy = vi.spyOn(state.auditSink, "emit");

    handleLlmOutput(state, makeLlmOutputEvent(), makeHookCtx());

    expect(emitSpy).toHaveBeenCalledOnce();
    const event = emitSpy.mock.calls[0]![0] as Record<string, unknown>;
    expect(event.event).toBe("raw_output_captured");
    expect(typeof event.sha256).toBe("string");
    expect(typeof event.contentLength).toBe("number");
    expect(typeof event.content).toBe("string");
  });

  it("truncates long content to 500 chars", () => {
    const state = createTestState();
    const emitSpy = vi.spyOn(state.auditSink, "emit");

    const longText = "x".repeat(1000);
    handleLlmOutput(state, makeLlmOutputEvent({ assistantTexts: [longText] }), makeHookCtx());

    const event = emitSpy.mock.calls[0]![0] as Record<string, unknown>;
    expect((event.content as string).length).toBeLessThanOrEqual(504); // 500 + "..."
    expect((event.contentLength as number)).toBe(1000);
  });

  it("skips empty assistant texts", () => {
    const state = createTestState();
    const emitSpy = vi.spyOn(state.auditSink, "emit");

    handleLlmOutput(state, makeLlmOutputEvent({ assistantTexts: [] }), makeHookCtx());
    expect(emitSpy).not.toHaveBeenCalled();
  });

  it("doesn't throw on malformed input", () => {
    const state = createTestState();
    expect(() => {
      handleLlmOutput(state, {} as any, makeHookCtx());
    }).not.toThrow();
  });

  it("fail-open when audit sink throws", () => {
    const state = createTestState();
    vi.spyOn(state.auditSink, "emit").mockImplementation(() => { throw new Error("sink error"); });

    expect(() => {
      handleLlmOutput(state, makeLlmOutputEvent(), makeHookCtx());
    }).not.toThrow();
  });
});
