import { describe, it, expect, vi } from "vitest";
import { handleMessageReceived } from "../src/hooks/message-received.js";
import { handleBeforeDispatch } from "../src/hooks/before-dispatch.js";
import { handleMessageSending } from "../src/hooks/message-sending.js";
import { handleLlmOutput } from "../src/hooks/llm-output.js";
import { handleGatewayStop } from "../src/hooks/gateway-stop.js";
import { createTestState, makeHookCtx, makeDispatchCtx, makeReceivedEvent, makeDispatchEvent, makeSendingEvent, makeLlmOutputEvent } from "./helpers.js";
import type { PluginState } from "../src/pipeline-factory.js";

function createBrokenState(): PluginState {
  const state = createTestState();
  // Replace inbound pipeline with a throwing mock
  (state as any).inbound = {
    inspect: () => { throw new Error("engine exploded"); },
  };
  (state as any).outbound = {
    inspect: () => { throw new Error("engine exploded"); },
  };
  return state;
}

describe("Fail-open guarantees", () => {
  it("message_received: engine throw doesn't propagate", () => {
    const state = createBrokenState();
    expect(() => {
      handleMessageReceived(state, makeReceivedEvent({ content: "test" }), makeHookCtx());
    }).not.toThrow();
  });

  it("before_dispatch: engine throw returns { handled: false }", () => {
    const state = createBrokenState();
    const result = handleBeforeDispatch(
      state,
      makeDispatchEvent({ content: "test" }),
      makeDispatchCtx(),
    );
    expect(result.handled).toBe(false);
  });

  it("message_sending: engine throw returns {}", () => {
    const state = createBrokenState();
    const result = handleMessageSending(
      state,
      makeSendingEvent({ content: "test" }),
      makeHookCtx(),
    );
    expect(result).toEqual({});
  });

  it("llm_output: audit sink throw doesn't propagate", () => {
    const state = createTestState();
    vi.spyOn(state.auditSink, "emit").mockImplementation(() => { throw new Error("sink boom"); });
    expect(() => {
      handleLlmOutput(state, makeLlmOutputEvent(), makeHookCtx());
    }).not.toThrow();
  });

  it("gateway_stop: teardown throw doesn't propagate", () => {
    const state = createTestState();
    state.teardown = () => { throw new Error("teardown boom"); };
    expect(() => handleGatewayStop(state)).not.toThrow();
  });

  it("tracker throw in before_dispatch returns { handled: false }", () => {
    const state = createTestState();
    vi.spyOn(state.tracker, "getState").mockImplementation(() => { throw new Error("tracker boom"); });
    // This will throw inside before_dispatch when checking termination
    const result = handleBeforeDispatch(
      state,
      makeDispatchEvent(),
      makeDispatchCtx(),
    );
    expect(result.handled).toBe(false);
  });

  it("tracker throw in message_sending returns {}", () => {
    const state = createTestState();
    vi.spyOn(state.tracker, "getState").mockImplementation(() => { throw new Error("tracker boom"); });
    const result = handleMessageSending(
      state,
      makeSendingEvent(),
      makeHookCtx(),
    );
    expect(result).toEqual({});
  });
});
