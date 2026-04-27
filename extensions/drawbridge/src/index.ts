/**
 * Drawbridge OpenClaw plugin entry point.
 *
 * Hook-only plugin — scans inbound/outbound content for prompt injection,
 * PII, and frequency-based escalation. Invisible to the LLM.
 *
 * Async init with promise caching: first hook call pays the cost,
 * subsequent calls get the cached result. Init failure resolves to null
 * (sentinel for no-op — all hooks pass through).
 */

import type { DrawbridgePluginConfig } from "./config.js";
import { resolveConfig } from "./config.js";
import { initializePluginState } from "./pipeline-factory.js";
import type { PluginState } from "./pipeline-factory.js";
import { handleMessageReceived } from "./hooks/message-received.js";
import { handleBeforeDispatch } from "./hooks/before-dispatch.js";
import { handleMessageSending } from "./hooks/message-sending.js";
import { handleLlmOutput } from "./hooks/llm-output.js";
import { handleGatewayStop } from "./hooks/gateway-stop.js";
import { handleBeforeToolCallGuard } from "./hooks/before-tool-call-guard.js";
import { createToolErrorEnricher } from "./hooks/tool-error-enricher.js";
import type { VigilHarborIngestFn, AlertNotifyFn } from "./audit-sink.js";

export type { DrawbridgePluginConfig } from "./config.js";
export type { PluginState } from "./pipeline-factory.js";

export interface CreatePluginOptions {
  config?: DrawbridgePluginConfig;
  vhIngest?: VigilHarborIngestFn;
  alertNotify?: AlertNotifyFn;
}

/**
 * Create the Drawbridge plugin definition.
 * Returns an object compatible with OpenClaw's `definePluginEntry` shape.
 *
 * When `definePluginEntry` is available (installed as OpenClaw plugin),
 * use it directly. When running standalone (tests, external consumers),
 * use `createDrawbridgePlugin()` for the raw hook handlers.
 */
export function createDrawbridgePlugin(opts?: CreatePluginOptions) {
  const config = resolveConfig(opts?.config);

  // Async init — cached promise, resolved once
  let stateP: Promise<PluginState | null> | null = null;

  function getState(): Promise<PluginState | null> {
    if (!stateP) {
      stateP = initializePluginState({
        config,
        vhIngest: opts?.vhIngest,
        alertNotify: opts?.alertNotify,
      }).catch((err) => {
        console.warn(`[drawbridge] Plugin disabled: ${(err as Error).message}`);
        return null;
      });
    }
    return stateP;
  }

  return {
    id: "drawbridge" as const,
    name: "Drawbridge",
    description: "Session-aware content sanitization via ClawMoat + Drawbridge",

    register(api: {
      on: (
        hookName: string,
        handler: (...args: unknown[]) => unknown,
        opts?: { priority?: number },
      ) => void;
    }) {
      api.on(
        "message_received",
        async (event: unknown, ctx: unknown) => {
          const state = await getState();
          if (!state) return;
          handleMessageReceived(
            state,
            event as Parameters<typeof handleMessageReceived>[1],
            ctx as Parameters<typeof handleMessageReceived>[2],
          );
        },
      );

      api.on(
        "before_dispatch",
        async (event: unknown, ctx: unknown) => {
          const state = await getState();
          if (!state) return { handled: false };
          return handleBeforeDispatch(
            state,
            event as Parameters<typeof handleBeforeDispatch>[1],
            ctx as Parameters<typeof handleBeforeDispatch>[2],
          );
        },
      );

      api.on(
        "message_sending",
        async (event: unknown, ctx: unknown) => {
          const state = await getState();
          if (!state) return {};
          return handleMessageSending(
            state,
            event as Parameters<typeof handleMessageSending>[1],
            ctx as Parameters<typeof handleMessageSending>[2],
          );
        },
      );

      api.on(
        "llm_output",
        async (event: unknown, ctx: unknown) => {
          const state = await getState();
          if (!state) return;
          handleLlmOutput(
            state,
            event as Parameters<typeof handleLlmOutput>[1],
            ctx as Parameters<typeof handleLlmOutput>[2],
          );
        },
      );

      api.on(
        "gateway_stop",
        async () => {
          // Only tear down if init already happened — never trigger lazy init during shutdown
          if (!stateP) return;
          const state = await stateP;
          if (!state) return;
          handleGatewayStop(state);
        },
      );

      // Tool call policy guard — security gating at priority 10 (before enricher)
      api.on(
        "before_tool_call",
        async (event: unknown, ctx: unknown) => {
          const state = await getState();
          if (!state) return {};
          return handleBeforeToolCallGuard(
            state,
            event as import("./types/openclaw.js").BeforeToolCallEvent,
            ctx as import("./types/openclaw.js").BeforeToolCallContext,
          );
        },
        { priority: 10 },
      );

      // Tool error enricher — independent of PluginState (no async init needed)
      const enricher = createToolErrorEnricher();
      enricher.registerHooks(api);
    },
  };
}

// Default export for OpenClaw plugin loader
export default createDrawbridgePlugin();
