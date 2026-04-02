/**
 * message_sending hook — scan outbound content, redact or cancel.
 * Returns { content } to redact, { cancel: true } to drop, {} to pass.
 * Fail-open.
 */

import type { PluginState } from "../pipeline-factory.js";
import { deriveSessionId, isExempt } from "../session.js";
import type { MessageSendingEvent, HookContext, MessageSendingResult } from "../types/openclaw.js";

const PASS: MessageSendingResult = Object.freeze({});

export function handleMessageSending(
  state: PluginState,
  event: MessageSendingEvent,
  ctx: HookContext,
): MessageSendingResult {
  try {
    if (isExempt(ctx, state.config, "outbound")) return PASS;
    if (state.config.direction === "inbound") return PASS;

    const sessionId = deriveSessionId(ctx);

    // Pre-check: session already terminated (from inbound or prior outbound)
    const sessionState = state.tracker.getState(sessionId);
    if (sessionState?.terminated) {
      return { cancel: true };
    }

    const result = state.outbound.inspect({
      content: event.content,
      source: "assistant",
      sessionId,
    });

    if (result.terminated) {
      return { cancel: true };
    }

    if (!result.safe) {
      // Redact if possible, otherwise cancel
      if (state.config.redactOutbound && result.sanitizedContent) {
        return { content: result.sanitizedContent };
      }
      return { cancel: true };
    }

    return PASS;
  } catch (err) {
    const msg = String((err as Error).message ?? err).slice(0, 200);
    console.warn("[drawbridge:message_sending] Fail-open:", msg);
    return PASS;
  }
}
