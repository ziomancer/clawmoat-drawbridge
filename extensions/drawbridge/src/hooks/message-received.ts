/**
 * message_received hook — scan inbound content, cache result.
 * Observational only (void return). Fail-open.
 */

import type { PluginState } from "../pipeline-factory.js";
import { cacheKey, cacheSet } from "../pipeline-factory.js";
import { deriveSessionId, isExempt } from "../session.js";
import type { MessageReceivedEvent, HookContext } from "../types/openclaw.js";

export function handleMessageReceived(
  state: PluginState,
  event: MessageReceivedEvent,
  ctx: HookContext,
): void {
  try {
    if (isExempt(ctx, state.config, "inbound")) return;

    const sessionId = deriveSessionId(ctx, event.content, event.timestamp);
    const result = state.inbound.inspect({
      content: event.content,
      source: "user",
      sessionId,
      messageId: event.metadata?.messageId as string | undefined,
    });

    const key = cacheKey(event.content, sessionId);
    cacheSet(state.cache, key, result);
  } catch (err) {
    console.warn("[drawbridge:message_received] Fail-open:", (err as Error).message ?? err);
  }
}
