/**
 * before_dispatch hook — gate inbound content based on scan results.
 * Returns { handled: true, text } to block, { handled: false } to pass.
 * Fail-open.
 */

import type { PluginState } from "../pipeline-factory.js";
import { cacheKey, cacheGet } from "../pipeline-factory.js";
import { deriveSessionId, isExempt } from "../session.js";
import type { BeforeDispatchEvent, BeforeDispatchContext, BeforeDispatchResult } from "../types/openclaw.js";

const PASS: BeforeDispatchResult = { handled: false };

export function handleBeforeDispatch(
  state: PluginState,
  event: BeforeDispatchEvent,
  ctx: BeforeDispatchContext,
): BeforeDispatchResult {
  try {
    if (isExempt(ctx, state.config, "inbound")) return PASS;
    if (state.config.direction === "outbound") return PASS;

    const sessionId = deriveSessionId(ctx, event.content, event.timestamp);

    // Check for terminated session first
    const sessionState = state.tracker.getState(sessionId);
    if (sessionState?.terminated) {
      return { handled: true, text: state.config.terminateMessage };
    }

    // Read from cache (populated by message_received) or re-scan on miss
    const key = cacheKey(event.content, sessionId);
    let result = cacheGet(state.cache, key);

    if (!result) {
      result = state.inbound.inspect({
        content: event.content,
        source: "user",
        sessionId,
      });
    }

    // Tier3 reached during this scan
    if (result.terminated) {
      return { handled: true, text: state.config.terminateMessage };
    }

    // Content blocked
    if (!result.safe) {
      return { handled: true, text: state.config.blockMessage };
    }

    // Tier2 escalation
    if (result.escalationTier === "tier2" && state.config.tier2Action === "block") {
      return { handled: true, text: state.config.blockMessage };
    }

    return PASS;
  } catch {
    // Fail-open
    return PASS;
  }
}
