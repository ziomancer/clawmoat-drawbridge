/**
 * Session key derivation and exemption checks.
 */

import { randomUUID } from "node:crypto";
import { sha256 } from "@vigil-harbor/clawmoat-drawbridge";
import type { HookContext, BeforeDispatchContext } from "./types/openclaw.js";
import type { ResolvedConfig } from "./config.js";

/**
 * Derive a stable session ID from hook context.
 * Falls back to an ephemeral key for unidentified senders —
 * disables cross-turn frequency tracking (correct: can't track
 * escalation without a stable identity).
 */
export function deriveSessionId(
  ctx: HookContext | BeforeDispatchContext,
  content?: string,
  timestamp?: number,
): string {
  const sessionKey = "sessionKey" in ctx ? ctx.sessionKey : undefined;
  if (sessionKey) return sessionKey;

  const channelId = ctx.channelId ?? "unknown";
  const identity = ctx.conversationId ?? ctx.accountId;
  if (identity) return `${channelId}:${identity}`;

  // Ephemeral fallback — no cross-turn tracking, high-entropy to avoid collisions
  console.warn("[drawbridge] Ephemeral session ID — no stable identity available for frequency tracking");
  const ephemeralSeed = `${content ?? ""}${timestamp ?? Date.now()}${randomUUID()}`;
  return `${channelId}:ephemeral:${sha256(ephemeralSeed)}`;
}

/**
 * Check if a message should bypass scanning.
 * Inbound: checks sender + channel.
 * Outbound: checks channel only (sender is always the bot).
 */
export function isExempt(
  ctx: HookContext | BeforeDispatchContext,
  config: ResolvedConfig,
  direction: "inbound" | "outbound",
): boolean {
  const channelId = ctx.channelId;
  if (channelId && config.exemptChannels.includes(channelId)) return true;

  if (direction === "inbound") {
    const senderId = ctx.senderId;
    if (senderId && config.exemptSenders.includes(senderId)) return true;
  }

  return false;
}
