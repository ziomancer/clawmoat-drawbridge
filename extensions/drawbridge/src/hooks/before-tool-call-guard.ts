/**
 * before_tool_call hook — tool call policy guard.
 * Priority 10 (runs before enricher at 50).
 * Fail-open: errors → allow, log warning.
 */

import type { PluginState } from "../pipeline-factory.js";
import { deriveSessionId } from "../session.js";
import type {
  BeforeToolCallEvent,
  BeforeToolCallContext,
  BeforeToolCallResult,
} from "../types/openclaw.js";

const PASS: BeforeToolCallResult = Object.freeze({});

export function handleBeforeToolCallGuard(
  state: PluginState,
  event: BeforeToolCallEvent,
  ctx: BeforeToolCallContext,
): BeforeToolCallResult {
  try {
    if (!state.config.toolGuardEnabled) return PASS;
    if (!state.guard) return PASS;

    const sessionId = deriveSessionId(ctx);

    const result = state.guard.evaluate({
      toolName: event.toolName,
      params: event.params,
      sessionId,
      toolCallId: event.toolCallId,
      agentId: ctx.agentId,
    });

    state.inbound.emitToolPolicy({
      sessionId,
      block: result.block,
      toolName: result.audit.toolName,
      paramsHash: result.audit.paramsHash,
      policyDecision: result.audit.policyDecision,
      policyReason: result.audit.policyReason,
      policySeverity: result.audit.policySeverity,
      escalationApplied: result.audit.escalationApplied,
      sessionTier: result.audit.sessionTier,
      paramScanUnsafe: result.audit.paramScanUnsafe,
      paramScanFindingCount: result.audit.paramScanFindingCount,
      agentId: ctx.agentId,
      toolCallId: event.toolCallId,
    });

    if (result.block && isWriteTool(result.audit.toolName)) {
      state.inbound.emitWriteFailed({
        sessionId,
        toolName: result.audit.toolName,
        cause: "policy_block",
        errorCategory: "policy",
        errorSummary: result.blockReason ?? "blocked by guard",
        agentId: ctx.agentId,
        toolCallId: event.toolCallId,
      });
    }

    if (result.block) {
      return { block: true, blockReason: result.blockReason };
    }

    return PASS;
  } catch (err) {
    console.warn(
      "[drawbridge:guard] Fail-open in before_tool_call:",
      (err as Error).message ?? err,
    );
    return PASS;
  }
}

function isWriteTool(normalizedName: string): boolean {
  return normalizedName === "write";
}
