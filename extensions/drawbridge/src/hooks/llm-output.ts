/**
 * llm_output hook — forensic breadcrumb only.
 * Emits structured audit event with truncated content, no pipeline scan.
 * Fail-open.
 *
 * Intentionally skips exemption check: forensic capture is universal
 * regardless of channel/sender exemptions. Exemptions control scanning
 * and blocking, not audit trail completeness.
 */

import { sha256 } from "@vigil-harbor/clawmoat-drawbridge";
import type { TypedAuditEvent } from "@vigil-harbor/clawmoat-drawbridge";
import type { PluginState } from "../pipeline-factory.js";
import type { LlmOutputEvent, HookContext } from "../types/openclaw.js";

const MAX_CONTENT_LENGTH = 500;

export function handleLlmOutput(
  state: PluginState,
  event: LlmOutputEvent,
  ctx: HookContext,
): void {
  try {
    const fullText = event.assistantTexts.join("\n");
    if (!fullText) return;

    const truncated = fullText.length > MAX_CONTENT_LENGTH
      ? fullText.slice(0, MAX_CONTENT_LENGTH - 3) + "..."
      : fullText;

    state.auditSink.emit({
      event: "raw_output_captured",
      timestamp: new Date().toISOString(),
      sessionId: event.sessionId,
      content: truncated,
      contentLength: fullText.length,
      sha256: sha256(fullText),
    } as TypedAuditEvent);
  } catch {
    // Fail-open
  }
}
