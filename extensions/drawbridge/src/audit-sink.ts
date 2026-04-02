/**
 * Audit event routing — log, Vigil Harbor MCP, or both.
 * Alert severity routing: info→log, warning→log+notify, critical→log+notify+terminate.
 */

import type { TypedAuditEvent } from "@vigil-harbor/clawmoat-drawbridge";
import type { AlertPayload } from "@vigil-harbor/clawmoat-drawbridge";

export interface AuditSink {
  emit(event: TypedAuditEvent): void;
  alert(payload: AlertPayload): void;
}

/** Pluggable callback for Vigil Harbor MCP ingestion. */
export type VigilHarborIngestFn = (
  type: string,
  namespace: string,
  tags: string[],
  text: string,
) => void;

/** Pluggable callback for alert notifications (e.g., Discord admin channel). */
export type AlertNotifyFn = (severity: string, message: string) => void;

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

export class LogSink implements AuditSink {
  emit(event: TypedAuditEvent): void {
    console.log(`[drawbridge:audit] ${event.event}`, JSON.stringify(event));
  }

  alert(payload: AlertPayload): void {
    const level = payload.severity === "critical" ? "error" : "warn";
    console[level](`[drawbridge:alert] ${payload.severity}`, JSON.stringify(payload));
  }
}

/** Drain a possibly-async callback result without unhandled rejection. */
function drainAsync(fn: () => void): void {
  try {
    const result: unknown = fn();
    if (result && typeof (result as Promise<unknown>).catch === "function") {
      (result as Promise<unknown>).catch(() => {});
    }
  } catch {
    // Swallowed — audit/alert failures must never propagate
  }
}

export class VigilHarborSink implements AuditSink {
  constructor(
    private readonly ingest: VigilHarborIngestFn,
    private readonly notify?: AlertNotifyFn,
  ) {}

  emit(event: TypedAuditEvent): void {
    drainAsync(() => this.ingest(
      "drawbridge_audit",
      "security",
      ["drawbridge", event.event],
      JSON.stringify(event),
    ));
  }

  alert(payload: AlertPayload): void {
    drainAsync(() => this.ingest(
      "drawbridge_alert",
      "security",
      ["drawbridge", "alert", payload.severity],
      JSON.stringify(payload),
    ));

    if (this.notify && (payload.severity === "high" || payload.severity === "critical")) {
      const notify = this.notify;
      drainAsync(() => notify(payload.severity, `[Drawbridge ${payload.severity}] ${payload.ruleId}: ${payload.summary}`));
    }
  }
}

export class CompositeSink implements AuditSink {
  private readonly sinks: AuditSink[];

  constructor(...sinks: AuditSink[]) {
    this.sinks = sinks;
  }

  emit(event: TypedAuditEvent): void {
    for (const sink of this.sinks) {
      try {
        sink.emit(event);
      } catch {
        // Individual sink failure doesn't block others
      }
    }
  }

  alert(payload: AlertPayload): void {
    for (const sink of this.sinks) {
      try {
        sink.alert(payload);
      } catch {
        // Individual sink failure doesn't block others
      }
    }
  }
}

export function createAuditSink(
  mode: "log" | "vigil-harbor" | "both",
  vhIngest?: VigilHarborIngestFn,
  alertNotify?: AlertNotifyFn,
): AuditSink {
  const logSink = new LogSink();
  if (mode !== "log" && !vhIngest) {
    console.warn(`[drawbridge] auditSink="${mode}" but no vhIngest callback provided — falling back to log-only`);
  }
  if (mode === "log" || !vhIngest) return logSink;

  const vhSink = new VigilHarborSink(vhIngest, alertNotify);
  if (mode === "vigil-harbor") return vhSink;

  return new CompositeSink(logSink, vhSink);
}
