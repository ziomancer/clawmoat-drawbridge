import { describe, it, expect, vi } from "vitest";
import { LogSink, VigilHarborSink, CompositeSink, createAuditSink } from "../src/audit-sink.js";
import type { TypedAuditEvent, AlertPayload } from "@vigil-harbor/clawmoat-drawbridge";

function makeAuditEvent(): TypedAuditEvent {
  return {
    event: "scan_pass",
    timestamp: new Date().toISOString(),
    sessionId: "s1",
    safe: true,
    findingCount: 0,
    blockingFindingCount: 0,
    ruleIds: [],
  } as TypedAuditEvent;
}

function makeAlert(severity: "info" | "high" | "critical" = "high"): AlertPayload {
  return {
    severity,
    ruleId: "test-rule",
    summary: "test reason",
    sessionId: "s1",
    timestamp: new Date().toISOString(),
  } as AlertPayload;
}

describe("Audit routing", () => {
  describe("LogSink", () => {
    it("emits to console.log", () => {
      const sink = new LogSink();
      const spy = vi.spyOn(console, "log").mockImplementation(() => {});
      sink.emit(makeAuditEvent());
      expect(spy).toHaveBeenCalledOnce();
      spy.mockRestore();
    });

    it("alerts to console.warn for high severity", () => {
      const sink = new LogSink();
      const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
      sink.alert(makeAlert("high"));
      expect(spy).toHaveBeenCalledOnce();
      spy.mockRestore();
    });

    it("alerts to console.error for critical severity", () => {
      const sink = new LogSink();
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      sink.alert(makeAlert("critical"));
      expect(spy).toHaveBeenCalledOnce();
      spy.mockRestore();
    });
  });

  describe("VigilHarborSink", () => {
    it("calls ingest with correct params", () => {
      const ingest = vi.fn();
      const sink = new VigilHarborSink(ingest);
      sink.emit(makeAuditEvent());
      expect(ingest).toHaveBeenCalledWith("drawbridge_audit", "security", expect.any(Array), expect.any(String));
    });

    it("silently drops on ingest failure", () => {
      const ingest = vi.fn(() => { throw new Error("network error"); });
      const sink = new VigilHarborSink(ingest);
      expect(() => sink.emit(makeAuditEvent())).not.toThrow();
    });

    it("calls notify for high/critical alerts", () => {
      const ingest = vi.fn();
      const notify = vi.fn();
      const sink = new VigilHarborSink(ingest, notify);
      sink.alert(makeAlert("high"));
      expect(notify).toHaveBeenCalledOnce();
    });

    it("does not notify for info alerts", () => {
      const ingest = vi.fn();
      const notify = vi.fn();
      const sink = new VigilHarborSink(ingest, notify);
      sink.alert(makeAlert("info"));
      expect(notify).not.toHaveBeenCalled();
    });

    it("silently drops on notify failure", () => {
      const ingest = vi.fn();
      const notify = vi.fn(() => { throw new Error("notify error"); });
      const sink = new VigilHarborSink(ingest, notify);
      expect(() => sink.alert(makeAlert("critical"))).not.toThrow();
    });
  });

  describe("CompositeSink", () => {
    it("routes to all sinks", () => {
      const ingest = vi.fn();
      const log = new LogSink();
      const vh = new VigilHarborSink(ingest);
      const composite = new CompositeSink(log, vh);
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      composite.emit(makeAuditEvent());
      expect(logSpy).toHaveBeenCalled();
      expect(ingest).toHaveBeenCalled();
      logSpy.mockRestore();
    });

    it("one sink failure doesn't block the other", () => {
      const ingest = vi.fn(() => { throw new Error("boom"); });
      const log = new LogSink();
      const vh = new VigilHarborSink(ingest);
      const composite = new CompositeSink(vh, log); // VH first (will throw)
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      expect(() => composite.emit(makeAuditEvent())).not.toThrow();
      expect(logSpy).toHaveBeenCalled(); // Log sink still ran
      logSpy.mockRestore();
    });
  });

  describe("createAuditSink factory", () => {
    it("returns LogSink for 'log' mode", () => {
      const sink = createAuditSink("log");
      expect(sink).toBeInstanceOf(LogSink);
    });

    it("returns VigilHarborSink for 'vigil-harbor' mode", () => {
      const sink = createAuditSink("vigil-harbor", vi.fn());
      expect(sink).toBeInstanceOf(VigilHarborSink);
    });

    it("returns CompositeSink for 'both' mode", () => {
      const sink = createAuditSink("both", vi.fn());
      expect(sink).toBeInstanceOf(CompositeSink);
    });

    it("falls back to LogSink when VH ingest not provided", () => {
      const sink = createAuditSink("vigil-harbor");
      expect(sink).toBeInstanceOf(LogSink);
    });
  });
});
