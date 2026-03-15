/**
 * DrawbridgeScanner: ClawMoat integration with threshold filtering,
 * direction-aware scanning, and finding callbacks.
 *
 * v0.1 — the only implemented module. All other pipeline modules are stubs.
 */

import {
  SEVERITY_RANK,
  isSeverity,
  type ClawMoatFinding,
  type ClawMoatScanResult,
  type DrawbridgeScannerConfig,
  type DrawbridgeScanResult,
  type DrawbridgeFinding,
  type Severity,
  type SanitizeConfig,
  type SanitizeResult,
} from "../types/scanner.js";
import { sanitizeContent } from "../sanitize/index.js";
import { safeStringify } from "../lib/safe-stringify.js";

/** Reserved prefixes for Drawbridge internal modules (pre-filter, schema) */
const RESERVED_TYPE_PREFIXES = ["syntactic", "schema"];

/** Normalize a ClawMoat type+subtype into a Drawbridge rule ID. */
export function normalizeRuleId(type: string, subtype: string): string {
  const clean = (s: string) => s.replace(/[^a-zA-Z0-9_-]/g, ".");
  const cleanType = clean(type);
  // Prevent collision with drawbridge.syntactic.* and drawbridge.schema.*
  const safeType = RESERVED_TYPE_PREFIXES.includes(cleanType)
    ? `scanner.${cleanType}`
    : cleanType;
  return `drawbridge.${safeType}.${clean(subtype)}`;
}

/** Resolve the effective severity rank for a ClawMoat finding. */
function effectiveSeverityRank(severity: string): number {
  if (isSeverity(severity)) return SEVERITY_RANK[severity];
  // Unknown severity string — fail-safe: treat as critical
  return SEVERITY_RANK.critical;
}

/** Resolve the effective Severity for a ClawMoat finding. */
function effectiveSeverity(severity: string): Severity {
  return isSeverity(severity) ? severity : "critical";
}

// ---------------------------------------------------------------------------
// ClawMoat engine interface (for constructor injection / mocking)
// ---------------------------------------------------------------------------

interface ClawMoatEngine {
  scan(text: string): ClawMoatScanResult;
}

// ---------------------------------------------------------------------------
// DrawbridgeScanner
// ---------------------------------------------------------------------------

export class DrawbridgeScanner {
  private readonly _engine: ClawMoatEngine;
  private readonly config: Required<Pick<DrawbridgeScannerConfig, "blockThreshold" | "direction">> & {
    onFinding?: (finding: DrawbridgeFinding) => void;
  };

  /**
   * @param config User-facing configuration (threshold, direction, callbacks).
   * @param engine Optional ClawMoat instance for testing. If omitted, instantiates
   *   the real ClawMoat class. Throws if ClawMoat is not installed.
   */
  constructor(config?: DrawbridgeScannerConfig, engine?: ClawMoatEngine) {
    this.config = {
      blockThreshold: config?.blockThreshold ?? "low",
      direction: config?.direction ?? "inbound",
      onFinding: config?.onFinding,
    };

    if (engine) {
      this._engine = engine;
    } else {
      try {
        // Dynamic import at construction — ClawMoat is an optional peer dep.
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { ClawMoat } = require("clawmoat") as { ClawMoat: new () => ClawMoatEngine };
        this._engine = new ClawMoat();
      } catch {
        throw new Error(
          "ClawMoat is required for DrawbridgeScanner. Install it: npm install clawmoat",
        );
      }
    }
  }

  /** Expose the underlying ClawMoat instance for advanced users. */
  get engine(): ClawMoatEngine {
    return this._engine;
  }

  /**
   * Scan a string for threats using ClawMoat.
   * Applies direction filtering, severity thresholds, and deduplication.
   */
  scan(content: string): DrawbridgeScanResult {
    const raw = this._engine.scan(content);
    const thresholdRank = SEVERITY_RANK[this.config.blockThreshold];

    // Collect directional findings
    const rawFindings = this.collectDirectionalFindings(raw);

    const findings: DrawbridgeFinding[] = [];
    const blockingFindings: DrawbridgeFinding[] = [];

    for (const { finding, direction } of rawFindings) {
      const rank = effectiveSeverityRank(finding.severity);
      const blocked = rank >= thresholdRank;
      const ruleId = normalizeRuleId(finding.type, finding.subtype);
      const sev = effectiveSeverity(finding.severity);

      // NOTE (v1.0): `source` holds a direct reference to the ClawMoat finding object.
      // Consumer callbacks that mutate finding.source will affect downstream sanitization.
      // Deep-cloning here would add overhead on the hot path. Accepted tradeoff for v1.0;
      // v1.1 may freeze the source or copy on construction.
      const enriched: DrawbridgeFinding = {
        ruleId,
        source: finding,
        blocked,
        description: `${finding.type}/${finding.subtype} (${sev}): "${finding.matched}"`,
        direction,
      };

      findings.push(enriched);
      if (blocked) blockingFindings.push(enriched);
      try {
        this.config.onFinding?.(enriched);
      } catch {
        // Consumer callbacks must never break internal state
      }
    }

    return {
      safe: blockingFindings.length === 0,
      findings,
      blockingFindings,
      raw,
    };
  }

  /**
   * Scan an arbitrary value by JSON-stringifying it first.
   * Safely handles circular references with depth-limited fallback.
   *
   * **Note:** `findings[].source.position` references character positions in the
   * JSON-stringified output, not positions in the original object structure.
   * Do not use position values from `scanObject` results for source mapping
   * back to the original object.
   */
  scanObject(content: unknown): DrawbridgeScanResult {
    return this.scan(safeStringify(content));
  }

  /**
   * Scan and sanitize in one call.
   * Equivalent to scan() followed by sanitizeContent() on blocked findings.
   */
  scanAndSanitize(
    content: string,
    sanitizeConfig?: Partial<SanitizeConfig> & { redactAll?: boolean },
  ): DrawbridgeScanResult & { sanitized: SanitizeResult } {
    const result = this.scan(content);
    const sanitized = sanitizeContent(content, result.findings, sanitizeConfig);
    return { ...result, sanitized };
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private collectDirectionalFindings(
    raw: ClawMoatScanResult,
  ): Array<{ finding: ClawMoatFinding; direction: "inbound" | "outbound" }> {
    const dir = this.config.direction;

    if (dir === "inbound") {
      return raw.inbound.findings.map((f) => ({ finding: f, direction: "inbound" as const }));
    }

    if (dir === "outbound") {
      return raw.outbound.findings.map((f) => ({ finding: f, direction: "outbound" as const }));
    }

    // "both" — merge with dedup by position+type, highest severity wins
    const merged = new Map<string, { finding: ClawMoatFinding; direction: "inbound" | "outbound" }>();

    for (const f of raw.inbound.findings) {
      const key = `${f.position}:${f.type}`;
      merged.set(key, { finding: f, direction: "inbound" });
    }

    for (const f of raw.outbound.findings) {
      const key = `${f.position}:${f.type}`;
      const existing = merged.get(key);
      if (!existing) {
        merged.set(key, { finding: f, direction: "outbound" });
      } else {
        // Take the higher severity
        const existingRank = effectiveSeverityRank(existing.finding.severity);
        const newRank = effectiveSeverityRank(f.severity);
        if (newRank > existingRank) {
          merged.set(key, { finding: f, direction: "outbound" });
        }
      }
    }

    return [...merged.values()];
  }
}
