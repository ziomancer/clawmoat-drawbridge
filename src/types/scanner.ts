import { Severity, SEVERITY_RANK, isSeverity } from "./common.js";

// Re-export for convenience (consumers can import from scanner or common)
export { Severity, SEVERITY_RANK, isSeverity };

// --- ClawMoat native types (mirrors darfaz's actual API) ---

/** Single finding from ClawMoat scan */
export interface ClawMoatFinding {
  type: string;
  subtype: string;
  severity: string;
  matched: string;
  position: number;
}

/** ClawMoat directional scan result */
export interface ClawMoatDirectionalResult {
  findings: ClawMoatFinding[];
  safe: boolean;
  severity: string;
  action: string;
}

/** Full ClawMoat scan result */
export interface ClawMoatScanResult {
  safe: boolean;
  findings: ClawMoatFinding[];
  inbound: ClawMoatDirectionalResult;
  outbound: ClawMoatDirectionalResult;
}

// --- Drawbridge scanner types ---

/** Configuration for the Drawbridge scanner */
export interface DrawbridgeScannerConfig {
  /**
   * Minimum severity to trigger a block.
   * Findings below this threshold are still reported but don't cause safe=false.
   * Default: "low" (everything blocks)
   */
  blockThreshold?: Severity;

  /**
   * Which scan direction to evaluate.
   * "inbound" = user/external input headed toward the agent
   * "outbound" = agent output headed toward tools/user
   * "both" = evaluate both directions (dedup by position+type, highest severity wins)
   * Default: "inbound"
   */
  direction?: "inbound" | "outbound" | "both";

  /**
   * Optional callback fired for each finding. Provides observability
   * without requiring consumers to parse results.
   */
  onFinding?: (finding: DrawbridgeFinding) => void;
}

/** Drawbridge scan result — enriched wrapper around ClawMoat's result */
export interface DrawbridgeScanResult {
  /** Overall safety verdict (respects blockThreshold) */
  safe: boolean;

  /** All findings, regardless of threshold */
  findings: DrawbridgeFinding[];

  /** Findings that met the blockThreshold (caused safe=false) */
  blockingFindings: DrawbridgeFinding[];

  /** Raw ClawMoat result, preserved for audit/debugging */
  raw: ClawMoatScanResult;
}

/** Enriched finding with normalized rule ID */
export interface DrawbridgeFinding {
  /** Normalized rule ID: "drawbridge.<type>.<subtype>" */
  ruleId: string;

  /** Original ClawMoat finding */
  source: ClawMoatFinding;

  /** Whether this finding met the block threshold */
  blocked: boolean;

  /** Human-readable description */
  description: string;

  /** Which direction this finding came from */
  direction: "inbound" | "outbound";
}
