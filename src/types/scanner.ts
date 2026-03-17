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

// --- Sanitize types ---

/** Configuration for content sanitization/redaction */
export interface SanitizeConfig {
  /** Replacement string for redacted content. Default: "[REDACTED]" */
  placeholder: string;

  /**
   * Whether to include the ruleId in the placeholder.
   * If true: "[REDACTED:drawbridge.prompt_injection.instruction_override]"
   * If false: "[REDACTED]"
   * Default: false
   */
  includeRuleId: boolean;

  /** Whether to include content hashes in redaction details. Default: false */
  hashRedactions?: boolean;

  /**
   * HMAC key for redaction hashes. Required if hashRedactions is true.
   * Without a key, hashes are omitted entirely — no bare SHA-256.
   */
  hmacKey?: string;
}

/** Default sanitize/redaction configuration */
export const DEFAULT_SANITIZE_CONFIG: SanitizeConfig = {
  placeholder: "[REDACTED]",
  includeRuleId: false,
};

/** Per-redaction detail for audit trail */
export interface RedactionDetail {
  /** Rule ID that caused this redaction */
  ruleId: string;
  /** Start position in original content */
  position: number;
  /** Length of content that was replaced */
  matchedLength: number;
  /** HMAC-SHA256 hash of the replaced content (if hashRedactions + hmacKey configured), otherwise empty string */
  sha256: string;
  /** The placeholder that replaced it */
  replacement: string;
  /** Whether this used the multi-occurrence fallback */
  fallback: boolean;
}

/** Result of content sanitization */
export interface SanitizeResult {
  /** The redacted content string */
  sanitized: string;

  /** Number of redactions applied */
  redactionCount: number;

  /** Total characters removed */
  charactersRemoved: number;

  /** Rule IDs of findings that caused redactions */
  redactedRuleIds: string[];

  /** Original content length */
  originalLength: number;

  /** Number of redactions that used multi-occurrence fallback (no reliable position data) */
  fallbackRedactions: number;

  /** Per-redaction detail for audit trail */
  redactions: RedactionDetail[];
}
