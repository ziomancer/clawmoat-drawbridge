/**
 * Shared type primitives used across multiple Drawbridge modules.
 * Prevents cross-module coupling — modules import from common, not from each other.
 */

/** Severity levels for threshold filtering (used by scanner, frequency, profiles) */
export type Severity = "low" | "medium" | "high" | "critical";

/** Severity ranking for threshold comparison */
export const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Type guard: is this string a valid Severity? */
export const isSeverity = (value: string): value is Severity =>
  value in SEVERITY_RANK;

/** Audit verbosity levels (used by profiles, audit, pipeline) */
export type AuditVerbosity = "minimal" | "standard" | "high" | "maximum";

/** Content source classification (used by validation, pipeline) */
export type ContentSource = "transcript" | "mcp" | (string & {});
