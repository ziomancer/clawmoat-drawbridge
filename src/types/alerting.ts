/**
 * Alert rules, delivery, deduplication, and rate limiting.
 *
 * Spec reference: Audit Alerting v2.3
 */

import type { TypedAuditEvent } from "./audit.js";
import { deepFreeze } from "./common.js";

/** Alert severity levels */
export type AlertSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Alert severity ranking for comparison */
export const ALERT_SEVERITY_RANK: Record<AlertSeverity, number> = Object.freeze({
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
});

/** Alert rule identifiers */
export type AlertRuleId =
  | "syntacticFailBurst"
  | "frequencyEscalationTier2"
  | "frequencyEscalationTier3"
  | "scanBlockAfterSyntacticPass"
  | "writeFailSpike"
  | "trustedToolSchemaFail"
  | "toolPolicyBlock";

/** Alert payload delivered to consumers */
export interface AlertPayload {
  /** Unique alert identifier for deduplication tracking */
  alertId: string;
  /** Which rule fired */
  ruleId: AlertRuleId;
  /** Alert severity */
  severity: AlertSeverity;
  /** Session that triggered the alert */
  sessionId: string;
  /** Optional agent identifier */
  agentId?: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Human-readable one-line summary */
  summary: string;
  /** Detailed context */
  details: {
    /** The event(s) that caused the alert */
    triggeringEvents: TypedAuditEvent[];
    /** Recent events from same session (capped by recentContextMax) */
    recentContext: TypedAuditEvent[];
    /** Current frequency score if applicable */
    sessionSuspicionScore?: number;
  };
  /** Rule configuration that governed this alert */
  metadata: {
    ruleConfig: Record<string, unknown>;
  };
}

/** Per-rule configuration */
export interface AlertRuleConfigs {
  syntacticFailBurst: {
    enabled: boolean;
    /** Minimum events to trigger. Default: 5 */
    count: number;
    /** Time window in minutes. Default: 10 */
    windowMinutes: number;
  };
  frequencyEscalation: {
    /** Tier 2 alerts. Default: true */
    tier2Enabled: boolean;
    /** Tier 3 alerts. ALWAYS true — cannot be disabled */
    tier3Enabled: true;
  };
  scanBlockAfterSyntacticPass: {
    enabled: boolean;
    /**
     * After this many occurrences within 24h, severity escalates
     * from medium to high. Default: 3
     */
    escalateAfter: number;
  };
  writeFailSpike: {
    enabled: boolean;
    /** Minimum events to trigger. Default: 3 */
    count: number;
    /** Time window in minutes. Default: 5 */
    windowMinutes: number;
  };
  /**
   * Alert Rule 2: fire on schema_fail from a trusted server.
   * Optional for backward compatibility — defaults to `{ enabled: true }` when absent.
   */
  trustedToolSchemaFail?: {
    enabled: boolean;
  };
  toolPolicyBlock?: {
    enabled: boolean;
    /** Minimum blocks to trigger. Default: 1 */
    count: number;
    /** Time window in minutes. Default: 10 */
    windowMinutes: number;
  };
}

/** Alert manager configuration */
export interface AlertManagerConfig {
  /** Master toggle. When false, no alerts fire. Default: true */
  enabled: boolean;

  /** Per-rule configuration */
  rules: AlertRuleConfigs;

  /** Deduplication window in minutes. Default: 5 */
  suppressionWindowMinutes: number;

  /** Rate limits */
  rateLimit: {
    maxPerMinute: number;
    maxPerHour: number;
  };

  /** Max recent events included in alert context. Default: 20 */
  recentContextMax: number;

  /**
   * Alert handler. Called for every alert that passes dedup and rate limits.
   * Consumer decides delivery (Slack, PagerDuty, log file, etc.).
   */
  onAlert?: (alert: AlertPayload) => void;

  /**
   * Error handler. Called if onAlert throws.
   * Alerting must never crash the pipeline.
   */
  onError?: (error: unknown, alert: AlertPayload | null) => void;
}

/** Default alert rule configuration */
export const DEFAULT_ALERT_RULES: AlertRuleConfigs = deepFreeze({
  syntacticFailBurst: {
    enabled: true,
    count: 5,
    windowMinutes: 10,
  },
  frequencyEscalation: {
    tier2Enabled: true,
    tier3Enabled: true,
  },
  scanBlockAfterSyntacticPass: {
    enabled: true,
    escalateAfter: 3,
  },
  writeFailSpike: {
    enabled: true,
    count: 3,
    windowMinutes: 5,
  },
  trustedToolSchemaFail: {
    enabled: true,
  },
  toolPolicyBlock: {
    enabled: true,
    count: 1,
    windowMinutes: 10,
  },
});

/** Default alert manager configuration */
export const DEFAULT_ALERT_CONFIG: AlertManagerConfig = deepFreeze({
  enabled: true,
  rules: DEFAULT_ALERT_RULES,
  suppressionWindowMinutes: 5,
  rateLimit: {
    maxPerMinute: 20,
    maxPerHour: 100,
  },
  recentContextMax: 20,
});
