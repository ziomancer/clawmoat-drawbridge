/**
 * Alert rules, delivery channels, and escalation.
 *
 * Spec reference: Audit Alerting v2.3
 *
 * NOT IMPLEMENTED in v0.1. Types exported for pipeline type stability.
 */

/** Alert severity levels */
export type AlertSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Alert payload delivered to channels */
export interface AlertPayload {
  ruleId: string;
  severity: AlertSeverity;
  title: string;
  detail: string;
  agentId: string;
  sessionId: string;
  timestamp: string;
  recentContext: unknown[];
  suppressedCount?: number;
}

/** Alert delivery channel types */
export type AlertChannel = "log" | "file" | "webhook";

/** Webhook channel configuration */
export interface WebhookChannelConfig {
  url: string;
  secret?: string;
  retries: number;
  retryDelayMs: number;
  timeoutMs: number;
}

/** Alerting configuration */
export interface AlertingConfig {
  enabled: boolean;
  channels: {
    webhook?: WebhookChannelConfig;
  };
  suppression: {
    windowMinutes: number;
  };
  rateLimit: {
    maxPerMinute: number;
    maxPerHour: number;
  };
  retention: {
    days: number;
  };
  index: {
    ttlMinutes: number;
  };
}
