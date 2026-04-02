/**
 * AlertManager: evaluates audit events against configurable rules
 * and fires alerts when patterns are detected.
 *
 * Callback-based delivery — the consumer decides where alerts go.
 * Alert failures are swallowed (onError callback if provided).
 * The manager must NEVER throw or crash the pipeline.
 *
 * Spec reference: Audit Alerting v2.3
 */

import { randomUUID } from "node:crypto";

import type {
  AlertManagerConfig,
  AlertPayload,
  AlertRuleId,
  AlertSeverity,
} from "../types/alerting.js";
import { DEFAULT_ALERT_CONFIG, DEFAULT_ALERT_RULES } from "../types/alerting.js";

import type {
  TypedAuditEvent,
  FrequencyAuditEvent,
  SyntacticAuditEvent,
  SchemaAuditEvent,
} from "../types/audit.js";

/** Evaluates audit events against configurable rules and fires alerts when patterns are detected */
export class AlertManager {
  private readonly config: AlertManagerConfig;

  // Cross-session event index (ring buffers per event type for burst detection)
  private readonly eventIndex: Map<string, Array<{ timestamp: number; sessionId: string }>>;

  // Dedup: key = `${ruleId}|${sessionId}`, value = timestamp of last alert
  private readonly dedupMap: Map<string, number>;

  // Rate limiting
  private readonly minuteTimestamps: number[];
  private readonly hourTimestamps: number[];

  // Rule 4 correlation: key = messageId or toolCallId, value = syntactic_pass event
  private readonly syntacticPassIndex: Map<string, TypedAuditEvent>;

  // Rule 4 escalation counter
  private rule4Count = 0;
  private rule4WindowStart: number = Date.now();

  // Per-session recent event buffer (FIFO eviction at MAX_SESSION_EVENT_ENTRIES)
  private readonly sessionEvents: Map<string, TypedAuditEvent[]>;
  private static readonly MAX_SESSION_EVENT_ENTRIES = 10_000;

  // Stats
  private alertCount = 0;
  private suppressedCount = 0;
  private rateLimitedCount = 0;

  constructor(config?: Partial<AlertManagerConfig>) {
    this.config = {
      ...DEFAULT_ALERT_CONFIG,
      ...config,
      rules: {
        ...DEFAULT_ALERT_RULES,
        ...config?.rules,
        frequencyEscalation: {
          ...DEFAULT_ALERT_RULES.frequencyEscalation,
          ...config?.rules?.frequencyEscalation,
          tier3Enabled: true, // ALWAYS true — cannot be disabled
        },
        trustedToolSchemaFail: {
          enabled: config?.rules?.trustedToolSchemaFail?.enabled
            ?? DEFAULT_ALERT_RULES.trustedToolSchemaFail?.enabled
            ?? true,
        },
      },
      rateLimit: {
        ...DEFAULT_ALERT_CONFIG.rateLimit,
        ...config?.rateLimit,
      },
    };

    // Validate config values (Finding #19)
    if (!Number.isFinite(this.config.suppressionWindowMinutes) || this.config.suppressionWindowMinutes < 0) {
      throw new Error(
        `AlertManager: suppressionWindowMinutes must be a non-negative finite number, ` +
        `got ${this.config.suppressionWindowMinutes}`,
      );
    }
    if (!Number.isInteger(this.config.rateLimit.maxPerMinute) || this.config.rateLimit.maxPerMinute < 1) {
      throw new Error(
        `AlertManager: rateLimit.maxPerMinute must be a positive integer, ` +
        `got ${this.config.rateLimit.maxPerMinute}`,
      );
    }
    if (!Number.isInteger(this.config.rateLimit.maxPerHour) || this.config.rateLimit.maxPerHour < 1) {
      throw new Error(
        `AlertManager: rateLimit.maxPerHour must be a positive integer, ` +
        `got ${this.config.rateLimit.maxPerHour}`,
      );
    }
    if (!Number.isFinite(this.config.recentContextMax) || !Number.isInteger(this.config.recentContextMax) || this.config.recentContextMax < 0) {
      throw new Error(
        `AlertManager: recentContextMax must be a non-negative finite integer, got ${this.config.recentContextMax}`,
      );
    }

    this.eventIndex = new Map();
    this.dedupMap = new Map();
    this.minuteTimestamps = [];
    this.hourTimestamps = [];
    this.syntacticPassIndex = new Map();
    this.sessionEvents = new Map();
  }

  // ---------------------------------------------------------------------------
  // Core
  // ---------------------------------------------------------------------------

  /**
   * Evaluate an audit event against all rules.
   * Returns the alert if one was fired, null otherwise.
   */
  evaluate(event: TypedAuditEvent): AlertPayload | null {
    if (!this.config.enabled) return null;

    try {
      // 1. Index the event
      this.indexEvent(event);

      // 2. Evaluate rules
      let alert: AlertPayload | null = null;

      switch (event.event) {
        case "syntactic_fail":
          alert = this.evaluateSyntacticFailBurst(event);
          break;

        case "syntactic_pass":
          this.indexSyntacticPass(event);
          break;

        case "frequency_escalation_tier2":
          alert = this.evaluateFrequencyEscalation(event, "tier2", "high");
          break;

        case "frequency_escalation_tier3":
          alert = this.evaluateFrequencyEscalation(event, "tier3", "critical");
          break;

        case "scan_block":
          alert = this.evaluateScanBlockAfterSyntacticPass(event);
          break;

        case "schema_fail":
          alert = this.evaluateTrustedToolSchemaFail(event);
          break;

        // write_failed not yet a Drawbridge audit event — writeFailSpike deferred
      }

      // 3. Apply dedup and rate limiting
      if (alert) {
        if (this.isDuplicate(alert)) {
          this.suppressedCount++;
          return null;
        }
        // Critical alerts are never rate-limited (Finding #10)
        if (alert.severity !== "critical" && this.isRateLimited()) {
          this.rateLimitedCount++;
          return null;
        }
        this.deliver(alert);
        return alert;
      }

      return null;
    } catch (error) {
      // evaluate() must NEVER throw — a failed evaluation is not an alert (Finding #15)
      // Surface the error via onError for observability while preserving fail-open.
      try {
        this.config.onError?.(error, null);
      } catch {
        // swallow completely — alerting must never crash pipeline
      }
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  /** Number of alerts delivered */
  get alerts(): number {
    return this.alertCount;
  }

  /** Number of alerts suppressed by dedup */
  get suppressed(): number {
    return this.suppressedCount;
  }

  /** Number of alerts dropped by rate limit */
  get rateLimited(): number {
    return this.rateLimitedCount;
  }

  /** Clear all state (index, dedup, rate limit, correlation) */
  clear(): void {
    this.eventIndex.clear();
    this.dedupMap.clear();
    this.minuteTimestamps.length = 0;
    this.hourTimestamps.length = 0;
    this.syntacticPassIndex.clear();
    this.sessionEvents.clear();
    this.rule4Count = 0;
    this.rule4WindowStart = Date.now();
    this.alertCount = 0;
    this.suppressedCount = 0;
    this.rateLimitedCount = 0;
  }

  // ---------------------------------------------------------------------------
  // Rule evaluators
  // ---------------------------------------------------------------------------

  /** Rule 1: Syntactic fail burst (cross-session aggregation) */
  private evaluateSyntacticFailBurst(
    event: TypedAuditEvent,
  ): AlertPayload | null {
    const rule = this.config.rules.syntacticFailBurst;
    if (!rule.enabled) return null;

    const windowMs = rule.windowMinutes * 60_000;
    const now = Date.now();
    const entries = this.eventIndex.get("syntactic_fail") ?? [];
    const recentCount = entries.filter((e) => now - e.timestamp < windowMs).length;

    if (recentCount < rule.count) return null;

    return this.buildAlert({
      ruleId: "syntacticFailBurst",
      severity: "medium",
      sessionId: event.sessionId,
      agentId: event.agentId,
      summary: `${recentCount} syntactic failures in ${rule.windowMinutes} minutes across sessions`,
      triggeringEvents: [event],
      ruleConfig: { count: rule.count, windowMinutes: rule.windowMinutes },
    });
  }

  /** Rule 3: Frequency escalation */
  private evaluateFrequencyEscalation(
    event: TypedAuditEvent,
    tier: "tier2" | "tier3",
    severity: AlertSeverity,
  ): AlertPayload | null {
    if (tier === "tier2" && !this.config.rules.frequencyEscalation.tier2Enabled) {
      return null;
    }
    // tier3 is ALWAYS enabled — no check

    const freqEvent = event as FrequencyAuditEvent;

    return this.buildAlert({
      ruleId:
        tier === "tier2"
          ? "frequencyEscalationTier2"
          : "frequencyEscalationTier3",
      severity,
      sessionId: event.sessionId,
      agentId: event.agentId,
      summary:
        tier === "tier3"
          ? `Session terminated — suspicion score ${freqEvent.currentScore.toFixed(1)} exceeded tier3 threshold`
          : `Frequency escalation to tier2 — suspicion score ${freqEvent.currentScore.toFixed(1)}`,
      triggeringEvents: [event],
      ruleConfig: {},
      sessionSuspicionScore: freqEvent.currentScore,
    });
  }

  /** Rule 4: Scan block after syntactic pass (correlation by messageId) */
  private evaluateScanBlockAfterSyntacticPass(
    event: TypedAuditEvent,
  ): AlertPayload | null {
    const rule = this.config.rules.scanBlockAfterSyntacticPass;
    if (!rule.enabled) return null;

    const correlationId = event.messageId ?? event.toolCallId;
    if (!correlationId) return null;

    const priorPass = this.syntacticPassIndex.get(correlationId);
    if (!priorPass) return null;

    // If syntactic pass had flags, system caught something — not a gap
    const syntacticEvent = priorPass as SyntacticAuditEvent;
    if (syntacticEvent.ruleIds && syntacticEvent.ruleIds.length > 0) {
      return null;
    }

    // Track for escalation
    this.rule4Count++;
    const twentyFourHours = 24 * 60 * 60_000;
    if (Date.now() - this.rule4WindowStart > twentyFourHours) {
      this.rule4Count = 1;
      this.rule4WindowStart = Date.now();
    }

    const alertSeverity: AlertSeverity =
      this.rule4Count >= rule.escalateAfter ? "high" : "medium";

    return this.buildAlert({
      ruleId: "scanBlockAfterSyntacticPass",
      severity: alertSeverity,
      sessionId: event.sessionId,
      agentId: event.agentId,
      summary: `Scanner blocked content that syntactic filter passed cleanly (occurrence ${this.rule4Count})`,
      triggeringEvents: [event, priorPass],
      ruleConfig: {
        escalateAfter: rule.escalateAfter,
        occurrenceCount: this.rule4Count,
      },
    });
  }

  /** Rule 2: Trusted tool schema fail */
  private evaluateTrustedToolSchemaFail(
    event: TypedAuditEvent,
  ): AlertPayload | null {
    const rule = this.config.rules.trustedToolSchemaFail;
    if (!rule?.enabled) return null;

    const schemaEvent = event as SchemaAuditEvent;
    if (schemaEvent.trusted !== true) return null;

    return this.buildAlert({
      ruleId: "trustedToolSchemaFail",
      severity: "high",
      sessionId: event.sessionId,
      agentId: event.agentId,
      summary: `Trusted tool ${schemaEvent.serverName}:${schemaEvent.toolName} produced structurally invalid output`,
      triggeringEvents: [event],
      ruleConfig: { enabled: rule.enabled },
    });
  }

  // ---------------------------------------------------------------------------
  // Indexing
  // ---------------------------------------------------------------------------

  private indexEvent(event: TypedAuditEvent): void {
    // Event type index (for burst detection)
    const typeKey = event.event;
    if (!this.eventIndex.has(typeKey)) {
      this.eventIndex.set(typeKey, []);
    }
    const entries = this.eventIndex.get(typeKey)!;
    entries.push({ timestamp: Date.now(), sessionId: event.sessionId });
    if (entries.length > 1000) {
      entries.splice(0, entries.length - 1000);
    }

    // Per-session recent events (bounded to MAX_SESSION_EVENT_ENTRIES sessions).
    // When the session cap is reached, the least-recently-added session and ALL
    // of its buffered events are evicted. This is intentional — partial eviction
    // would leave stale context in alert payloads. Individual session buffers are
    // separately bounded by recentContextMax (shift on overflow, lines below).
    if (!this.sessionEvents.has(event.sessionId)) {
      this.sessionEvents.set(event.sessionId, []);
      if (this.sessionEvents.size > AlertManager.MAX_SESSION_EVENT_ENTRIES) {
        const oldest = this.sessionEvents.keys().next().value;
        if (oldest !== undefined) this.sessionEvents.delete(oldest);
      }
    }
    const sessionBuf = this.sessionEvents.get(event.sessionId)!;
    sessionBuf.push(event);
    if (sessionBuf.length > this.config.recentContextMax) {
      sessionBuf.shift();
    }
  }

  private indexSyntacticPass(event: TypedAuditEvent): void {
    const id = event.messageId ?? event.toolCallId;
    if (id) {
      this.syntacticPassIndex.set(id, event);
      if (this.syntacticPassIndex.size > 10_000) {
        const firstKey = this.syntacticPassIndex.keys().next().value;
        if (firstKey) this.syntacticPassIndex.delete(firstKey as string);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Dedup & rate limiting
  // ---------------------------------------------------------------------------

  private isDuplicate(alert: AlertPayload): boolean {
    // Include tool identity for schema alerts so different tools' failures
    // aren't collapsed within the same session.
    let key = `${alert.ruleId}|${alert.sessionId}`;
    if (alert.ruleId === "trustedToolSchemaFail") {
      const trigger = alert.details.triggeringEvents[0] as SchemaAuditEvent | undefined;
      key += `|${trigger?.serverName ?? ""}:${trigger?.toolName ?? ""}`;
    }
    const lastTime = this.dedupMap.get(key);
    const windowMs = this.config.suppressionWindowMinutes * 60_000;
    const now = Date.now();

    if (lastTime && now - lastTime < windowMs) {
      return true;
    }

    this.dedupMap.set(key, now);

    // Prune stale entries
    for (const [k, t] of this.dedupMap) {
      if (now - t > windowMs) {
        this.dedupMap.delete(k);
      }
    }

    return false;
  }

  private isRateLimited(): boolean {
    const now = Date.now();
    const oneMinuteAgo = now - 60_000;
    const oneHourAgo = now - 3_600_000;

    while (
      this.minuteTimestamps.length > 0 &&
      this.minuteTimestamps[0]! < oneMinuteAgo
    ) {
      this.minuteTimestamps.shift();
    }
    while (
      this.hourTimestamps.length > 0 &&
      this.hourTimestamps[0]! < oneHourAgo
    ) {
      this.hourTimestamps.shift();
    }

    if (this.minuteTimestamps.length >= this.config.rateLimit.maxPerMinute)
      return true;
    if (this.hourTimestamps.length >= this.config.rateLimit.maxPerHour)
      return true;

    this.minuteTimestamps.push(now);
    this.hourTimestamps.push(now);
    return false;
  }

  // ---------------------------------------------------------------------------
  // Delivery & building
  // ---------------------------------------------------------------------------

  private buildAlert(params: {
    ruleId: AlertRuleId;
    severity: AlertSeverity;
    sessionId: string;
    agentId?: string;
    summary: string;
    triggeringEvents: TypedAuditEvent[];
    ruleConfig: Record<string, unknown>;
    sessionSuspicionScore?: number;
  }): AlertPayload {
    return {
      alertId: randomUUID(),
      ruleId: params.ruleId,
      severity: params.severity,
      sessionId: params.sessionId,
      agentId: params.agentId,
      timestamp: new Date().toISOString(),
      summary: params.summary,
      details: {
        triggeringEvents: params.triggeringEvents,
        recentContext: (this.sessionEvents.get(params.sessionId) ?? []).slice(
          -this.config.recentContextMax,
        ),
        sessionSuspicionScore: params.sessionSuspicionScore,
      },
      metadata: {
        ruleConfig: params.ruleConfig,
      },
    };
  }

  private deliver(alert: AlertPayload): void {
    try {
      this.config.onAlert?.(alert);
      this.alertCount++;
    } catch (error) {
      try {
        this.config.onError?.(error, alert);
      } catch {
        // swallow completely — alerting must never crash pipeline
      }
    }
  }
}
