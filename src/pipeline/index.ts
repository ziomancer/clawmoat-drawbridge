/**
 * DrawbridgePipeline: full orchestration runner that routes content through
 * validation stages, scanner, frequency tracking, and audit emission.
 *
 * Single entry point: inspect(input) -> PipelineResult
 *
 * Pipeline flow:
 *   1. Trust check (trusted servers bypass)
 *   2. Stringify content (if object)
 *   3. Syntactic pre-filter
 *   4. Frequency update (pre-filter findings)
 *   5. Two-pass gate (if hard block, optionally skip scanner)
 *   6. Scanner (ClawMoat)
 *   7. Frequency update (scanner findings)
 *   8. Sanitize (redact blocked content)
 *   9. Audit events (per-stage)
 *  10. Alert evaluation (per-event)
 *
 * All modules are constructed once and reused across inspect() calls.
 * The pipeline is NOT thread-safe (same as all Drawbridge modules).
 */

import { DrawbridgeScanner } from "../scanner/index.js";
import { FrequencyTracker } from "../frequency/index.js";
import { PreFilter, SchemaValidator } from "../validation/index.js";
import { ProfileResolver } from "../profiles/index.js";
import { AuditEmitter } from "../audit/index.js";
import { AlertManager } from "../alerting/index.js";
import { sanitizeContent } from "../sanitize/index.js";
import { safeStringify } from "../lib/safe-stringify.js";
import type {
  DrawbridgePipelineConfig,
  PipelineInput,
  PipelineResult,
  TrustTier,
} from "../types/pipeline.js";
import type { TypedAuditEvent } from "../types/audit.js";
import type { AlertPayload } from "../types/alerting.js";
import type { SyntacticFilterResult, SchemaValidationResult } from "../types/validation.js";
import type { DrawbridgeScanResult, SanitizeResult } from "../types/scanner.js";
import type { FrequencyUpdateResult, EscalationTier, SessionSuspicionState } from "../types/frequency.js";
import type { ResolvedProfile } from "../types/profiles.js";
import { DEFAULT_HARD_BLOCK_RULES } from "../types/validation.js";

/** Full pipeline orchestration: routes content through validation, scanning, frequency tracking, and audit */
export class DrawbridgePipeline {
  private readonly scanner: DrawbridgeScanner;
  private readonly tracker: FrequencyTracker;
  private readonly preFilter: PreFilter;
  private readonly schemaValidator: SchemaValidator | null;
  private readonly profile: ProfileResolver;
  private readonly auditor: AuditEmitter;
  private readonly alerter: AlertManager;
  private readonly _trustedServers: string[];
  private readonly _twoPass: { enabled: boolean; hardBlockRules: string[] };
  private readonly _sanitize: {
    enabled: boolean;
    redactAll: boolean;
    placeholder: string;
    includeRuleId: boolean;
  };
  private readonly syntacticEnabled: boolean;

  /** Consumer's onEvent callback (forwarded per-event by pipeline) */
  private readonly _consumerOnEvent?: (event: TypedAuditEvent) => void;
  private readonly _consumerOnError?: (error: unknown, event: TypedAuditEvent) => void;

  /** Orphaned construction events (profile_loaded, audit_config_loaded) */
  private constructionEvents: TypedAuditEvent[] = [];

  /** Tracks last emitted escalation tier per session (for transition-only emission) */
  private readonly lastEmittedTier: Map<string, EscalationTier> = new Map();

  /** Max entries in lastEmittedTier before LRU eviction (matches frequency tracker scale) */
  private static readonly MAX_TIER_CACHE_SIZE = 10_000;

  /** Tier1 threshold from frequency config (stored at construction since tracker.config is private) */
  private readonly tier1Threshold: number;

  constructor(config?: DrawbridgePipelineConfig) {
    const cfg = config ?? {};

    // 1. Resolve profile first — it tunes other modules
    this.profile = new ProfileResolver(cfg.profile);
    const resolved = this.profile.profile;

    // 2. Build pre-filter config (profile applies suppress rules)
    this.syntacticEnabled = cfg.syntactic?.enabled !== false;
    const syntacticConfig = this.profile.applySyntacticConfig(cfg.syntactic);
    this.preFilter = new PreFilter(syntacticConfig);

    // 2b. Schema validator (if config provided)
    this.schemaValidator = cfg.schema
      ? new SchemaValidator(cfg.schema)
      : null;

    // 3. Build frequency tracker config (profile applies weight/threshold overrides)
    const frequencyConfig = this.profile.applyFrequencyConfig(cfg.frequency);
    this.tracker = new FrequencyTracker(frequencyConfig);
    this.tier1Threshold = frequencyConfig.thresholds.tier1;

    // 4. Scanner — pass through engine if provided for testing
    this.scanner = new DrawbridgeScanner(
      cfg.scanner,
      cfg.engine as { scan(text: string): import("../types/scanner.js").ClawMoatScanResult } | undefined,
    );

    // 5. Sanitize config
    this._sanitize = {
      enabled: cfg.sanitize?.enabled !== false,
      redactAll: cfg.sanitize?.redactAll ?? false,
      placeholder: cfg.sanitize?.placeholder ?? "[REDACTED]",
      includeRuleId: cfg.sanitize?.includeRuleId ?? false,
    };

    // 6. Two-pass config
    this._twoPass = {
      enabled: cfg.twoPass?.enabled ?? false,
      hardBlockRules: cfg.twoPass?.hardBlockRules ?? [...DEFAULT_HARD_BLOCK_RULES],
    };

    // 7. Trust config
    this._trustedServers = cfg.trustedServers ?? [];

    // 8. Audit emitter — pipeline is the event router (Option A)
    this._consumerOnEvent = cfg.audit?.onEvent;
    this._consumerOnError = cfg.audit?.onError;
    this.auditor = new AuditEmitter({
      ...cfg.audit,
      alertingEnabled: cfg.audit?.alertingEnabled ?? (cfg.alerting?.enabled !== false),
      onEvent: (event: TypedAuditEvent) => {
        // During construction, collect events; during inspect, the pipeline routes them
        this.constructionEvents.push(event);
      },
      onError: cfg.audit?.onError,
    });

    // 9. Alert manager
    this.alerter = new AlertManager(cfg.alerting);

    // 10. Emit profile_loaded (goes into constructionEvents via the onEvent wrapper)
    this.auditor.emitProfileLoaded({
      sessionId: "__init__",
      profileId: resolved.id,
      baseProfileId: resolved.baseProfileId,
      suppressedRules: resolved.syntacticEmphasis.suppressRules,
      frequencyOverrides: resolved.frequencyWeightOverrides,
    });
  }

  // ---------------------------------------------------------------------------
  // Core
  // ---------------------------------------------------------------------------

  inspect(input: PipelineInput): PipelineResult {
    const events: TypedAuditEvent[] = [];
    const alerts: AlertPayload[] = [];

    // Prepend orphaned construction events on first inspect()
    if (this.constructionEvents.length > 0) {
      for (const ce of this.constructionEvents) {
        events.push(ce);
        this.forwardToConsumer(ce);
        const alert = this.alerter.evaluate(ce);
        if (alert) alerts.push(alert);
      }
      this.constructionEvents = [];
    }

    // --- Stringify content ---
    const content = typeof input.content === "string"
      ? input.content
      : safeStringify(input.content);

    // --- Common audit params (clarification #5: include toolCallId) ---
    const auditParams = {
      sessionId: input.sessionId,
      messageId: input.messageId,
      toolCallId: input.toolCallId,
      agentId: undefined as string | undefined,
      profile: this.profile.profile.id,
    };

    // --- Trust check ---
    const trustTier = this.resolveTrust(input);
    if (trustTier === "trusted") {
      return this.trustedFastPath(content, input, events, alerts, auditParams);
    }

    // --- Check for terminated session ---
    const currentState = this.tracker.getState(input.sessionId);
    if (currentState?.terminated) {
      return this.terminatedPath(content, input, events, alerts, auditParams);
    }

    // --- Clarification #4: capture prior state BEFORE any frequency updates ---
    const priorState = this.tracker.getState(input.sessionId);

    // --- Stage 1: Syntactic pre-filter ---
    let preFilterResult: SyntacticFilterResult | null = null;
    let preFilterRuleIds: string[] = [];

    if (this.syntacticEnabled) {
      preFilterResult = this.preFilter.run(content);
      preFilterRuleIds = preFilterResult.ruleIds;

      // Audit: syntactic result
      this.routeEvent(
        this.auditor.emitSyntactic({
          ...auditParams,
          pass: preFilterResult.pass,
          ruleIds: preFilterResult.ruleIds,
          flags: preFilterResult.flags,
          hasFlags: preFilterResult.pass && preFilterResult.ruleIds.length > 0,
        }),
        events,
        alerts,
      );

      // Audit: rule_triggered fan-out (high verbosity)
      if (preFilterResult.ruleIds.length > 0) {
        const severities: Record<string, "block" | "flag"> = {};
        for (const id of preFilterResult.ruleIds) {
          severities[id] = preFilterResult.pass ? "flag" : "block";
        }
        for (const re of this.auditor.emitRuleTriggered({
          ...auditParams,
          ruleIds: preFilterResult.ruleIds,
          severities,
          stage: "syntactic",
        })) {
          this.routeEvent(re, events, alerts);
        }

        // Audit: flags_summary (standard verbosity, suppressed at high+)
        this.routeEvent(
          this.auditor.emitFlagsSummary({
            ...auditParams,
            stage: "syntactic",
            ruleIds: preFilterResult.ruleIds,
            flagCount: preFilterResult.ruleIds.length,
            blocked: !preFilterResult.pass,
          }),
          events,
          alerts,
        );
      }
    }

    // --- Stage 1b: Schema validation (MCP sources only) ---
    const schemaResult = this.runSchemaValidation(content, input, events, alerts, auditParams);

    // Schema violations are structural (type/format issues), not injection signals.
    // They are tracked via audit events and the trustedToolSchemaFail alert rule,
    // but excluded from frequency/suspicion scoring to avoid false escalation
    // from legitimate tools with schema mismatches.

    // --- Frequency update: pre-filter findings ---
    // Syntactic pre-filter findings contribute to suspicion — defense in depth
    let frequencyResult: FrequencyUpdateResult | null = null;

    if (preFilterRuleIds.length > 0) {
      frequencyResult = this.tracker.update(input.sessionId, preFilterRuleIds);

      // Clarification #3: only emit frequency escalation on tier transition
      this.emitFrequencyIfTransition(input.sessionId, frequencyResult, auditParams, events, alerts);

      // Terminated after pre-filter frequency update?
      if (frequencyResult.terminated) {
        return this.buildResult({
          safe: false,
          trusted: false,
          preFilterResult,
          schemaResult,
          scanResult: null,
          sanitizeResult: null,
          escalationTier: "tier3",
          frequencyResult,
          terminated: true,
          auditEvents: events,
          alerts,
          sanitizedContent: null,
          inspectedContent: content,
        });
      }
    }

    // --- Two-pass gate ---
    let skipScanner = false;

    if (this._twoPass.enabled && preFilterResult && !preFilterResult.pass) {
      const hasHardBlock = preFilterResult.ruleIds.some(
        (id) => this._twoPass.hardBlockRules.includes(id),
      );

      if (hasHardBlock) {
        // Clarification #6: hard-blocked content is rejected wholesale -- nothing to sanitize
        skipScanner = true;

        // Clarification #4: override uses PRIOR state (before current frequency updates)
        if (priorState && priorState.lastScore >= this.tier1Threshold) {
          skipScanner = false;
        }
      }
    }

    // --- Stage 2: Scanner (ClawMoat) ---
    let scanResult: DrawbridgeScanResult | null = null;

    if (!skipScanner) {
      scanResult = this.scanner.scan(content);

      // Audit: scan result
      this.routeEvent(
        this.auditor.emitScan({
          ...auditParams,
          safe: scanResult.safe,
          findingCount: scanResult.findings.length,
          blockingFindingCount: scanResult.blockingFindings.length,
          ruleIds: scanResult.findings.map((f) => f.ruleId),
        }),
        events,
        alerts,
      );

      // Audit: rule_triggered fan-out for scanner findings
      if (scanResult.findings.length > 0) {
        const severities: Record<string, "block" | "flag"> = {};
        for (const f of scanResult.findings) {
          severities[f.ruleId] = f.blocked ? "block" : "flag";
        }
        for (const re of this.auditor.emitRuleTriggered({
          ...auditParams,
          ruleIds: scanResult.findings.map((f) => f.ruleId),
          severities,
          stage: "scanner",
        })) {
          this.routeEvent(re, events, alerts);
        }

        // Flags summary for scanner
        this.routeEvent(
          this.auditor.emitFlagsSummary({
            ...auditParams,
            stage: "scanner",
            ruleIds: scanResult.findings.map((f) => f.ruleId),
            flagCount: scanResult.findings.length,
            blocked: !scanResult.safe,
          }),
          events,
          alerts,
        );
      }

      // --- Frequency update: scanner findings ---
      // Intentional: both stages contribute to suspicion -- defense in depth
      const scannerRuleIds = scanResult.findings.map((f) => f.ruleId);
      if (scannerRuleIds.length > 0) {
        const scanFreqResult = this.tracker.update(input.sessionId, scannerRuleIds);
        frequencyResult = scanFreqResult;

        this.emitFrequencyIfTransition(input.sessionId, scanFreqResult, auditParams, events, alerts);
      }
    }

    // --- Overall safety verdict ---
    const preFilterSafe = preFilterResult?.pass ?? true;
    const scannerSafe = scanResult?.safe ?? true;
    const safe = preFilterSafe && scannerSafe;

    // --- Sanitize ---
    let sanitizeResult: SanitizeResult | null = null;
    let sanitizedContent: string | null = null;

    // Clarification #6: no sanitized output on two-pass skip
    if (this._sanitize.enabled && scanResult && scanResult.findings.length > 0) {
      sanitizeResult = sanitizeContent(content, scanResult.findings, {
        placeholder: this._sanitize.placeholder,
        includeRuleId: this._sanitize.includeRuleId,
        redactAll: this._sanitize.redactAll,
      });
      sanitizedContent = sanitizeResult.sanitized;

      // Audit: sanitize event
      if (sanitizeResult.redactionCount > 0) {
        this.routeEvent(
          this.auditor.emitSanitize({
            ...auditParams,
            redactionCount: sanitizeResult.redactionCount,
            charactersRemoved: sanitizeResult.charactersRemoved,
            redactedRuleIds: sanitizeResult.redactedRuleIds,
          }),
          events,
          alerts,
        );

        // Emit output_diff at high verbosity with per-redaction data
        if (sanitizeResult.redactions.length > 0) {
          this.routeEvent(
            this.auditor.emitOutputDiff({
              ...auditParams,
              removals: sanitizeResult.redactions
                .map(r => ({
                  ruleId: r.ruleId,
                  position: r.position,
                  matchedLength: r.matchedLength,
                  contentHash: r.sha256,
                  fallback: r.fallback,
                })),
              replacements: sanitizeResult.redactions.map(r => ({
                ruleId: r.ruleId,
                lengthBefore: r.matchedLength,
                lengthAfter: r.replacement.length,
                contentHash: r.sha256,
                fallback: r.fallback,
              })),
            }),
            events,
            alerts,
          );
        }
      }
    }

    // --- Raw capture (maximum verbosity) ---
    // Clarification #10: gate sha256 computation behind verbosity
    if (this.auditor.meetsVerbosity("maximum")) {
      this.routeEvent(
        this.auditor.emitRawCapture({
          ...auditParams,
          type: "input",
          content,
        }),
        events,
        alerts,
      );

      if (sanitizedContent) {
        this.routeEvent(
          this.auditor.emitRawCapture({
            ...auditParams,
            type: "output",
            content: sanitizedContent,
          }),
          events,
          alerts,
        );
      }
    }

    // --- Determine escalation tier ---
    const escalationTier: EscalationTier = frequencyResult?.tier ?? "none";
    const terminated = frequencyResult?.terminated ?? false;

    return this.buildResult({
      safe,
      trusted: false,
      preFilterResult,
      schemaResult,
      scanResult,
      sanitizeResult,
      escalationTier,
      frequencyResult,
      terminated,
      auditEvents: events,
      alerts,
      sanitizedContent,
      inspectedContent: content,
    });
  }

  // ---------------------------------------------------------------------------
  // Public API: module access
  // ---------------------------------------------------------------------------

  /** Access the resolved profile (frozen, safe to expose) */
  get resolvedProfile(): ResolvedProfile {
    return this.profile.profile;
  }

  /** Get a session's current frequency state (returns snapshot, not reference) */
  getSessionState(sessionId: string): SessionSuspicionState | null {
    return this.tracker.getState(sessionId);
  }

  /** Get audit stats (emitted, dropped, errors) */
  getAuditStats(): { emitted: number; dropped: number; errors: number } {
    return {
      emitted: this.auditor.emitted,
      dropped: this.auditor.dropped,
      errors: this.auditor.errors,
    };
  }

  /** Get alert stats */
  getAlertStats(): { alerts: number; suppressed: number; rateLimited: number } {
    return {
      alerts: this.alerter.alerts,
      suppressed: this.alerter.suppressed,
      rateLimited: this.alerter.rateLimited,
    };
  }

  /** Reset a session's frequency state */
  resetSession(sessionId: string): void {
    this.tracker.reset(sessionId);
    this.lastEmittedTier.delete(sessionId);
  }

  /** Clear all state across all modules */
  clear(): void {
    this.tracker.clear();
    this.alerter.clear();
    this.auditor.resetStats();
    this.lastEmittedTier.clear();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Resolve trust tier for an input.
   * Trusted if source is "mcp" and serverName is in trustedServers list.
   */
  private resolveTrust(input: PipelineInput): TrustTier {
    if (input.source !== "mcp") return "untrusted";
    if (!input.serverName) return "untrusted";
    return this._trustedServers.includes(input.serverName)
      ? "trusted"
      : "untrusted";
  }

  /** Fast path for trusted MCP servers — still runs schema validation */
  private trustedFastPath(
    content: string,
    input: PipelineInput,
    events: TypedAuditEvent[],
    alerts: AlertPayload[],
    auditParams: Record<string, unknown>,
  ): PipelineResult {
    const schemaResult = this.runSchemaValidation(content, input, events, alerts, auditParams);

    this.routeEvent(
      this.auditor.emitScan({
        ...(auditParams as Parameters<AuditEmitter["emitScan"]>[0]),
        safe: true,
        findingCount: 0,
        blockingFindingCount: 0,
        ruleIds: [],
      }),
      events,
      alerts,
    );

    return this.buildResult({
      safe: true,
      trusted: true,
      preFilterResult: null,
      schemaResult,
      scanResult: null,
      sanitizeResult: null,
      escalationTier: "none",
      frequencyResult: null,
      terminated: false,
      auditEvents: events,
      alerts,
      sanitizedContent: null,
      inspectedContent: content,
    });
  }

  /** Path for already-terminated sessions */
  private terminatedPath(
    content: string,
    input: PipelineInput,
    events: TypedAuditEvent[],
    alerts: AlertPayload[],
    auditParams: Record<string, unknown>,
  ): PipelineResult {
    const state = this.tracker.getState(input.sessionId)!;
    this.routeEvent(
      this.auditor.emitFrequency({
        ...(auditParams as Parameters<AuditEmitter["emitFrequency"]>[0]),
        previousScore: state.lastScore,
        currentScore: state.lastScore,
        tier: "tier3",
        terminated: true,
      }),
      events,
      alerts,
    );

    return this.buildResult({
      safe: false,
      trusted: false,
      preFilterResult: null,
      schemaResult: null,
      scanResult: null,
      sanitizeResult: null,
      escalationTier: "tier3",
      frequencyResult: null,
      terminated: true,
      auditEvents: events,
      alerts,
      sanitizedContent: null,
      inspectedContent: content,
    });
  }

  /**
   * Route an emitted event: collect, forward to consumer, evaluate alerts.
   */
  private routeEvent(
    event: TypedAuditEvent | null,
    events: TypedAuditEvent[],
    alerts: AlertPayload[],
  ): void {
    if (!event) return;

    events.push(event);
    this.forwardToConsumer(event);

    const alert = this.alerter.evaluate(event);
    if (alert) {
      alerts.push(alert);
    }
  }

  /** Forward a single event to the consumer's onEvent callback */
  private forwardToConsumer(event: TypedAuditEvent): void {
    if (!this._consumerOnEvent) return;
    try {
      this._consumerOnEvent(event);
    } catch (error) {
      try {
        this._consumerOnError?.(error, event);
      } catch {
        // swallow
      }
    }
  }

  /**
   * Clarification #3: only emit frequency escalation event when the new tier
   * is strictly higher than the previously emitted tier for this session.
   */
  private emitFrequencyIfTransition(
    sessionId: string,
    result: FrequencyUpdateResult,
    auditParams: Record<string, unknown>,
    events: TypedAuditEvent[],
    alerts: AlertPayload[],
  ): void {
    if (result.tier === "none") return;

    const lastTier = this.lastEmittedTier.get(sessionId) ?? "none";
    const tierRank: Record<EscalationTier, number> = {
      none: 0,
      tier1: 1,
      tier2: 2,
      tier3: 3,
    };

    // LRU refresh: delete-and-re-set moves the key to the end of insertion order,
    // so eviction always removes the least-recently-accessed session.
    if (this.lastEmittedTier.has(sessionId)) {
      this.lastEmittedTier.delete(sessionId);
    }

    if (tierRank[result.tier] <= tierRank[lastTier]) {
      // No escalation — restore the existing tier at the refreshed position.
      this.lastEmittedTier.set(sessionId, lastTier);
      return;
    }

    this.lastEmittedTier.set(sessionId, result.tier);

    // LRU eviction when cache exceeds bound — removes least-recently-accessed
    if (this.lastEmittedTier.size > DrawbridgePipeline.MAX_TIER_CACHE_SIZE) {
      const lru = this.lastEmittedTier.keys().next().value;
      if (lru !== undefined) this.lastEmittedTier.delete(lru);
    }

    this.routeEvent(
      this.auditor.emitFrequency({
        ...(auditParams as Parameters<AuditEmitter["emitFrequency"]>[0]),
        previousScore: result.previousScore,
        currentScore: result.currentScore,
        tier: result.tier as "tier1" | "tier2" | "tier3",
        terminated: result.terminated,
      }),
      events,
      alerts,
    );
  }

  /**
   * Run schema validation if applicable (MCP source with serverName + toolName).
   * Shared between the main inspect path and the trusted fast path.
   *
   * When `input.content` is a string and `JSON.parse` fails, the raw string is
   * passed to the validator. `validateAgainstSchema` will reject it (typeof !== "object"),
   * and `validateDefault` strict mode will reject it (jsType === "string"). This is a
   * safe fallback — malformed/binary data cannot silently pass schema checks.
   */
  private runSchemaValidation(
    content: string,
    input: PipelineInput,
    events: TypedAuditEvent[],
    alerts: AlertPayload[],
    auditParams: Record<string, unknown>,
  ): SchemaValidationResult | null {
    if (!this.schemaValidator || input.source !== "mcp" || !input.serverName || !input.toolName) {
      return null;
    }

    // Use the original content object when available (non-string input.content);
    // otherwise parse the stringified form. Note: if safeStringify altered the
    // representation (e.g. BigInt → null, circular refs → "[Circular]"), the
    // round-tripped object will differ from the original — this is intentional,
    // as the validator should see what downstream consumers would see.
    const parsedContent = typeof input.content !== "string" ? input.content : undefined;
    const contentForSchema = parsedContent !== undefined
      ? parsedContent
      : (() => { try { return JSON.parse(content); } catch { return content; } })();

    const schemaResult = this.schemaValidator.validate(contentForSchema, input.serverName, input.toolName);
    const trusted = this._trustedServers.includes(input.serverName);

    this.routeEvent(
      this.auditor.emitSchema({
        ...(auditParams as Parameters<AuditEmitter["emitSchema"]>[0]),
        pass: schemaResult.pass,
        violations: schemaResult.violations,
        ruleIds: schemaResult.ruleIds,
        serverName: input.serverName,
        toolName: input.toolName,
        trusted,
      }),
      events,
      alerts,
    );

    return schemaResult;
  }

  private buildResult(fields: PipelineResult): PipelineResult {
    return fields;
  }
}
