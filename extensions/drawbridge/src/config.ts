/**
 * Plugin configuration types and defaults.
 * Defensive copies at construction — immutable after init.
 */

import type { FrequencyTrackerConfig, AuditVerbosity } from "@vigil-harbor/clawmoat-drawbridge";
import type { BuiltInProfileId, CustomProfileDefinition } from "@vigil-harbor/clawmoat-drawbridge";

export interface DrawbridgePluginConfig {
  /** Inbound profile. Default: "general" */
  inboundProfile?: BuiltInProfileId | CustomProfileDefinition;
  /** Outbound profile. Default: "customer-service" */
  outboundProfile?: BuiltInProfileId | CustomProfileDefinition;

  /** Shared FrequencyTracker config. Applied to the single shared tracker. */
  frequency?: Partial<FrequencyTrackerConfig>;

  /** Severity threshold for blocking. Default: "medium" */
  blockThreshold?: "low" | "medium" | "high" | "critical";
  /** Scanning direction. Default: "both" */
  direction?: "inbound" | "outbound" | "both";

  /** Action on tier2 escalation. Default: "warn" */
  tier2Action?: "warn" | "block";
  /** Message returned when content is blocked. */
  blockMessage?: string;
  /** Message returned when session is terminated. */
  terminateMessage?: string;

  /** Redact outbound content vs cancel. Default: true */
  redactOutbound?: boolean;
  /** HMAC-hash redacted spans. Default: true */
  hashRedactions?: boolean;

  /** Audit output target. Default: "log" */
  auditSink?: "log" | "vigil-harbor" | "both";
  /** Audit verbosity. Default: "standard" */
  auditVerbosity?: AuditVerbosity;
  /** Discord channel ID for alert notifications. */
  alertChannel?: string;

  /** Channel IDs exempt from scanning. */
  exemptChannels?: string[];
  /** Sender IDs exempt from scanning. */
  exemptSenders?: string[];

  /** Whether the tool call policy guard is enabled. Default: true */
  toolGuardEnabled?: boolean;
  /** Tools that skip policy evaluation (still audited). */
  exemptTools?: string[];
  /** Allowlist for tier2+ sessions. Default: ["read"] */
  restrictedTools?: string[];
  /** Custom ClawMoat policies for tool evaluation. */
  toolPolicies?: Record<string, unknown>;
  /** Promote "warn" to "block" at tier1+. Default: true */
  escalateWarnings?: boolean;
  /** Scan tool params through content pipeline. Default: true */
  scanParams?: boolean;
}

export interface ResolvedConfig {
  inboundProfile: BuiltInProfileId | CustomProfileDefinition;
  outboundProfile: BuiltInProfileId | CustomProfileDefinition;
  frequency: Partial<FrequencyTrackerConfig> | undefined;
  blockThreshold: "low" | "medium" | "high" | "critical";
  direction: "inbound" | "outbound" | "both";
  tier2Action: "warn" | "block";
  blockMessage: string;
  terminateMessage: string;
  redactOutbound: boolean;
  hashRedactions: boolean;
  auditSink: "log" | "vigil-harbor" | "both";
  auditVerbosity: AuditVerbosity;
  alertChannel: string | undefined;
  exemptChannels: readonly string[];
  exemptSenders: readonly string[];
  toolGuardEnabled: boolean;
  exemptTools: readonly string[];
  restrictedTools: readonly string[];
  toolPolicies: Record<string, unknown> | undefined;
  escalateWarnings: boolean;
  scanParams: boolean;
}

export function resolveConfig(input?: DrawbridgePluginConfig): Readonly<ResolvedConfig> {
  const cfg = input ?? {};
  const freq = cfg.frequency
    ? Object.freeze({
        ...cfg.frequency,
        weights: cfg.frequency.weights ? Object.freeze({ ...cfg.frequency.weights }) : undefined,
        thresholds: cfg.frequency.thresholds ? Object.freeze({ ...cfg.frequency.thresholds }) : undefined,
        memory: cfg.frequency.memory ? Object.freeze({ ...cfg.frequency.memory }) : undefined,
      })
    : undefined;
  return Object.freeze({
    inboundProfile: cfg.inboundProfile ?? "general",
    outboundProfile: cfg.outboundProfile ?? "customer-service",
    frequency: freq,
    blockThreshold: cfg.blockThreshold ?? "medium",
    direction: cfg.direction ?? "both",
    tier2Action: cfg.tier2Action ?? "warn",
    blockMessage: cfg.blockMessage ?? "Message blocked by content filter.",
    terminateMessage: cfg.terminateMessage ?? "Session terminated due to repeated violations.",
    redactOutbound: cfg.redactOutbound ?? true,
    hashRedactions: cfg.hashRedactions ?? true,
    auditSink: cfg.auditSink ?? "log",
    auditVerbosity: cfg.auditVerbosity ?? "standard",
    alertChannel: cfg.alertChannel,
    exemptChannels: Object.freeze([...(cfg.exemptChannels ?? [])]),
    exemptSenders: Object.freeze([...(cfg.exemptSenders ?? [])]),
    toolGuardEnabled: cfg.toolGuardEnabled ?? true,
    exemptTools: Object.freeze([...(cfg.exemptTools ?? [])]),
    restrictedTools: Object.freeze([...(cfg.restrictedTools ?? ["read"])]),
    toolPolicies: cfg.toolPolicies,
    escalateWarnings: cfg.escalateWarnings ?? true,
    scanParams: cfg.scanParams ?? true,
  });
}
