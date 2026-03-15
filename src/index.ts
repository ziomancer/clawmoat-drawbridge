// === Shared primitives (canonical source — also re-exported by individual modules) ===
export type { Severity, AuditVerbosity, ContentSource } from "./types/common.js";
export { SEVERITY_RANK, isSeverity } from "./types/common.js";

// === v0.1 implemented ===
export { DrawbridgeScanner, normalizeRuleId } from "./scanner/index.js";

// === v0.2 implemented ===
export { FrequencyTracker } from "./frequency/index.js";

// === v0.3 implemented ===
export { sanitizeContent } from "./sanitize/index.js";

// === v0.3 implemented ===
export { ProfileResolver } from "./profiles/index.js";
export { PreFilter } from "./validation/index.js";

// === v0.4 implemented ===
export { AuditEmitter, sha256 } from "./audit/index.js";

// === v0.5+ stubs (pipeline modules) ===
export { AlertManager } from "./alerting/index.js";
export { DrawbridgePipeline } from "./pipeline/index.js";

// === Module-specific types ===
export type {
  // Scanner (v0.1)
  ClawMoatFinding,
  ClawMoatDirectionalResult,
  ClawMoatScanResult,
  DrawbridgeScannerConfig,
  DrawbridgeScanResult,
  DrawbridgeFinding,
  // Sanitize (v0.3)
  SanitizeConfig,
  SanitizeResult,
} from "./types/scanner.js";

export { DEFAULT_SANITIZE_CONFIG } from "./types/scanner.js";

export type {
  // Frequency (v0.2)
  EscalationTier,
  SessionSuspicionState,
  FrequencyConfig,
  FrequencyUpdateResult,
  FrequencyMemoryConfig,
  FrequencyTrackerConfig,
} from "./types/frequency.js";

export { DEFAULT_FREQUENCY_CONFIG, DEFAULT_MEMORY_CONFIG } from "./types/frequency.js";

export type {
  // Profiles (v0.3)
  BuiltInProfileId,
  SchemaStrictness,
  SchemaStrictnessConfig,
  SyntacticEmphasis,
  ContextProfile,
  CustomProfileDefinition,
  ResolvedProfile,
} from "./types/profiles.js";

export { BUILTIN_PROFILES } from "./profiles/builtin.js";

export type {
  // Validation (v0.3)
  SyntacticFilterConfig,
  SyntacticFilterResult,
  SchemaValidationResult,
  PreFilterResult,
  TwoPassConfig,
} from "./types/validation.js";

export { DEFAULT_SYNTACTIC_CONFIG, DEFAULT_HARD_BLOCK_RULES } from "./types/validation.js";
export { SYNTACTIC_RULES, SYNTACTIC_RULE_TAXONOMY } from "./validation/index.js";

export type {
  // Audit (v0.4)
  AuditEventType,
  AuditEvent,
  AuditEmitterConfig,
  TypedAuditEvent,
  ScanAuditEvent,
  SyntacticAuditEvent,
  FrequencyAuditEvent,
  SanitizeAuditEvent,
  ProfileAuditEvent,
  AuditConfigEvent,
  FlagsSummaryEvent,
  RuleTriggeredEvent,
  OutputDiffEvent,
  RawCaptureEvent,
} from "./types/audit.js";

export {
  EVENT_MIN_VERBOSITY,
  meetsVerbosity,
  DEFAULT_AUDIT_CONFIG,
} from "./types/audit.js";

export type {
  // Alerting (v0.5)
  AlertSeverity,
  AlertPayload,
  AlertRuleId,
  AlertRuleConfigs,
  AlertManagerConfig,
} from "./types/alerting.js";

export {
  ALERT_SEVERITY_RANK,
  DEFAULT_ALERT_RULES,
  DEFAULT_ALERT_CONFIG,
} from "./types/alerting.js";

export type {
  // Pipeline (v0.2+)
  TrustTier,
  PipelineInput,
  PipelineResult,
  DrawbridgePipelineConfig,
} from "./types/pipeline.js";
