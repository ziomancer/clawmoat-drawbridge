// === Shared primitives (canonical source — also re-exported by individual modules) ===
export type { Severity, AuditVerbosity, ContentSource } from "./types/common.js";
export { SEVERITY_RANK, isSeverity } from "./types/common.js";

// === v0.1 implemented ===
export { DrawbridgeScanner, normalizeRuleId } from "./scanner/index.js";

// === v0.2+ stubs (pipeline modules) ===
export { FrequencyTracker } from "./frequency/index.js";
export { ProfileResolver } from "./profiles/index.js";
export { PreFilter } from "./validation/index.js";
export { AuditEmitter } from "./audit/index.js";
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
} from "./types/scanner.js";

export type {
  // Frequency (v0.2+)
  EscalationTier,
  SessionSuspicionState,
  FrequencyConfig,
  FrequencyUpdateResult,
} from "./types/frequency.js";

export { DEFAULT_FREQUENCY_CONFIG } from "./types/frequency.js";

export type {
  // Profiles (v0.2+)
  BuiltInProfileId,
  SchemaStrictness,
  SchemaStrictnessConfig,
  SyntacticEmphasis,
  ContextProfile,
  CustomProfileDefinition,
} from "./types/profiles.js";

export type {
  // Validation (v0.2+)
  SyntacticFilterResult,
  SchemaValidationResult,
  PreFilterResult,
  TwoPassConfig,
} from "./types/validation.js";

export { DEFAULT_HARD_BLOCK_RULES } from "./types/validation.js";

export type {
  // Audit (v0.2+)
  AuditEventType,
  AuditEvent,
  AuditConfig,
} from "./types/audit.js";

export type {
  // Alerting (v0.2+)
  AlertSeverity,
  AlertPayload,
  AlertChannel,
  WebhookChannelConfig,
  AlertingConfig,
} from "./types/alerting.js";

export type {
  // Pipeline (v0.2+)
  TrustTier,
  PipelineInput,
  PipelineResult,
  DrawbridgePipelineConfig,
} from "./types/pipeline.js";
