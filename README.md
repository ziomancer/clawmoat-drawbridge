<p align="center">
  <img src="./drawbridge-logo.svg" width="500" alt="Drawbridge Logo">
</p>

<p align="center">
  Session-aware content sanitization pipeline powered by <a href="https://github.com/darfaz/clawmoat">ClawMoat</a>.<br>
  Standalone library — wire into any agent pipeline. 424 library tests + 68 plugin tests, security-hardened.
</p>

---

## What Drawbridge Does

ClawMoat detects threats in a single scan. Drawbridge wraps it in a session-aware pipeline: threshold-based blocking, syntactic pre-filtering, exponential-decay frequency tracking with three escalation tiers, content redaction, deployment-specific context profiles, structured audit trails, and cross-session alert rules.

Every module is standalone. Use them individually or wire them together.

## Install

```bash
npm install @vigil-harbor/clawmoat-drawbridge clawmoat
```

## Modules

### Scanner

Wraps ClawMoat with threshold filtering, direction-aware scanning (inbound/outbound/both), and a finding callback for observability.

<details>
<summary>Usage</summary>

```ts
import { DrawbridgeScanner } from "@vigil-harbor/clawmoat-drawbridge";

const scanner = new DrawbridgeScanner({
  blockThreshold: "medium",
  direction: "inbound",
});

const result = scanner.scan("some user input");
if (!result.safe) {
  console.log("Blocked:", result.blockingFindings);
}
```
</details>

### Syntactic Pre-Filter

Pure-function pattern matching — catches injection phrases, structural anomalies, encoding tricks. 17-rule frozen taxonomy with NFKC normalization, zero-width character stripping, and extended homoglyph detection. No model calls, sub-millisecond.

<details>
<summary>Usage</summary>

```ts
import { PreFilter } from "@vigil-harbor/clawmoat-drawbridge";

const filter = new PreFilter();
const result = filter.run(content);
if (!result.pass) {
  console.log("Blocked by rules:", result.ruleIds);
}
```
</details>

### Frequency Tracker

Per-session exponential-decay suspicion scoring with rolling window counter. Findings accumulate, scores decay over time. Three escalation tiers: forced deep inspection → enhanced scrutiny → session termination. Rolling counter prevents low-and-slow evasion of exponential decay. Session creation rate-limited at capacity to prevent flood-eviction attacks.

<details>
<summary>Usage</summary>

```ts
import { FrequencyTracker } from "@vigil-harbor/clawmoat-drawbridge";

const tracker = new FrequencyTracker();
const result = tracker.update(sessionId, scanResult.findings.map(f => f.ruleId));
if (result.terminated) {
  // Session killed — tier3 exceeded
}
```
</details>

### Content Sanitize

Position-based redaction with overlap merging. Strips or replaces matched content from scanner findings. Configurable placeholders, blocked-only or redact-all modes. Optional HMAC-SHA256 content hashing for redaction audit trails (no bare SHA-256 ever emitted).

<details>
<summary>Usage</summary>

```ts
const { sanitized, safe } = scanner.scanAndSanitize(content);
// sanitized.sanitized → redacted content
// sanitized.redactionCount → number of replacements

// With HMAC hashing for audit correlation:
const result = sanitizeContent(content, findings, {
  hashRedactions: true,
  hmacKey: process.env.REDACTION_HMAC_KEY,
});
// result.redactions[0].contentHash → HMAC-SHA256 hex string
```
</details>

### Context Profiles

Deployment-specific tuning. Five built-in profiles (general, customer-service, code-generation, research, admin) that adjust pre-filter emphasis and frequency thresholds. Custom profiles supported.

<details>
<summary>Usage</summary>

```ts
import { ProfileResolver, PreFilter, FrequencyTracker } from "@vigil-harbor/clawmoat-drawbridge";

const profile = new ProfileResolver("admin");
const filter = new PreFilter(profile.applySyntacticConfig());
const tracker = new FrequencyTracker(profile.applyFrequencyConfig());
// Admin: lower escalation thresholds, stricter frequency weights
```
</details>

### Audit Emitter

Structured event emission gated by four verbosity tiers (minimal → standard → high → maximum). Callback-based — no file I/O, no opinions on storage.

<details>
<summary>Usage</summary>

```ts
import { AuditEmitter } from "@vigil-harbor/clawmoat-drawbridge";

const audit = new AuditEmitter({
  verbosity: "standard",
  onEvent: (event) => myLogger.write(event),
});
```
</details>

### Alert Manager

Evaluates audit events against configurable rules. Cross-session burst detection, frequency escalation alerts, scanner/pre-filter correlation. Critical alerts exempt from rate limiting. Config validated at construction. Tier 3 alerts cannot be disabled.

<details>
<summary>Usage</summary>

```ts
import { AlertManager, AuditEmitter } from "@vigil-harbor/clawmoat-drawbridge";

const alerts = new AlertManager({
  onAlert: (alert) => pagerduty.send(alert),
});

const audit = new AuditEmitter({
  onEvent: (event) => {
    myLogger.write(event);
    alerts.evaluate(event);
  },
});
```
</details>

### Schema Validator

Validates MCP tool output against registered schemas with discriminated union support. Colon-namespaced keys (`serverName:toolName`), prototype-pollution-safe field checks, and fail-closed defaults. Runs as a standalone module or wired into the pipeline.

<details>
<summary>Usage</summary>

```ts
import { SchemaValidator } from "@vigil-harbor/clawmoat-drawbridge";

const validator = new SchemaValidator({
  enabled: true,
  toolSchemas: {
    "my-server:my-tool": {
      discriminant: "type",
      variants: {
        success: { required: ["data"], fields: { data: "string" } },
        error: { required: ["message"], fields: { message: "string" } },
      },
    },
  },
});

const result = validator.validate(toolOutput, "my-server", "my-tool");
if (!result.pass) {
  console.log("Schema violations:", result.violations);
}
```
</details>

### Pipeline (v1.1)

Single `inspect()` call that orchestrates every stage: trust check, pre-filter, schema validation, two-pass gate, scanner, frequency tracking, sanitize, audit emission, and alert evaluation. Returns a unified `PipelineResult` with safety verdict, redacted content, audit events, and alerts.

- **Trust tier routing** — trusted MCP servers bypass inspection (schema validation still runs)
- **Schema validation** — MCP tool outputs validated against registered schemas; hard-blocked content skips schema
- **Two-pass gating** — hard-block pre-filter rules skip the scanner; prior session suspicion can force the scanner back on
- **HMAC redaction hashing** — opt-in keyed hashes on redacted content for audit correlation (no bare SHA-256)
- **Terminated session fast-path** — tier3 sessions are blocked immediately without re-inspection
- **Profile-driven tuning** — profile applied at construction, tunes pre-filter and frequency tracker
- **Trusted tool alerts** — `trustedToolSchemaFail` fires high-severity alerts when trusted servers emit malformed output
- **Input normalization** — NFKC normalization, zero-width stripping, homoglyph mapping applied before pattern matching
- **Validation hooks** — `validateSessionId` and `validateServerName` callbacks for transport-layer identity verification
- **Module accessors** — `scannerModule`, `frequencyModule`, `resolvedProfile`, etc. for fine-grained control

<details>
<summary>Usage</summary>

```ts
import { DrawbridgePipeline } from "@vigil-harbor/clawmoat-drawbridge";

const pipeline = new DrawbridgePipeline({
  profile: "admin",
  trustedServers: ["local-filesystem"],
  twoPass: { enabled: true },
  schema: {
    enabled: true,
    toolSchemas: { "my-server:my-tool": myToolSchema },
  },
  sanitize: {
    hashRedactions: true,
    hmacKey: process.env.REDACTION_HMAC_KEY,
  },
  audit: {
    verbosity: "high",
    onEvent: (event) => console.log(JSON.stringify(event)),
  },
  alerting: {
    onAlert: (alert) => sendToSlack(alert),
  },
  // Transport-layer identity verification (recommended)
  validateServerName: (name) => verifiedMcpServers.has(name),
  validateSessionId: (id) => sessionStore.has(id),
});

const result = pipeline.inspect({
  content: userInput,
  source: "transcript",
  sessionId: "session-123",
  messageId: "msg-456",
});

if (!result.safe) {
  console.log("Blocked:", result.scanResult?.blockingFindings);
  console.log("Sanitized:", result.sanitizedContent);
}

if (result.terminated) {
  // Session killed — drop the connection
}
```
</details>

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           DrawbridgePipeline        │
                    │            inspect(input)           │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │         Trust Check                 │
                    │   trusted server? → fast-path exit  │
                    │   (schema validation still runs)    │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │     Syntactic Pre-Filter            │
                    │   regex patterns, structural checks │──── findings  ────┐
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐                   │
                    │      Two-Pass Gate                  │                   │
                    │  hard block? skip scanner + schema  │                   │
                    │  (frequency override can force it)  │                   │
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐                   │
                    │   Schema Validator (MCP only)       │                   │
                    │   discriminated unions, field types  │                   │
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐                   │
                    │     Scanner (ClawMoat)              │                   │
                    │   prompt injection, PII, secrets    │──── findings  ────┤
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐    ┌─────────────▼──────────┐
                    │         Sanitize                    │    │  Frequency Tracker      │
                    │   redact blocked content            │    │  decay scoring, tiers   │
                    │   (HMAC hashing opt-in)             │    └─────────────────────────┘
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       Audit Emitter                 │
                    │  verbosity-gated structured events  │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       Alert Manager                 │
                    │  rules → onAlert callback           │
                    │  (trustedToolSchemaFail alert)      │
                    └─────────────────────────────────────┘
```

All modules are standalone — use individually or together. Context profiles tune the pre-filter and frequency tracker at construction time. Callback-based delivery throughout: no file I/O, no network calls.

## Module Status

| Module | Version | Tests | Status |
|--------|---------|-------|--------|
| Scanner | v0.1 | 20 | ✅ Implemented + audited |
| Frequency Tracker | v1.1 | 34 | ✅ Rolling window, eviction hardening |
| Pre-Filter | v1.1 | 47 | ✅ NFKC normalization, 17-rule taxonomy |
| Normalization | v1.1 | 29 | ✅ Zero-width, homoglyph, RTL detection |
| Schema Validator | v1.1 | 17 | ✅ Implemented + hardened |
| Profiles | v1.1 | 24 | ✅ Deep-frozen resolved profiles |
| Sanitize | v1.1 | 38 | ✅ HMAC hashing, overlap merge |
| Audit Emitter | v1.1 | 41 | ✅ Config validation, verbosity gating |
| Alert Manager | v1.1 | 38 | ✅ Critical exempt, error boundary |
| Security Audit | — | 45 | ✅ 20 findings, all addressed |
| Pipeline | v1.1 | 62 | ✅ Validation hooks, defensive copies |
| Hardening Tests | — | 25 | ✅ Pass 3 coverage |
| OpenClaw Plugin | v1.0 | 69 | ✅ Hook-only, fail-open, scan cache |

## Security

Adversarial security review completed across all modules. 20 findings identified and addressed across three hardening passes.

### Original audit (v1.0)

| ID | Severity | Description |
|----|----------|-------------|
| S1.4 | Critical | `isSeverity` prototype chain bypass — block threshold evasion |
| S6.1 | High | Audit emitter spread order — timestamp and event type forgery |
| S1.3 | Medium | `normalizeRuleId` namespace collision with reserved prefixes |
| S1.6 | Medium | `onFinding` callback exceptions broke scan loop |
| S5.1 | Medium | Out-of-bounds position produced phantom redactions |
| X3a | Medium | `SYNTACTIC_RULES` shallow freeze — nested arrays mutable |
| X3b | Medium | `EVENT_MIN_VERBOSITY` not frozen |

### v1.1 Hardening

**Schema & HMAC (pre-audit)**
- HMAC-SHA256 redaction hashing (no bare SHA-256), prototype pollution guards, schema key namespace validation, deep-cloned toolSchemas, double-violation prevention, schema skipped on hard-blocked content, `safe` vs `schemaResult.pass` semantic separation

**Pass 1 — Input normalization** (Findings #1-4)
- NFKC normalization before all injection pattern matching
- Zero-width character stripping with escalation when combined with injection patterns
- Extended homoglyph map (Greek, Latin Extended)
- RTL override detection

**Pass 2 — Defensive copies & immutable exports** (Findings #11-13, #17)
- Spread-copy config arrays in pipeline constructor
- `deepFreeze` / `Object.freeze` on all exported constants
- Frozen resolved profile properties

**Pass 3 — Alerting & frequency hardening** (Findings #6-10, #15, #18-19)
- Config validation at construction (audit verbosity, alert manager params)
- Critical alerts exempt from rate limiting
- `evaluate()` error boundary — never throws on malformed events
- Rolling window counter prevents low-and-slow evasion of exponential decay
- Session creation rate-limited at capacity; terminated sessions evicted first
- `validateSessionId` / `validateServerName` hooks for transport-layer verification

Tier 3 frequency alerts cannot be disabled — the constructor enforces `tier3Enabled: true` regardless of consumer config.

### Security Considerations

`sessionId` and `serverName` in `PipelineInput` are caller-provided and unvalidated by default:

- **sessionId** must be derived from authenticated transport state (e.g., server-signed session token). If sourced from client input, attackers can poison other sessions' frequency scores. Configure `validateSessionId` for runtime enforcement.
- **serverName** must be verified at the transport layer (e.g., mTLS, signed tokens). If sourced from message content, attackers can spoof trusted servers to bypass all inspection. Configure `validateServerName` for runtime enforcement.

See `DrawbridgePipelineConfig` for the validation callback signatures.

## License

MIT — Built by [Vigil Harbor, LLC](https://vigilharbor.com)
