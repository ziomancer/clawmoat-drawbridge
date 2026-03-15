<p align="center">
  <img src="./drawbridge-logo.svg" width="500" alt="Drawbridge Logo">
</p>

<p align="center">
  Session-aware content sanitization pipeline powered by <a href="https://github.com/darfaz/clawmoat">ClawMoat</a>.<br>
  Standalone library — wire into any agent pipeline. 295 tests, security-audited.
</p>

---

## What Drawbridge Does

ClawMoat detects threats in a single scan. Drawbridge wraps it in a session-aware pipeline: threshold-based blocking, syntactic pre-filtering, exponential-decay frequency tracking with three escalation tiers, content redaction, deployment-specific context profiles, structured audit trails, and cross-session alert rules.

Every module is standalone. Use them individually or wire them together.

## Install

```bash
npm install @ziomancer/clawmoat-drawbridge clawmoat
```

## Modules

### Scanner

Wraps ClawMoat with threshold filtering, direction-aware scanning (inbound/outbound/both), and a finding callback for observability.

<details>
<summary>Usage</summary>

```ts
import { DrawbridgeScanner } from "@ziomancer/clawmoat-drawbridge";

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

Pure-function pattern matching — catches injection phrases, structural anomalies, encoding tricks. 16-rule frozen taxonomy. No model calls, sub-millisecond.

<details>
<summary>Usage</summary>

```ts
import { PreFilter } from "@ziomancer/clawmoat-drawbridge";

const filter = new PreFilter();
const result = filter.run(content);
if (!result.pass) {
  console.log("Blocked by rules:", result.ruleIds);
}
```
</details>

### Frequency Tracker

Per-session exponential-decay suspicion scoring. Findings accumulate, scores decay over time. Three escalation tiers: forced deep inspection → enhanced scrutiny → session termination.

<details>
<summary>Usage</summary>

```ts
import { FrequencyTracker } from "@ziomancer/clawmoat-drawbridge";

const tracker = new FrequencyTracker();
const result = tracker.update(sessionId, scanResult.findings.map(f => f.ruleId));
if (result.terminated) {
  // Session killed — tier3 exceeded
}
```
</details>

### Content Sanitize

Position-based redaction with overlap merging. Strips or replaces matched content from scanner findings. Configurable placeholders, blocked-only or redact-all modes.

<details>
<summary>Usage</summary>

```ts
const { sanitized, safe } = scanner.scanAndSanitize(content);
// sanitized.sanitized → redacted content
// sanitized.redactionCount → number of replacements
```
</details>

### Context Profiles

Deployment-specific tuning. Five built-in profiles (general, customer-service, code-generation, research, admin) that adjust pre-filter emphasis and frequency thresholds. Custom profiles supported.

<details>
<summary>Usage</summary>

```ts
import { ProfileResolver, PreFilter, FrequencyTracker } from "@ziomancer/clawmoat-drawbridge";

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
import { AuditEmitter } from "@ziomancer/clawmoat-drawbridge";

const audit = new AuditEmitter({
  verbosity: "standard",
  onEvent: (event) => myLogger.write(event),
});
```
</details>

### Alert Manager

Evaluates audit events against configurable rules. Cross-session burst detection, frequency escalation alerts, scanner/pre-filter correlation. Tier 3 alerts cannot be disabled.

<details>
<summary>Usage</summary>

```ts
import { AlertManager, AuditEmitter } from "@ziomancer/clawmoat-drawbridge";

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

### Pipeline (v1.0)

Single `inspect()` call that orchestrates every stage: trust check, pre-filter, two-pass gate, scanner, frequency tracking, sanitize, audit emission, and alert evaluation. Returns a unified `PipelineResult` with safety verdict, redacted content, audit events, and alerts.

- **Trust tier routing** — trusted MCP servers bypass inspection entirely
- **Two-pass gating** — hard-block pre-filter rules skip the scanner; prior session suspicion can force the scanner back on
- **Terminated session fast-path** — tier3 sessions are blocked immediately without re-inspection
- **Profile-driven tuning** — profile applied at construction, tunes pre-filter and frequency tracker
- **Construction event storage** — `profile_loaded` and `audit_config_loaded` events prepended to the first `inspect()` result
- **Module accessors** — `scannerModule`, `frequencyModule`, `resolvedProfile`, etc. for fine-grained control

<details>
<summary>Usage</summary>

```ts
import { DrawbridgePipeline } from "@ziomancer/clawmoat-drawbridge";

const pipeline = new DrawbridgePipeline({
  profile: "admin",
  trustedServers: ["local-filesystem"],
  twoPass: { enabled: true },
  audit: {
    verbosity: "high",
    onEvent: (event) => console.log(JSON.stringify(event)),
  },
  alerting: {
    onAlert: (alert) => sendToSlack(alert),
  },
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
                    │           DrawbridgePipeline         │
                    │            inspect(input)            │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │         Trust Check                  │
                    │   trusted server? → fast-path exit   │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │     Syntactic Pre-Filter             │
                    │   regex patterns, structural checks  │──── findings ────┐
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐                   │
                    │      Two-Pass Gate                   │                   │
                    │  hard block? skip scanner            │                   │
                    │  (frequency override can force it)   │                   │
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐                   │
                    │     Scanner (ClawMoat)               │                   │
                    │   prompt injection, PII, secrets     │──── findings ────┤
                    └──────────────┬──────────────────────┘                   │
                                   │                                          │
                    ┌──────────────▼──────────────────────┐    ┌─────────────▼──────────┐
                    │         Sanitize                     │    │  Frequency Tracker      │
                    │   redact blocked content             │    │  decay scoring, tiers   │
                    └──────────────┬──────────────────────┘    └─────────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       Audit Emitter                  │
                    │  verbosity-gated structured events   │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       Alert Manager                  │
                    │  rules → onAlert callback            │
                    └─────────────────────────────────────┘
```

All modules are standalone — use individually or together. Context profiles tune the pre-filter and frequency tracker at construction time. Callback-based delivery throughout: no file I/O, no network calls.

## Module Status

| Module | Version | Tests | Status |
|--------|---------|-------|--------|
| Scanner | v0.1 | 18 | ✅ Implemented + audited |
| Frequency Tracker | v0.2 | 32 | ✅ Implemented + audited |
| Pre-Filter | v0.3 | 35 | ✅ Implemented + audited |
| Profiles | v0.3 | 24 | ✅ Implemented + audited |
| Sanitize | v0.3 | 20 | ✅ Implemented + audited |
| Audit Emitter | v0.4 | 41 | ✅ Implemented + audited |
| Alert Manager | v0.5 | 38 | ✅ Implemented + audited |
| Security Audit | — | 45 | ✅ 7 bugs found and fixed |
| Pipeline | v1.0 | 42 | ✅ Implemented |

## Security

Security audit completed across all modules. 7 vulnerabilities found and fixed:

| ID | Severity | Description |
|----|----------|-------------|
| S1.4 | Critical | `isSeverity` prototype chain bypass — block threshold evasion |
| S6.1 | High | Audit emitter spread order — timestamp and event type forgery |
| S1.3 | Medium | `normalizeRuleId` namespace collision with reserved prefixes |
| S1.6 | Medium | `onFinding` callback exceptions broke scan loop |
| S5.1 | Medium | Out-of-bounds position produced phantom redactions |
| X3a | Medium | `SYNTACTIC_RULES` shallow freeze — nested arrays mutable |
| X3b | Medium | `EVENT_MIN_VERBOSITY` not frozen |

Tier 3 frequency alerts cannot be disabled — the constructor enforces `tier3Enabled: true` regardless of consumer config.

## License

MIT — Built by [Vigil Harbor, LLC](https://vigilharbor.com)
