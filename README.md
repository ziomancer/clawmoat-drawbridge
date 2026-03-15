<p align="center">
  <img src="./drawbridge-logo.svg" width="500" alt="Drawbridge Logo">
</p>

Session-aware content sanitization pipeline powered by [ClawMoat](https://github.com/darfaz/clawmoat).
Standalone library — wire into any agent pipeline. 253 tests, security-audited.

## What Drawbridge Does

ClawMoat detects threats in a single scan. Drawbridge adds the session layer:

- **Threshold-based blocking** — tune what severity level triggers a block
- **Direction-aware scanning** — inspect inbound, outbound, or both
- **Syntactic pre-filter** — fast regex-based detection of injection patterns, structural anomalies, encoding tricks
- **Session frequency tracking** — exponential-decay suspicion scores with three escalation tiers
- **Content sanitization** — position-based redaction with overlap merging
- **Context profiles** — deployment-specific tuning (customer-service, code-generation, research, admin)
- **Structured audit trail** — verbosity-gated event emission with callback delivery
- **Alert rules** — cross-session burst detection, frequency escalation alerts, syntactic/scanner correlation

## Install

```bash
npm install @ziomancer/clawmoat-drawbridge clawmoat
```

## Quick Start

### Scanner

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

### Scan + Sanitize

```ts
const { sanitized, safe } = scanner.scanAndSanitize(content);
// sanitized.sanitized contains redacted content
```

### Syntactic Pre-Filter

```ts
import { PreFilter } from "@ziomancer/clawmoat-drawbridge";

const filter = new PreFilter({ maxPayloadBytes: 524_288, maxJsonDepth: 10 });
const result = filter.run(content);

if (!result.pass) {
  console.log("Blocked by rules:", result.ruleIds);
}
```

### Session Frequency Tracking

```ts
import { FrequencyTracker } from "@ziomancer/clawmoat-drawbridge";

const tracker = new FrequencyTracker();
const freq = tracker.update(sessionId, scanResult.findings.map(f => f.ruleId));

if (freq.terminated) {
  // Session exceeded tier3 — terminate
}
```

### Context Profiles

```ts
import { ProfileResolver, PreFilter, FrequencyTracker } from "@ziomancer/clawmoat-drawbridge";

const profile = new ProfileResolver("admin");
const filter = new PreFilter(profile.applySyntacticConfig());
const tracker = new FrequencyTracker(profile.applyFrequencyConfig());
```

### Audit Trail

```ts
import { AuditEmitter } from "@ziomancer/clawmoat-drawbridge";

const audit = new AuditEmitter({
  verbosity: "standard",
  onEvent: (event) => myLogger.write(event),
});

audit.emitScan({ sessionId, safe: result.safe, findingCount: result.findings.length, blockingFindingCount: result.blockingFindings.length, ruleIds: result.findings.map(f => f.ruleId) });
```

### Alert Rules

```ts
import { AlertManager } from "@ziomancer/clawmoat-drawbridge";

const alerts = new AlertManager({
  onAlert: (alert) => pagerduty.send(alert),
});

// Feed audit events into the alert manager
audit = new AuditEmitter({
  onEvent: (event) => {
    myLogger.write(event);
    alerts.evaluate(event);
  },
});
```

## Scanner Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `blockThreshold` | `"low" \| "medium" \| "high" \| "critical"` | `"low"` | Minimum severity to trigger a block |
| `direction` | `"inbound" \| "outbound" \| "both"` | `"inbound"` | Which scan direction to evaluate |
| `onFinding` | `(finding) => void` | — | Callback fired for each finding (exception-safe) |

## Architecture

```
Content → PreFilter → Scanner → FrequencyTracker → Sanitize
              ↓           ↓            ↓               ↓
           AuditEmitter ← ← ← ← ← ← ← ← ← ← ← ← ← ←
              ↓
         AlertManager → onAlert callback
```

All modules are standalone — use them individually or wire together via the pipeline (v1.0).
Callback-based delivery throughout: no file I/O, no network calls. The consumer decides where events and alerts go.

## Module Status

| Module | Version | Tests | Status |
|--------|---------|-------|--------|
| Scanner | v0.1 | 18 | Implemented + security-audited |
| Frequency Tracker | v0.2 | 32 | Implemented + security-audited |
| Pre-Filter | v0.3 | 35 | Implemented + security-audited |
| Profiles | v0.3 | 24 | Implemented + security-audited |
| Sanitize | v0.3 | 20 | Implemented + security-audited |
| Audit Emitter | v0.4 | 41 | Implemented + security-audited |
| Alert Manager | v0.5 | 38 | Implemented + security-audited |
| Security Audit | — | 45 | 7 bugs found and fixed |
| Pipeline | v1.0 | — | Next |

## Security

Security audit completed across all modules (v0.1–v0.5). 7 vulnerabilities found and fixed:

- **S1.4** (Critical) — `isSeverity` prototype chain bypass allowed block threshold evasion
- **S6.1** (High) — Audit emitter spread order allowed timestamp and event type forgery
- **S1.3** — `normalizeRuleId` namespace collision with reserved prefixes
- **S1.6** — `onFinding` callback exceptions broke scan loop
- **S5.1** — Out-of-bounds position in sanitize produced phantom redactions
- **X3** — Shallow freeze on `SYNTACTIC_RULES`; missing freeze on `EVENT_MIN_VERBOSITY`

Tier 3 frequency alerts cannot be disabled — the constructor enforces `tier3Enabled: true` regardless of consumer config.

## License

MIT — Built by [Vigil Harbor, LLC](https://vigilharbor.com)
