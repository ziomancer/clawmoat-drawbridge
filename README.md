# @vigilharbor/clawmoat-drawbridge-sanitizer

Session-aware content sanitization pipeline powered by [ClawMoat](https://github.com/darfaz/clawmoat).
Standalone library — wire into any agent pipeline.

## What Drawbridge Does

ClawMoat detects threats in a single scan. Drawbridge adds:
- **Threshold-based blocking** — tune what severity level triggers a block
- **Direction-aware scanning** — inspect inbound, outbound, or both
- **Session tracking** — accumulate suspicion across turns with escalation (v0.2)
- **Context profiles** — tune behavior per deployment type (v0.2)
- **Structured audit trails** — compliance-ready logging (v0.2)
- **Alert rules** — automated escalation and notification (v0.2)

## Install

```bash
npm install @vigilharbor/clawmoat-drawbridge-sanitizer clawmoat
```

## Quick Start

```ts
import { DrawbridgeScanner } from "@vigilharbor/clawmoat-drawbridge-sanitizer";

const scanner = new DrawbridgeScanner({
  blockThreshold: "medium",
  direction: "inbound",
});

const result = scanner.scan("some user input");

if (!result.safe) {
  console.log("Blocked:", result.blockingFindings);
}
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `blockThreshold` | `"low" \| "medium" \| "high" \| "critical"` | `"low"` | Minimum severity to trigger a block |
| `direction` | `"inbound" \| "outbound" \| "both"` | `"inbound"` | Which scan direction to evaluate |
| `onFinding` | `(finding) => void` | — | Callback fired for each finding |

## Scanning Objects

```ts
// Safely handles circular references
const result = scanner.scanObject({ nested: complexData });
```

## Roadmap

- **v0.1** (current) — Scanner with threshold filtering and direction control
- **v0.2** — Session frequency tracking with escalation tiers
- **v0.3** — Content sanitization (`sanitize()` / redaction), context profiles, and syntactic pre-filtering
- **v0.4** — Structured audit trail with verbosity tiers
- **v0.5** — Alert rules and delivery channels
- **v1.0** — Full pipeline orchestration

## License

MIT — Built by [Vigil Harbor, LLC](https://vigilharbor.com)
