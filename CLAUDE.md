# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Drawbridge is a session-aware content sanitization pipeline for AI agents. It wraps ClawMoat (prompt injection + PII scanner) with syntactic pre-filtering, exponential-decay frequency tracking, escalation tiers, content redaction, context-aware profiles, audit trails, and alerting. Published on npm as `@vigil-harbor/clawmoat-drawbridge` (v1.2.0). An OpenClaw plugin is available at `extensions/drawbridge/`.

## Build & Run

```bash
npm install
npm run build          # tsc → dist/
npm test               # vitest run
npm run test:watch     # vitest (watch mode)
npm run typecheck      # tsc --noEmit
```

### OpenClaw plugin (extensions/drawbridge/)

```bash
cd extensions/drawbridge
npm install
npm run build
npm test
```

## Architecture

### Two packages in one repo

- **Root (`src/`)** — standalone npm library (`@vigil-harbor/clawmoat-drawbridge`). Core pipeline, scanner, frequency tracker, profiles, audit, alerting, sanitization.
- **Plugin (`extensions/drawbridge/`)** — OpenClaw plugin (`@vigil-harbor/openclaw-drawbridge`). Hook-only integration: message_received, before_dispatch, message_sending, llm_output, tool_result_persist, gateway_stop.

### Pipeline flow (DrawbridgePipeline.inspect)

```
Trust check → Syntactic pre-filter (17 rules, NFKC normalized)
→ Frequency update → Two-pass gate → Schema validation (MCP)
→ Scanner (ClawMoat) → Frequency update → Sanitize (redact)
→ Audit events → Alert evaluation → PipelineResult
```

### Key modules

- `src/pipeline/index.ts` (~600 lines) — full orchestration
- `src/validation/index.ts` (~490 lines) — PreFilter + SchemaValidator
- `src/alerting/index.ts` (~450 lines) — AlertManager
- `src/frequency/index.ts` (~400 lines) — FrequencyTracker
- `extensions/drawbridge/src/hooks/tool-error-enricher.ts` (~350 lines) — MCP tool error recovery

### Frequency & escalation

Per-session exponential decay scoring (half-life 60s) + rolling window counters:
- Tier 1 (>10): forced deep inspection
- Tier 2 (>20): enhanced scrutiny
- Tier 3 (>35): session termination (cannot be disabled)

### Profiles

5 built-in: general, customer-service, code-generation, research, admin. Custom profiles supported via ProfileResolver.

## Key Conventions

- **TypeScript ESM** — `"type": "module"`, `moduleResolution: "NodeNext"`, `.js` extensions in imports
- **ClawMoat is an optional peer dep** — fail-open if missing; syntactic pre-filter still runs
- **Pipeline never throws** — all errors caught and returned in PipelineResult
- **Frozen exports** — built-in profiles, syntactic rules, and default configs are deepFrozen
- **602+ tests** — core library (424) + plugin (178). Run both before publishing.
- **HMAC-SHA256 for redaction hashing** — opt-in via `hashRedactions: true`

## Wiki

The Vigil Harbor wiki lives at `C:\Users\zioni\Documents\Vigil-Harbor\vigil-harbor-wiki`.
Read `SCHEMA.md` for conventions and maintenance rules.

Before starting implementation:
1. Read `index.md` to orient.
2. Read `projects/drawbridge/architecture.md` and `projects/drawbridge/state.md`.
3. Read `projects/drawbridge/filemap.md` before modifying files.

After completing work:
1. Update filemap and state for Drawbridge.
2. Create a `decisions/` entry for any non-obvious judgment calls.
3. Append to `log.md`.
