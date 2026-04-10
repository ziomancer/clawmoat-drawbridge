# Changelog

All notable changes to Drawbridge are documented here. Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] — 2026-04-09

### Added
- **Tool error enricher** — three-hook system that intercepts MCP tool failures, classifies by category/severity, and appends structured recovery guidance to the LLM context window
- Circuit breaker blocking tool calls after 3 consecutive failures per tool
- Three-layer template cascade: tool-specific > category > global fallback
- Sensitive parameter redaction and 800-char enrichment cap
- Tool name normalization for OpenClaw MCP server prefixes
- Counter compensation in `tool_result_persist` for content-based error detection
- 178 extension tests (was 68)

### Fixed
- Migrated all hook registrations from legacy `api.registerHook()` to typed `api.on()` — hooks were registered but never dispatched in live runtime
- Changed `gateway:stop` hook name to `gateway_stop` (typed hook system uses underscores)
- Added `EAI_AGAIN` to server_unreachable error pattern
- Synchronous handler invariant: `tool_result_persist` no longer returns a Promise

## [1.1.1] — 2026-04-02

### Fixed
- Use optional chaining in catch blocks to handle null/undefined errors
- Freeze shared `PASS` constants and `SYNTACTIC_RULE_TAXONOMY` to prevent mutation
- Snapshot validator callbacks and `deriveSessionId` signature
- Shallow config merge (now deep-merges nested config objects)
- Widen prefilter perf test threshold for CI runners
- Truncate long error messages in logs
- Changelog tier 1 typo and finding count

### Added
- OpenClaw Drawbridge plugin with 68 tests (`extensions/drawbridge`)
- Shared `FrequencyTracker` injection and thresholds getter
- ClawMoat resolution error logging and cache-miss re-scan docs
- CI release workflow for automated npm publishing via GitHub Releases

## [1.1.0] — 2026-03-28

### Security Hardening — Pass 1: Input Normalization

Fixes findings #1-4 from the adversarial security review (unicode/encoding bypass vectors).

#### Added
- `src/validation/normalize.ts` — dedicated normalization module for security pattern detection
- NFKC normalization applied before all injection and role-switch pattern matching
- Zero-width character stripping (U+200B-U+200F, U+FEFF, U+00AD, U+2060, U+2062-U+2064, U+180E)
- Null byte stripping (U+0000)
- Extended homoglyph map: Greek letters (alpha, epsilon, omicron, rho, kappa, iota, nu), Latin Extended (dotless i)
- RTL override character detection (U+202A-U+202E, U+2066-U+2069)
- Two new encoding rules: `invisible-chars`, `rtl-override` (taxonomy now 17 rules)
- Escalation logic: invisible chars + injection pattern match promotes encoding flag to fail, even when injection rule is profile-suppressed
- 29 unit tests for normalization, 12 bypass integration tests

#### Changed
- Injection and role-switch pattern matching now operates on NFKC-normalized content
- Structural checks (base64, length) still use raw content
- `null-byte` rule ID renamed to `invisible-chars` (broader scope)
- U+2028/U+2029 (line/paragraph separators) deliberately excluded from stripping to preserve `^SYSTEM:` multiline regex detection

#### Removed
- Old `normalizeHomoglyphs()` and `contentHasHomoglyphs()` functions (replaced by `normalizeForDetection()`)

### Security Hardening — Pass 2: Defensive Copies & Immutable Exports

Fixes findings #11 (mutable trustedServers), #12 (mutable hardBlockRules), #13 (mutable exported constants), #17 (unfrozen frequencyWeightOverrides).

#### Added
- `deepFreeze()` utility in `src/types/common.ts` for recursive object freezing
- 4 mutation resistance tests in `src/pipeline/__tests__/mutation.test.ts`

#### Changed
- Pipeline constructor: `trustedServers` and `hardBlockRules` are now spread-copied from config (prevents post-construction mutation)
- All exported constant objects/arrays frozen at module level: `SEVERITY_RANK`, `ALERT_SEVERITY_RANK`, `DEFAULT_SYNTACTIC_CONFIG`, `DEFAULT_FREQUENCY_CONFIG`, `DEFAULT_MEMORY_CONFIG`, `DEFAULT_SANITIZE_CONFIG`, `DEFAULT_AUDIT_CONFIG`, `DEFAULT_ALERT_RULES`, `DEFAULT_ALERT_CONFIG`, `DEFAULT_SCHEMA_CONFIG`, `DEFAULT_HARD_BLOCK_RULES`
- `ProfileResolver`: `frequencyWeightOverrides` now frozen on resolved profile

### Security Hardening — Pass 3: Alerting & Frequency Hardening

Fixes findings #6 (low-and-slow evasion), #7 (session eviction weaponization), #8 (session ID poisoning), #9 (trust bypass via serverName), #10 (rate limiting suppresses critical alerts), #15 (evaluate() throws), #18 (invalid verbosity disables audit), #19 (AlertManager config not validated).

#### Added
- **Config validation:** `AuditEmitter` rejects invalid verbosity strings; `AlertManager` validates `suppressionWindowMinutes`, rate limit values, and `recentContextMax` at construction
- **Rolling window counter:** New `rollingWindowMs` and `rollingThreshold` config on `FrequencyConfig`. Tracks non-decaying finding count per session. Forces at least tier 1 escalation when threshold met, preventing low-and-slow evasion of exponential decay
- **Session creation rate limiting:** New `maxNewSessionsPerMinute` on `FrequencyMemoryConfig`. Enforced when sessions are at capacity to prevent flood-eviction attacks
- **Terminated-first eviction:** Session eviction now prefers terminated sessions over active ones
- **Validation hooks:** `validateSessionId` and `validateServerName` callbacks on `DrawbridgePipelineConfig`. SessionId validation gates frequency tracking; serverName validation gates trust resolution
- **JSDoc `@security` warnings** on `PipelineInput.sessionId` and `PipelineInput.serverName`
- 25 hardening tests in `src/__tests__/pass3-hardening.test.ts`

#### Changed
- **Critical alert exemption:** Critical-severity alerts are never rate-limited. Prevents low-severity noise from silencing critical alerts
- **Error boundary:** `AlertManager.evaluate()` wrapped in top-level try/catch — never throws on malformed events, returns null
- Exported `VERBOSITY_RANK` from `src/types/audit.ts` (was private, needed for config validation)

## [1.1.0-pre] — Prior v1.1 changes

### Added
- Schema validation pipeline stage (discriminated unions, field type checks)
- HMAC-SHA256 redaction hashing (replaces bare SHA-256)
- Prototype pollution guards on schema validation (`Object.hasOwn()`)
- Schema key namespace validation (colon guards, empty-component rejection)
- `trustedToolSchemaFail` alert rule
- Two-pass gate: hard-blocked content skips schema validation
- `safe` vs `schemaResult.pass` semantic separation

### Fixed
- `isSeverity` prototype chain bypass (S1.4 — critical)
- Audit emitter spread order allowing timestamp/event forgery (S6.1 — high)
- `normalizeRuleId` namespace collision (S1.3 — medium)
- `onFinding` callback exceptions breaking scan loop (S1.6 — medium)
- Out-of-bounds position producing phantom redactions (S5.1 — medium)
- `SYNTACTIC_RULES` shallow freeze leaving nested arrays mutable (X3a — medium)
- `EVENT_MIN_VERBOSITY` not frozen (X3b — medium)

## [1.0.0] — Initial release

Full pipeline orchestration: trust check, syntactic pre-filter, frequency tracking, scanner integration, content sanitization, audit emission, alert evaluation. Five built-in context profiles, callback-based delivery throughout.
