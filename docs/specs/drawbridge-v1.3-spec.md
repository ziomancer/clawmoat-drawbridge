# Drawbridge v1.3 — Tool Call Policy Guard

> Corrected Spec — reviewed against actual codebase by CC
> Status: Ready for CC implementation
> Author: Devin Matthews / Claude
> Date: 2026-04-26

---

## 1. Release Scope

v1.3 ships four items as one release:

| # | Item | Category |
|---|------|----------|
| 1 | **Tool Call Policy Guard** | Headline feature — new pipeline module + OpenClaw hook |
| 2 | **`write_failed` audit event** | Unblocked deferred item — enables Alert Rule 5 |
| 3 | **ClawMoat v0.8.0 compat** | Peer dep bump + expose `evaluateTool` through Drawbridge |
| 4 | **Type stub corrections** | `BeforeToolCallEvent` + `BeforeToolCallContext` widened |

---

## 2. Problem Statement

Drawbridge scans **content** (message text, tool result bodies) but does not gate **actions** (tool invocations). When an LLM calls `exec` with `rm -rf /`, or `write` targeting `/etc/passwd`, or `browser` fetching a phishing URL — nothing stops it. The building blocks exist in isolation:

- **ClawMoat** has `evaluateTool(tool, args)` → `{ decision, reason, severity }`
- **OpenClaw** has `before_tool_call` → `{ block, blockReason }`
- **Drawbridge** has frequency tracking, audit trail, and alert manager

They're not wired together.

---

## 3. Architecture

### 3.1 Where It Lives

The guard is a **new module** in the Drawbridge core library (`src/guard/`) plus a **new hook handler** in the OpenClaw plugin (`extensions/drawbridge/src/hooks/before-tool-call-guard.ts`).

Separation of concerns:

```
src/guard/                        ← Pure logic, no OpenClaw dependency
  index.ts                        ← ToolCallGuard class
  types.ts                        ← Guard-specific types
  __tests__/
    guard.test.ts

extensions/drawbridge/src/hooks/
  before-tool-call-guard.ts       ← OpenClaw hook handler (thin adapter)
```

The guard module is usable standalone (non-OpenClaw consumers can call `ToolCallGuard.evaluate()` directly). The hook handler is a thin adapter that maps OpenClaw's `before_tool_call` event shape to the guard's input and returns `{ block, blockReason }`.

### 3.2 Relationship to Tool Error Enricher

The enricher already registers on `before_tool_call` for **circuit-breaking** (block after N consecutive failures). The guard registers on `before_tool_call` for **security policy** (block dangerous tool calls).

They are separate concerns with separate state:

| | Guard (new) | Enricher (existing) |
|---|---|---|
| Purpose | Security gating | Error recovery |
| State | Needs `PluginState` (pipeline, tracker, ClawMoat) | Independent (`attemptMap` only) |
| Priority | **10** (runs first) | **50** (runs second) |
| Registration | Main plugin `register()` | Enricher factory `registerHooks()` |
| Blocking | Blocks dangerous tools | Blocks failing tools |

If the guard blocks, the enricher never fires (OpenClaw's `{ block: true }` is terminal — stops lower-priority handlers). Clean.

### 3.3 Data Flow

```
before_tool_call(event, ctx)
  │
  ├─ 1. Session check
  │     Is session terminated (tier3)?
  │     → YES: block unconditionally
  │
  ├─ 2. Exemption check
  │     Is tool in exemptTools list?
  │     → YES: skip to audit-only, return { block: false }
  │
  ├─ 3. Parameter content scan (when params present)
  │     Stringify params → pipeline.inspect()
  │     Catches injection embedded in tool arguments
  │     (e.g., prompt injection in a write tool's body)
  │     → Findings feed frequency tracker (shared instance)
  │     ⚠ pipeline.inspect() internally calls tracker.update()
  │       — do NOT manually update the tracker in the guard;
  │       the shared tracker already receives the score delta.
  │
  ├─ 4. ClawMoat policy evaluation
  │     moat.evaluateTool(toolName, params ?? {})
  │     Returns { decision, reason, severity }
  │     Decision mapping:
  │       deny   → block
  │       review → block (no human reviewer in agent pipeline)
  │       warn   → allow (unless escalated, see step 5)
  │       allow  → allow
  │
  ├─ 5. Frequency-aware escalation
  │     If session tier ≥ tier1 AND decision = "warn":
  │       promote to block
  │     If session tier ≥ tier2:
  │       apply restrictedTools allowlist (configurable)
  │       any tool NOT on the allowlist → block
  │
  ├─ 6. Return structured result
  │     Guard returns ToolCallGuardResult with audit metadata.
  │     The CALLER (hook handler) is responsible for:
  │       • emitting tool_policy_block / tool_policy_allow audit events
  │       • feeding audit events to AlertManager
  │     This keeps the guard module free of AuditEmitter/AlertManager coupling.
  │
  └─ Hook handler returns { block, blockReason } to OpenClaw
```

### 3.4 Pipeline Reuse

The parameter content scan (step 3) reuses the **inbound** pipeline instance (`state.inbound`). Rationale:

- Tool params are attacker-influenced content (user input → LLM → tool args). Same trust model as inbound messages.
- Sharing the frequency tracker means injection attempts in tool args escalate the same session as injection in messages. One suspicion score per session, not two.
- The inbound profile's thresholds are appropriate — these are untrusted inputs.

The scan uses `source: "tool_params"` with the `toolName` from the event. The `ContentSource` type is an open union (`(string & {})`), so `"tool_params"` is valid without type changes. This avoids the `"mcp"` source, which would trigger trust resolution and could bypass inspection if `serverName` matched a trusted server entry.

---

## 4. Type Changes

### 4.1 OpenClaw Hook Type Stubs

File: `extensions/drawbridge/src/types/openclaw.ts`

**Before:**
```ts
export interface BeforeToolCallEvent {
  toolName: string;
}

export interface BeforeToolCallContext {
  sessionKey?: string;
}
```

**After:**
```ts
export interface BeforeToolCallEvent {
  toolName: string;
  params?: Record<string, unknown>;
  toolCallId?: string;
}

export interface BeforeToolCallContext {
  sessionKey?: string;
  agentId?: string;
}
```

Rationale: OpenClaw's runtime passes `params` and `toolCallId` in the event and `agentId` in the context. The type stubs were written before these fields were wired up. All new fields are optional — backward-compatible with existing enricher code.

### 4.2 New Audit Event Types

File: `src/types/audit.ts`

Add to `AuditEventType` union:
```ts
// Tool policy events (v1.3)
| "tool_policy_block"
| "tool_policy_allow"
// Write failure event (v1.3 — unblocks Alert Rule 5)
| "write_failed"
```

**Rebuild** `EVENT_MIN_VERBOSITY` as a new frozen object with the additional entries (the existing object is `Object.freeze()`'d and cannot be mutated in place):
```ts
tool_policy_block: "minimal",    // Security-relevant — always emit
tool_policy_allow: "high",       // Verbose — only when debugging
write_failed: "minimal",         // Security-relevant
```

### 4.3 New Typed Audit Events

File: `src/types/audit.ts`

Both interfaces extend `AuditEvent` (matching the pattern used by every existing event type):

```ts
/** Tool policy evaluation result */
import type { EscalationTier } from "../types/frequency.js";

export interface ToolPolicyAuditEvent extends AuditEvent {
  event: "tool_policy_block" | "tool_policy_allow";
  toolName: string;
  /** SHA-256 of stringified params — never log raw params (may contain secrets) */
  paramsHash: string;
  /** ClawMoat decision: allow | deny | warn | review */
  policyDecision: string;
  /** ClawMoat reason string */
  policyReason?: string;
  /** ClawMoat severity */
  policySeverity?: string;
  /** Whether frequency escalation promoted the decision */
  escalationApplied: boolean;
  /** Session tier at time of evaluation — matches ToolCallGuardResult.audit.sessionTier */
  sessionTier: EscalationTier;
  /** Whether parameter content scan found injection */
  paramScanUnsafe: boolean;
  /** Number of findings from parameter content scan */
  paramScanFindingCount: number;
}

/** Write operation failure */
export interface WriteFailedAuditEvent extends AuditEvent {
  event: "write_failed";
  toolName: string;
  /** Distinguishes policy-blocked writes from actual runtime failures */
  cause: "policy_block" | "runtime_error";
  /** Error classification */
  errorCategory: string;
  /** Sanitized error message (truncated, no secrets) */
  errorSummary: string;
}
```

Add both to the `TypedAuditEvent` discriminated union:
```ts
export type TypedAuditEvent =
  | ScanAuditEvent
  | SyntacticAuditEvent
  // ... existing members ...
  | RawCaptureEvent
  | ToolPolicyAuditEvent    // v1.3
  | WriteFailedAuditEvent;  // v1.3
```

### 4.4 New Alert Rule

File: `src/types/alerting.ts`

Add to `AlertRuleId` union:
```ts
| "toolPolicyBlock"
```

Add named property to `AlertRuleConfigs` interface:
```ts
toolPolicyBlock: {
  enabled: boolean;
  /** Minimum blocks to trigger. Default: 1 (any block is noteworthy) */
  count: number;
  /** Time window in minutes. Default: 10 */
  windowMinutes: number;
};
```

**Rebuild** `DEFAULT_ALERT_RULES` as a new frozen object with the additional entry (current object is `deepFreeze()`'d):
```ts
toolPolicyBlock: {
  enabled: true,
  count: 1,
  windowMinutes: 10,
},
```

Likewise rebuild `DEFAULT_ALERT_CONFIG` to include the new rule defaults.

Note: `writeFailSpike` config already exists in `AlertRuleConfigs` and `DEFAULT_ALERT_RULES` — no config changes needed for that rule. The only work is implementing the evaluation logic.

---

## 5. Guard Module — Core Library

### 5.1 ToolCallGuard Class

File: `src/guard/index.ts`

```ts
export class ToolCallGuard {
  /**
   * Dependencies are injected at construction, matching the pattern
   * used by DrawbridgePipeline, DrawbridgeScanner, and all other
   * Drawbridge modules. The guard stores references — it does NOT
   * own these instances (PluginState or the standalone consumer owns them).
   */
  constructor(config: ToolCallGuardConfig);

  /**
   * Evaluate a tool call against security policies.
   *
   * @param input - Tool call details (name, params, session)
   * @returns Guard decision with structured audit metadata
   */
  evaluate(input: ToolCallInput): ToolCallGuardResult;
}
```

### 5.2 Guard Types

File: `src/guard/types.ts`

```ts
import type { EscalationTier } from "../types/frequency.js";
import type { DrawbridgePipeline } from "../pipeline/index.js";
import type { FrequencyTracker } from "../frequency/index.js";

export interface ToolCallInput {
  toolName: string;
  params?: Record<string, unknown>;
  sessionId: string;
  toolCallId?: string;
  agentId?: string;
}

export interface ToolCallGuardConfig {
  /**
   * Inbound pipeline instance for parameter content scanning.
   * The guard calls pipeline.inspect() on stringified params.
   * Injected at construction — same instance as PluginState.inbound.
   */
  pipeline: DrawbridgePipeline;

  /**
   * Shared frequency tracker for session state reads.
   * The guard reads tier via tracker.thresholds + tracker.getState().
   * Injected at construction — same instance as PluginState.tracker.
   */
  tracker: FrequencyTracker;

  /**
   * ClawMoat engine instance for policy evaluation.
   * Duck-typed: must have evaluateTool(tool, args).
   * When absent, guard skips policy evaluation and relies on
   * content scanning + frequency gating only.
   */
  engine?: ClawMoatPolicyEngine;

  /**
   * Custom security policies passed to ClawMoat's evaluateTool.
   * Merged with ClawMoat's defaults. Allows per-deployment
   * policy customization without forking ClawMoat config.
   */
  policies?: Record<string, unknown>;

  /**
   * Tools exempt from policy evaluation.
   * Still audited, never blocked. Use for tools that are
   * already gated by OpenClaw's exec-approvals system.
   */
  exemptTools?: string[];

  /**
   * Tool allowlist for escalated sessions (tier2+).
   * When a session reaches tier2, ONLY these tools are allowed.
   * All other tools are blocked regardless of ClawMoat policy.
   * Compared case-insensitively (normalized to lowercase).
   * Default: ["read"]
   */
  restrictedTools?: string[];

  /**
   * Whether to promote ClawMoat "warn" decisions to "block"
   * when the session is at tier1 or above.
   * Default: true
   */
  escalateWarnings?: boolean;

  /**
   * Whether to scan tool parameters through the content pipeline.
   * Default: true
   */
  scanParams?: boolean;
}

/**
 * Duck-typed interface for the ClawMoat policy engine.
 * Matches ClawMoat's ClawMoat.evaluateTool() method signature.
 * The guard verifies this method exists at construction time
 * and skips policy evaluation if absent.
 */
export interface ClawMoatPolicyEngine {
  evaluateTool(tool: string, args: Record<string, unknown>): ToolPolicyResult;
}

export interface ToolPolicyResult {
  decision: "allow" | "deny" | "warn" | "review";
  reason?: string;
  severity?: string;
  tool?: string;
  [key: string]: unknown;
}

export interface ToolCallGuardResult {
  /** Whether to block this tool call */
  block: boolean;
  /** Human-readable reason for the block (injected into LLM context) */
  blockReason?: string;
  /** Structured audit metadata — caller emits via AuditEmitter */
  audit: {
    toolName: string;
    paramsHash: string;
    policyDecision: string;
    policyReason?: string;
    policySeverity?: string;
    escalationApplied: boolean;
    sessionTier: EscalationTier;
    paramScanUnsafe: boolean;
    paramScanFindingCount: number;
  };
}
```

### 5.3 Implementation Notes

**Parameter hashing:** `sha256(safeStringify(params))` using existing `sha256` from `src/lib/sha256.ts` and `safeStringify` from `src/lib/safe-stringify.ts`. Never log raw params — they may contain secrets, PII, or file contents. When `params` is absent, hash the empty string.

**Tool name normalization — two stages:**

1. **Strip OpenClaw server prefix** (reuse enricher's convention): OpenClaw prefixes MCP tools with the server name (e.g., `vigil-harbor__memory_search`). Split on the last `__` and take the suffix.

2. **Map to ClawMoat policy names:**

```ts
const TOOL_NAME_MAP: Record<string, string> = {
  bash: "exec",
  shell: "exec",
  execute: "exec",
  run_command: "exec",
  file_read: "read",
  file_write: "write",
  file_edit: "write",
  edit: "write",
  apply_patch: "write",
  web_fetch: "browser",
  web_search: "browser",
  navigate: "browser",
};

function normalizeForPolicy(rawToolName: string): string {
  // Stage 1: strip server prefix (e.g. "vigil-harbor__exec" → "exec")
  const sep = rawToolName.lastIndexOf("__");
  const unprefixed = sep >= 0 ? rawToolName.slice(sep + 2) : rawToolName;
  // Stage 2: map to ClawMoat policy name
  const lower = unprefixed.toLowerCase();
  return TOOL_NAME_MAP[lower] ?? lower;
}
```

ClawMoat returns `{ decision: 'allow', reason: 'No policy defined' }` for unknown tool names — safe default.

**Session tier retrieval:** The guard reads tier from the injected `FrequencyTracker` via its public API:

```ts
import type { EscalationTier, SessionSuspicionState } from "../types/frequency.js";

function deriveTier(
  tracker: FrequencyTracker,
  sessionId: string,
): EscalationTier {
  const state = tracker.getState(sessionId);
  if (!state) return "none";
  if (state.terminated) return "tier3";
  const thresholds = tracker.thresholds; // public getter, returns defensive copy
  if (state.lastScore >= thresholds.tier3) return "tier3";
  if (state.lastScore >= thresholds.tier2) return "tier2";
  if (state.lastScore >= thresholds.tier1) return "tier1";
  return "none";
}
```

The `FrequencyTracker.thresholds` getter (`frequency/index.ts:213`) returns `{ tier1, tier2, tier3 }` as a defensive copy — safe to call per-evaluation.

**Restricted tools comparison:** Normalize both the tool name and the `restrictedTools` entries to lowercase before comparison. The default `restrictedTools` is `["read"]` (single entry, lowercase).

**ClawMoat engine validation:** At construction, check `typeof engine?.evaluateTool === "function"`. If the resolved ClawMoat instance doesn't have `evaluateTool` (possible with very old versions), log a warning and skip policy evaluation — content scanning and frequency gating still provide value.

**Fail-open:** All guard logic is wrapped in try/catch. On error, the guard returns `{ block: false }` and logs a warning. Security failures must never block legitimate tool calls — same design principle as the rest of Drawbridge.

---

## 6. OpenClaw Plugin Integration

### 6.1 Hook Registration

File: `extensions/drawbridge/src/index.ts`

Add to the `register()` method, **before** the enricher registration:

```ts
api.on(
  "before_tool_call",
  async (event: unknown, ctx: unknown) => {
    const state = await getState();
    if (!state) return {};
    return handleBeforeToolCallGuard(
      state,
      event as BeforeToolCallEvent,
      ctx as BeforeToolCallContext,
    );
  },
  { priority: 10 },  // Run before enricher (default priority)
);
```

Priority 10 ensures the security guard runs before the enricher's circuit breaker. If the guard blocks, OpenClaw's terminal `{ block: true }` semantics prevent the enricher from firing.

### 6.2 Hook Handler

File: `extensions/drawbridge/src/hooks/before-tool-call-guard.ts`

Thin adapter — the guard returns structured results, the handler routes audit events:

1. Derive `sessionId` from `ctx.sessionKey` (reuse existing `deriveSessionId` from `session.ts`)
2. Check `state.config.toolGuardEnabled` — return `{}` if disabled; check `exemptTools` against tool name
3. Call `state.guard.evaluate(input)` — guard has pipeline and tracker from construction
4. Emit audit event via `state.auditSink` using the guard's returned `audit` metadata
5. Feed audit event to AlertManager for alert evaluation
6. Return `{ block, blockReason }` to OpenClaw

### 6.3 PluginState Extension

File: `extensions/drawbridge/src/pipeline-factory.ts`

Add `guard: ToolCallGuard` to the `PluginState` interface. Constructed during `initializePluginState()`:

```ts
import { ToolCallGuard } from "@vigil-harbor/clawmoat-drawbridge";

// After creating pipelines and tracker...

// Duck-type check for evaluateTool on the resolved engine
const policyEngine = (
  engine &&
  typeof (engine as Record<string, unknown>).evaluateTool === "function"
) ? engine as ClawMoatPolicyEngine : undefined;

const guard = new ToolCallGuard({
  pipeline: inbound,       // ← state.inbound, not "inboundPipeline"
  tracker,                 // ← shared FrequencyTracker instance
  engine: policyEngine,
  policies: config.toolPolicies,
  exemptTools: config.exemptTools,
  restrictedTools: config.restrictedTools,
  escalateWarnings: config.escalateWarnings ?? true,
  scanParams: config.scanParams ?? true,
});
```

Note: the `engine` variable is the raw ClawMoat instance resolved by `resolveClawMoatEngine()`. It's already used for the scanner pipelines. The duck-type check verifies `evaluateTool` exists before passing it to the guard — older ClawMoat versions that lack this method will degrade to content-scan + frequency-gating only.

### 6.4 Plugin Config Extension

File: `extensions/drawbridge/src/config.ts`

Add to `DrawbridgePluginConfig`:

```ts
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
```

Add corresponding fields to `ResolvedConfig` and wire defaults in `resolveConfig()`.

### 6.5 Plugin Manifest Update

File: `extensions/drawbridge/openclaw.plugin.json`

Add the new config fields to the `configSchema.properties` object. The schema currently has `"additionalProperties": false`, so OpenClaw will reject unrecognized config keys. Each new property needs a JSON Schema entry:

```json
"toolGuardEnabled": {
  "type": "boolean",
  "default": true,
  "description": "Enable tool call policy guard"
},
"exemptTools": {
  "type": "array",
  "items": { "type": "string" },
  "default": [],
  "description": "Tools exempt from policy evaluation"
},
"restrictedTools": {
  "type": "array",
  "items": { "type": "string" },
  "default": ["read"],
  "description": "Tool allowlist for tier2+ escalated sessions"
},
"toolPolicies": {
  "type": "object",
  "additionalProperties": true,
  "description": "Custom ClawMoat policy overrides for tool evaluation"
},
"escalateWarnings": {
  "type": "boolean",
  "default": true,
  "description": "Promote ClawMoat warn decisions to block at tier1+"
},
"scanParams": {
  "type": "boolean",
  "default": true,
  "description": "Scan tool parameters through the content pipeline"
}
```

---

## 7. Unblocking Alert Rule 5 (`writeFailSpike`)

### 7.1 What Was Blocked

`DEFERRED.md` documents: Alert Rule 5 cannot fire because the `write_failed` audit event type doesn't exist. The `AlertRuleId`, `AlertRuleConfigs`, and default config already define the rule shape (see `alerting.ts:149-153`). The `evaluate()` switch statement has a placeholder comment (`alerting/index.ts:159`). Test stubs exist in `alerting/__tests__/alerting.test.ts`.

### 7.2 Changes

1. **Add `write_failed` to `AuditEventType`** (covered in §4.2)
2. **Add `WriteFailedAuditEvent` interface** (covered in §4.3)
3. **Add `write_failed` to `TypedAuditEvent` union** (covered in §4.3)
4. **Add `emitWriteFailed()` to `AuditEmitter`** — follows the same pattern as existing `emitScan()`, `emitFrequency()`, etc.
5. **Implement the `writeFailSpike` case in `AlertManager.evaluate()`** — replace the placeholder comment at `alerting/index.ts:159` with a case that counts `write_failed` events within the configured window and fires when threshold is met
6. **Wire emission in the guard** — when `evaluateTool` returns a write-related block, the hook handler emits `write_failed` alongside `tool_policy_block`. This captures *prevented* write failures.
7. **Remove the `writeFailSpike` entry from `DEFERRED.md`**

### 7.3 Emission Points

The `write_failed` event fires from the hook handler (not the guard module — the guard has no AuditEmitter dependency):

- **Guard blocks a write:** When the guard blocks a tool whose normalized name is `write` (all write-like tools — `file_write`, `file_edit`, `edit`, `apply_patch` — converge to `write` via `TOOL_NAME_MAP`), the hook handler emits `write_failed` with `cause: "policy_block"` alongside `tool_policy_block`. This captures *prevented* write failures.

A second emission point (enricher emitting `write_failed` with `cause: "runtime_error"` when it classifies actual runtime write errors) is deferred to a v1.3.x patch — the guard emission alone is sufficient to unblock Alert Rule 5.

---

## 8. ClawMoat v0.8.0 Compatibility

### 8.1 Dependency Changes

File: `package.json` (root)

```diff
  "peerDependencies": {
    "clawmoat": ">=0.7.0"    # ← KEEP at >=0.7.0 (see note below)
  },
  "devDependencies": {
-   "clawmoat": "^0.7.0",
+   "clawmoat": "^0.8.0",    # ← dev dep bumped for testing
  }
```

File: `extensions/drawbridge/package.json`

Bump core library dep and dev dep. Keep peer dep at >=0.7.0:

```diff
  "dependencies": {
-   "@vigil-harbor/clawmoat-drawbridge": "^1.1.0"
+   "@vigil-harbor/clawmoat-drawbridge": "^1.3.0"
  },
  "peerDependencies": {
    "clawmoat": ">=0.7.0",   # ← KEEP at >=0.7.0
```

**Why keep peer dep at >=0.7.0:** The guard duck-type checks `typeof engine?.evaluateTool === "function"` at construction. Consumers on ClawMoat 0.7.x (which already has `evaluateTool`) work fine. Consumers on even older versions degrade to content-scan + frequency-gating only. Bumping the peer dep to >=0.8.0 would be a soft breaking change for no functional benefit — v0.8.0 adds FinanceGuard and MCP Scanner, neither of which Drawbridge integrates.

### 8.2 No Breaking Changes

ClawMoat v0.8.0 is backward-compatible. `scan()`, `scanInbound()`, `scanOutbound()` signatures unchanged. The `evaluateTool()` method has existed since v0.7.0 — it's just now being consumed. The guard duck-type checks for its existence, so consumers on ClawMoat 0.7.x work fine (evaluateTool is present), and hypothetical consumers on even older versions degrade to content-scan + frequency-gating only. The peer dep stays at `>=0.7.0` — no install breakage.

### 8.3 FinanceGuard / MCP Scanner

**Not integrated in v1.3.** These are separate ClawMoat v0.8.0 features with their own UX surface. The guard's `engine` config accepts any object with `evaluateTool()`, so consumers who want FinanceGuard can compose it themselves.

Document in README that ClawMoat v0.8.0 exposes `FinanceGuard` and `MCP Scanner` — point consumers to ClawMoat's docs for direct usage alongside Drawbridge.

---

## 9. Test Plan

### 9.1 Guard Unit Tests

File: `src/guard/__tests__/guard.test.ts`

| Test | Description |
|------|-------------|
| **Policy: deny blocks** | `evaluateTool` returns `deny` → `block: true` |
| **Policy: review blocks** | `evaluateTool` returns `review` → `block: true` (no human reviewer) |
| **Policy: warn allows** | `evaluateTool` returns `warn` at tier `none` → `block: false` |
| **Policy: warn blocked at tier1** | `evaluateTool` returns `warn` at tier1 + `escalateWarnings: true` → `block: true` |
| **Policy: allow passes** | `evaluateTool` returns `allow` → `block: false` |
| **Policy: unknown tool passes** | Unrecognized tool name → ClawMoat returns `allow` → passes |
| **Policy: engine absent** | No ClawMoat engine → skip policy eval, rely on content scan + frequency |
| **Policy: engine lacks evaluateTool** | Engine object without evaluateTool method → skip policy eval, warning logged |
| **Params: injection blocks** | Tool args contain prompt injection → pipeline scan unsafe → `block: true` |
| **Params: clean passes** | Clean tool args → pipeline scan safe → policy decides |
| **Params: absent skips scan** | No `params` in event → skip content scan, policy-only |
| **Params: hash in audit** | Audit metadata contains `sha256(params)`, never raw params |
| **Session: terminated blocks** | Session at tier3 → block unconditionally, no policy call |
| **Session: tier2 restricts** | Session at tier2 + tool not in `restrictedTools` → block |
| **Session: tier2 allows restricted** | Session at tier2 + tool in `restrictedTools` → policy decides |
| **Exempt: tool skips** | Tool in `exemptTools` → `block: false`, audit emitted |
| **Fail-open: engine throws** | ClawMoat throws → `block: false`, warning logged |
| **Fail-open: pipeline throws** | Content scan throws → `block: false`, warning logged |
| **Tool name: strips prefix** | `vigil-harbor__exec` → normalized to `exec` for policy eval |
| **Tool name: maps aliases** | `bash` → `exec`, `file_write` → `write`, etc. |
| **Tool name: case insensitive** | `Bash`, `BASH`, `bash` all map to `exec` |
| **Restricted: case insensitive** | `restrictedTools: ["read"]` matches `Read`, `READ`, `read` |
| **Audit: block metadata** | Block → audit object has correct fields (tier, decision, hash, etc.) |
| **Audit: allow metadata** | Allow → audit object has correct fields |

### 9.2 Plugin Hook Tests

File: `extensions/drawbridge/__tests__/tool-guard.test.ts`

| Test | Description |
|------|-------------|
| **Registration priority** | Guard registers at priority 10 |
| **Guard disabled** | `toolGuardEnabled: false` → handler returns `{}` |
| **PluginState null** | Init failed → returns `{}` (fail-open) |
| **Exemptions respected** | Exempt tool → passes through |
| **Session key derivation** | Hook correctly maps `ctx.sessionKey` to `sessionId` |
| **Audit routing** | Guard audit events flow through plugin's audit sink |
| **Alert routing** | `toolPolicyBlock` alerts fire and route to alert handler |
| **write_failed emission** | Blocked write tool → emits `write_failed` alongside `tool_policy_block` |
| **Coexistence with enricher** | Guard blocks → enricher never fires (verify via spy) |
| **Guard allows → enricher runs** | Guard passes → enricher circuit-breaker still works |

### 9.3 Alert Rule 5 Tests

File: `src/alerting/__tests__/alerting.test.ts`

Unblock the existing test stubs (referenced in `DEFERRED.md` at line 399):

| Test | Description |
|------|-------------|
| **writeFailSpike fires** | N `write_failed` events in window → alert fires |
| **writeFailSpike below threshold** | N-1 events → no alert |
| **writeFailSpike disabled** | `enabled: false` → no alert |
| **writeFailSpike window expiry** | Events outside window → no alert |

Add new `toolPolicyBlock` alert tests:

| Test | Description |
|------|-------------|
| **toolPolicyBlock fires** | 1 `tool_policy_block` event in window → alert fires |
| **toolPolicyBlock disabled** | `enabled: false` → no alert |
| **toolPolicyBlock window expiry** | Event outside window → no alert |

### 9.4 Existing Tests

Run full suite — no existing tests should break. Specific areas to verify:

- Pipeline tests: new audit event types don't break event routing
- Enricher tests: `BeforeToolCallEvent` type widening is backward-compatible (all new fields are optional)
- Alert tests: new `toolPolicyBlock` rule doesn't interfere with existing rules
- Frozen object rebuilds: verify `EVENT_MIN_VERBOSITY`, `DEFAULT_ALERT_RULES`, `DEFAULT_ALERT_CONFIG` still satisfy `Readonly<>` expectations

---

## 10. Documentation Updates

### 10.1 README.md

- Add "Tool Call Policy Guard" section under Features
- Update architecture diagram to show `before_tool_call` flow
- Add configuration reference for new guard options
- Update ClawMoat compatibility note (v0.8.0+)
- Mention FinanceGuard / MCP Scanner availability

### 10.2 CHANGELOG.md

```markdown
## [1.3.0] — 2026-0X-XX

### Added
- **Tool Call Policy Guard**: Security gating for tool calls via ClawMoat
  `evaluateTool()` + parameter content scanning + frequency-aware escalation.
  New `ToolCallGuard` class in core library, wired into OpenClaw's
  `before_tool_call` hook at priority 10.
- `tool_policy_block` and `tool_policy_allow` audit event types
- `toolPolicyBlock` alert rule (fires on any blocked tool call)
- `write_failed` audit event type (unblocks Alert Rule 5: `writeFailSpike`)
- `WriteFailedAuditEvent` interface
- Guard configuration: `exemptTools`, `restrictedTools`, `toolPolicies`,
  `escalateWarnings`, `scanParams`

### Changed
- ClawMoat dev dependency bumped to `^0.8.0` (peer dep stays at `>=0.7.0` — duck-typing keeps backward compat)
- `BeforeToolCallEvent` type stub widened: added `params?` and `toolCallId?`
- `BeforeToolCallContext` type stub widened: added `agentId?`
- `EVENT_MIN_VERBOSITY`, `DEFAULT_ALERT_RULES`, `DEFAULT_ALERT_CONFIG` rebuilt
  as new frozen objects (added entries for v1.3 event types and alert rules)

### Fixed
- Alert Rule 5 (`writeFailSpike`) now functional — was blocked on missing
  `write_failed` audit event type (tracked in DEFERRED.md)
```

### 10.3 DEFERRED.md

Remove the `writeFailSpike` entry from the Blocked section. Add:

```markdown
### Enricher → write_failed emission
- **Status:** Deferred to v1.3.x patch
- **Description:** The tool error enricher could emit `write_failed` when it
  classifies an error on write/edit/apply_patch tools. Currently only the guard
  hook handler emits `write_failed` (on blocked writes). Adding enricher emission
  would capture actual runtime write failures, not just policy-blocked ones.
```

### 10.4 OpenClaw Plugin Spec

File: `docs/openclaw-plugin-spec.md`

Add section for the new hook:

```markdown
### `before_tool_call` — Tool Policy Guard

**When:** Before every tool invocation, after OpenClaw validates args.

**Event shape:**
`{ toolName: string; params?: Record<string, unknown>; toolCallId?: string }`

**Context:** `{ sessionKey?: string; agentId?: string }`

**Returns:** `{ block?: boolean; blockReason?: string }`

**Action:**
1. Check session termination → block if tier3
2. Check exemptions (tools) → skip if exempt
3. Guard evaluates: param scan + policy + frequency escalation
4. Hook handler emits audit event + evaluates alerts
5. Return `{ block, blockReason }` to OpenClaw

**Priority:** 10 (before enricher circuit-breaker at default priority)

**Failure mode:** Fail-open. Guard errors → allow tool call, log warning.
```

---

## 11. CC Instruction Set

### Phase 1: Type Foundation

**Goal:** Add all new types and audit events. No logic changes.

1. **`src/types/audit.ts`:**
   - Add `tool_policy_block`, `tool_policy_allow`, `write_failed` to `AuditEventType` union
   - Rebuild `EVENT_MIN_VERBOSITY` as a new `Object.freeze()` with the three new entries added
   - Add `ToolPolicyAuditEvent extends AuditEvent` and `WriteFailedAuditEvent extends AuditEvent`
   - Add both to `TypedAuditEvent` discriminated union

2. **`src/types/alerting.ts`:**
   - Add `"toolPolicyBlock"` to `AlertRuleId` union
   - Add `toolPolicyBlock` property to `AlertRuleConfigs` interface
   - Rebuild `DEFAULT_ALERT_RULES` with `toolPolicyBlock` entry added
   - Rebuild `DEFAULT_ALERT_CONFIG` (it spreads `DEFAULT_ALERT_RULES`, so it picks up the change automatically if rebuilt after)

3. **`extensions/drawbridge/src/types/openclaw.ts`:**
   - Widen `BeforeToolCallEvent`: add `params?: Record<string, unknown>`, `toolCallId?: string`
   - Widen `BeforeToolCallContext`: add `agentId?: string`

4. **Run `npm run typecheck`** — must pass with zero errors. New types are additive; existing code doesn't reference them yet.

**Checkpoint gate:** `npm run typecheck` passes. No logic changes, no test changes.

### Phase 2: Audit + Alert Wiring

**Goal:** Wire new event types through AuditEmitter and AlertManager.

1. **`src/audit/index.ts`:**
   - Add import for `ToolPolicyAuditEvent` and `WriteFailedAuditEvent`
   - Add `emitToolPolicy()` method — follows the same pattern as `emitScan()` (accept params, construct event, call `this.emit()`, return event or null)
   - Add `emitWriteFailed()` method — same pattern

2. **`src/alerting/index.ts`:**
   - Replace the placeholder comment at line ~159 with a `"write_failed"` case that calls a new `evaluateWriteFailSpike()` private method
   - Add `"tool_policy_block"` case that calls a new `evaluateToolPolicyBlock()` private method
   - Implement both methods following the `evaluateSyntacticFailBurst()` pattern: count events of the target type within the configured window, fire alert when count ≥ threshold

3. **Update tests:**
   - `src/audit/__tests__/audit.test.ts`: test `emitToolPolicy()` and `emitWriteFailed()` emit correct event shapes at correct verbosity levels
   - `src/alerting/__tests__/alerting.test.ts`: unblock existing `writeFailSpike` test stubs, add `toolPolicyBlock` tests per §9.3

4. **Run `npm test`** — all existing + new tests pass.

**Checkpoint gate:** `npm test` passes. Audit + alert infrastructure ready.

### Phase 3: Guard Module

**Goal:** Implement the core guard logic as a standalone module.

1. **Create `src/guard/types.ts`** — types from §5.2 of this spec

2. **Create `src/guard/index.ts`** — `ToolCallGuard` class per §5.1 and §5.3
   - Constructor: accept `ToolCallGuardConfig`, store pipeline/tracker/engine/policies/exemptions/thresholds
   - Duck-type check engine for `evaluateTool` at construction, warn and store null if absent
   - `evaluate()` method: implement the data flow from §3.3 (steps 1–5, return structured result per step 6)
   - Two-stage tool name normalization: strip server prefix, then map aliases
   - `deriveTier()` helper reading `tracker.thresholds` and `tracker.getState()`
   - Fail-open try/catch wrapper around entire evaluate()
   - All params hashed via existing `sha256()` from `src/lib/sha256.ts`, never logged raw
   - Pipeline param scan uses `source: "tool_params"`, NOT `"mcp"`

3. **Update `src/index.ts`** — export `ToolCallGuard` and guard types:
   ```ts
   export { ToolCallGuard } from "./guard/index.js";
   export type {
     ToolCallInput,
     ToolCallGuardConfig,
     ClawMoatPolicyEngine,
     ToolPolicyResult,
     ToolCallGuardResult,
   } from "./guard/types.js";
   ```

4. **Create `src/guard/__tests__/guard.test.ts`** — all tests from §9.1
   - Mock ClawMoat engine (return configurable decisions)
   - Mock pipeline via engine injection (return configurable scan results)
   - Mock frequency tracker state (return configurable session state and thresholds)

5. **Run `npm test`** — all tests pass.

**Checkpoint gate:** `npm test` passes. Guard module complete and tested in isolation.

### Phase 4: OpenClaw Plugin Integration

**Goal:** Wire the guard into the OpenClaw plugin's hook system.

1. **Create `extensions/drawbridge/src/hooks/before-tool-call-guard.ts`**
   - `handleBeforeToolCallGuard(state, event, ctx)` function
   - Derive sessionId from `ctx.sessionKey` (reuse `deriveSessionId` from `session.ts`)
   - Check `state.config.toolGuardEnabled` — return `{}` if disabled
   - Check `exemptTools` against tool name (note: `isExempt` reads `channelId`/`senderId` which aren't on `BeforeToolCallContext` — do not reuse it here)
   - Call `state.guard.evaluate(input)` — guard already has pipeline and tracker
   - Emit audit event via `state.auditSink` using guard's `result.audit` metadata
   - If blocked write tool, also emit `write_failed` event
   - Feed audit event to AlertManager (if accessible, or via existing alert routing in auditSink)
   - Return `{ block, blockReason }` to OpenClaw
   - Wrap everything in try/catch → fail-open `{}`

2. **Update `extensions/drawbridge/src/config.ts`**
   - Add guard config fields to `DrawbridgePluginConfig` per §6.4
   - Add to `ResolvedConfig` interface
   - Add defaults to `resolveConfig()`

3. **Update `extensions/drawbridge/src/pipeline-factory.ts`**
   - Import `ToolCallGuard` from `@vigil-harbor/clawmoat-drawbridge`
   - Add `guard: ToolCallGuard` to `PluginState` interface
   - In `initializePluginState()`: duck-type check engine for `evaluateTool`, construct guard with `inbound` pipeline, shared `tracker`, and engine
   - Pass through config fields: `exemptTools`, `restrictedTools`, `toolPolicies`, `escalateWarnings`, `scanParams`

4. **Update `extensions/drawbridge/src/index.ts`**
   - Import `handleBeforeToolCallGuard`
   - Register `before_tool_call` handler at priority 10 (BEFORE enricher `registerHooks()` call)
   - Guard registration goes in the main `register()` method, not in the enricher

5. **Update `extensions/drawbridge/openclaw.plugin.json`**
   - Add all new config properties to `configSchema.properties` per §6.5

6. **Create `extensions/drawbridge/__tests__/tool-guard.test.ts`** — tests from §9.2
   - Use existing test helpers from `__tests__/helpers.ts`
   - Add `makeBeforeToolCallEvent` / `makeBeforeToolCallCtx` overrides for new fields

7. **Run full test suite** from both package roots:
   ```bash
   npm test                           # root — core library
   cd extensions/drawbridge && npm test  # plugin
   ```

**Checkpoint gate:** All tests pass in both packages.

### Phase 5: Dependencies + Docs + Cleanup

**Goal:** Bump deps, update docs, clean up deferred items.

1. **`package.json` (root):** Keep ClawMoat peer dep at `>=0.7.0`, bump dev dep to `^0.8.0`
2. **`package.json` (root):** Bump version to `1.3.0`
3. **`extensions/drawbridge/package.json`:**
   - Keep ClawMoat peer dep at `>=0.7.0`
   - Bump `@vigil-harbor/clawmoat-drawbridge` dep to `^1.3.0`
   - Bump version to `1.3.0`
4. **Update `README.md`** per §10.1
5. **Update `CHANGELOG.md`** per §10.2
6. **Update `DEFERRED.md`** per §10.3
7. **Update `docs/openclaw-plugin-spec.md`** per §10.4
8. **`npm install`** in both packages to update lockfiles
9. **Final full test run** — both packages
10. **`npm run typecheck`** — clean
11. **`npm run build`** — clean

**Checkpoint gate:** Build + typecheck + tests all pass. Ready for publish.

### Phase 6: Publish

1. **`npm run prepublishOnly`** (runs build + test)
2. **`npm publish`** — publishes `@vigil-harbor/clawmoat-drawbridge@1.3.0`
3. **`cd extensions/drawbridge && npm run prepublishOnly && npm publish`** — publishes `@vigil-harbor/openclaw-drawbridge@1.3.0`
4. **Git tag:** `v1.3.0`
5. **Push tag + branch**

---

## 12. Open Questions (Resolved)

| Question | Resolution |
|----------|-----------|
| Does `before_tool_call` have `params`? | **Designed for both paths.** Type stubs widened with `params?` optional. Guard checks `if (input.params)` — full param scan when present, tool-name-only gating when absent. No feature flag needed. |
| ClawMoat version? | **v0.8.0** is the latest published release (March 2026). Dev dep bumped to `^0.8.0` for testing. Peer dep stays at `>=0.7.0` to avoid soft breaking change — guard duck-types `evaluateTool` which exists since 0.7.0. |
| Guard reuses which pipeline? | **Inbound** (`state.inbound`). Same trust model — tool params are attacker-influenced. |
| What source for param scans? | **`"tool_params"`** — a new source string. Avoids `"mcp"` which would trigger trust resolution and could bypass inspection. `ContentSource` is an open union, so no type changes needed. |
| Guard priority vs enricher? | **Guard at 10, enricher at default.** `{ block: true }` is terminal. |
| Should FinanceGuard be integrated? | **No.** Separate feature surface. Document availability, don't wrap. |
| Who emits audit events? | **The hook handler, not the guard.** Guard returns structured `audit` metadata. Handler emits via `AuditEmitter` / `auditSink`. Keeps guard module decoupled from audit infrastructure. |
| Where does the guard read thresholds? | **`tracker.thresholds`** — public getter on `FrequencyTracker` returning `{ tier1, tier2, tier3 }`. Not from the pipeline (which only stores `tier1Threshold` privately). |

---

## 13. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Guard blocks legitimate tool calls | Fail-open default. `exemptTools` config. Conservative `restrictedTools` default (read-only). Alert on blocks so operator sees false positives. |
| ClawMoat `evaluateTool` performance | Synchronous, regex-based — microseconds. No network calls. No risk. |
| ClawMoat engine lacks `evaluateTool` | Duck-type checked at construction. Missing method → policy eval skipped, content scan + frequency gating still active. Warning logged. |
| Parameter content scan latency | Same pipeline used for message scanning. If message scanning is acceptable latency, param scanning is too (params are typically shorter than messages). |
| Param scan double-counts frequency | Intentional — `pipeline.inspect()` internally calls `tracker.update()`. Guard does NOT manually update tracker. Tool-arg injection compounds with message injection in the same session's suspicion score. Documented as defense-in-depth. |
| Type stub mismatch with future OpenClaw | All new fields are optional (`?`). Forward-compatible. |
| Shared frequency tracker contention | Same design as existing inbound/outbound sharing. Single event loop — no concurrent mutation. |
| Frozen object rebuilds break imports | Consumers import the const binding name, not the object identity. Rebuilding preserves the export name and type shape. |
| Consumer on ClawMoat 0.7.x installs guard | Guard duck-type checks `evaluateTool` at construction. 0.7.x has it — full guard functionality. Peer dep stays `>=0.7.0`, no install breakage. |
