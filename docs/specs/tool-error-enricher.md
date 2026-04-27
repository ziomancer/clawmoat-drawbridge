# Tool Error Enricher Spec

**Module:** `@vigil-harbor/clawmoat-drawbridge` v1.2.0
**Location:** `extensions/drawbridge/src/hooks/` (3 new hooks)
**Status:** Draft
**Date:** 2026-04-06

---

## Problem Statement

When MCP tool calls fail, OpenClaw injects the raw error text into the LLM context window as a tool result with `isError: true`. These error messages are terse and unhelpful: `"Request timeout"`, `"invalid params"`, `"ECONNREFUSED"`. The model cannot determine what went wrong, why, or what to do next. It either retries blindly (wasting tokens and context window), halts without informing the user, or invents an incorrect recovery path.

This is not theoretical. OpenClaw issue #12595 documents agents hitting tool execution errors and producing complete silence — no response to the user at all. Issue #36142 shows that rate limits after tool calls result in empty assistant messages with no error surfaced. In both cases, the model had no actionable recovery information in its context.

The vigil-harbor MCP server exposes 13 tools. Each can fail in distinct ways (timeout, validation, auth, rate-limit, server unreachable). The model interacts with these tools hundreds of times per session. Every unhelpful error is a coaching opportunity lost.

**Impact of not solving:** Agents stall silently, users lose trust, retrieval-dependent workflows fail without fallback, and context window budget is wasted on blind retries that a structured error message would have prevented.

---

## Goals

1. **Reduce blind retries by 80%.** When a tool error includes a structured recovery action, the model should follow it instead of repeating the same call. Measured by comparing consecutive identical tool calls before/after enrichment in session transcripts.

2. **Eliminate silent agent stalls on tool failure.** Every tool error should produce a model response that acknowledges the failure and either recovers or informs the user. Measured by auditing sessions for tool errors followed by empty assistant messages.

3. **Keep enrichment under 800 characters per error.** Context window is precious (maxTokens 8192). Enrichment must be proportional to severity — transient errors get short templates, terminal errors get full guidance. Measured by max enrichment text length across all templates.

4. **Hard-stop runaway error loops within 3 attempts.** When a tool fails 3 consecutive times, the `before_tool_call` hook blocks the 4th invocation. No reliance on model compliance. Measured by verifying no 4th invocation occurs in test harness.

5. **Zero false enrichments.** The enricher must never modify successful tool results, synthetic results, or results from non-target tools. Measured by running the enricher against the full test suite of existing hooks with no behavioral change.

---

## Non-Goals

1. **Patching OpenClaw core.** The enricher operates entirely within the plugin hook system. No changes to `src/agents/`, `src/plugins/hooks.ts`, or any upstream OpenClaw code. If a limitation requires core changes, it is deferred.

2. **Automatic retry execution.** The enricher tells the model what to do; it does not invoke tools itself. Retry is the model's decision, guided by the enriched text. Autonomous retry would require `before_tool_call` to spawn tool calls, which is outside the hook contract.

3. **Cross-session error learning.** The attempt counter resets on session end. Persistent error frequency analysis (e.g., "memory_search has timed out 47 times this week") is a future Dynasty integration, not part of this spec.

4. **MCP server-side error improvement.** The vigil-harbor MCP server should eventually return better errors natively. The enricher is a client-side stop-gap that operates regardless of server-side improvements. If the server starts returning structured errors, the enricher's templates can be relaxed — the architecture supports this gracefully.

5. **UI-facing error messages.** The enricher writes to the LLM context window (`content` blocks on the tool result message). It does not modify user-facing UI, toast notifications, or status indicators. The existing `lastToolError` / `RECOVERABLE_TOOL_ERROR_KEYWORDS` system handles UI-side suppression independently.

---

## User Stories

The "user" in these stories is the LLM (the agent). The human user is the beneficiary.

**As the agent, I want to know WHY a tool call failed** so that I can decide whether to retry, try a different tool, or inform the user.
- Given `memory_search` returns `isError: true` with text `"Request timeout"`
- When the enricher processes this result
- Then the context window contains: cause (server under load), recovery option 1 (retry with narrower query), recovery option 2 (use `memory_query` with source_type filter)

**As the agent, I want to know what parameter was wrong** so that I can correct it without guessing.
- Given `memory_query` returns a validation error: `"invalid params"`
- When the enricher processes this result
- Then the context window echoes back the invalid parameter name and value (redacted if sensitive), plus an example of correct input

**As the agent, I want to be told when to stop retrying** so that I don't waste the context window on a failing tool.
- Given `memory_search` has failed 3 consecutive times in this session
- When I attempt a 4th invocation
- Then `before_tool_call` blocks the call with a clear reason, and I inform the user instead

**As the agent, I want transient errors to be concise** so that my limited context window isn't flooded with recovery instructions for a blip.
- Given a tool returns a timeout on the first attempt
- When the enricher classifies this as `transient`
- Then the enriched text is a single line: "Retry once with same params"

**As the human user, I want to be informed when a tool is persistently failing** so that I can intervene (restart the MCP server, check network, etc.).
- Given a tool reaches its 3rd consecutive failure
- When the enricher classifies this as `terminal`
- Then the enriched text instructs the agent to inform me with the specific failure pattern

---

## Requirements

### P0 — Must-Have

**P0-1: `tool_result_persist` enrichment hook**

The enricher registers a `tool_result_persist` hook that intercepts tool result messages before they are written to the session transcript.

Acceptance criteria:
- [ ] Hook registered via `api.on("tool_result_persist", handler, { priority: ENRICHER_PRIORITY })`
- [ ] Detects errors via duck-type cast: `(event.message as { isError?: boolean }).isError === true`
- [ ] Skips enrichment when `event.isSynthetic === true`
- [ ] Skips enrichment when `toolName` does not match a tool in the remediation map
- [ ] Falls back to extracting `toolName` from message body when `ctx.toolName` is undefined
- [ ] Returns `{ message: enrichedMessage }` with modified `content` blocks and `details` metadata
- [ ] Handler is fully synchronous (no `await` — `tool_result_persist` rejects async handlers)
- [ ] Fails open: any exception is caught, logged via audit sink, and original message returned unmodified

**P0-2: `after_tool_call` counter and parameter stash**

The enricher registers an `after_tool_call` hook that maintains a session-scoped Map of attempt counts and last-known parameters for each tool.

Acceptance criteria:
- [ ] `Map.set()` is the FIRST operation in the handler — no `await` before it (synchronous-write invariant)
- [ ] Map key: `${ctx.sessionKey}::${event.toolName}` (sessionKey is the only field available in all three hook contexts)
- [ ] Map value: `{ attempts: number, lastParams: Record<string, unknown>, lastError: string }`
- [ ] Counter increments only when `event.error` is defined (not on success)
- [ ] Counter resets to 0 on successful tool call for that tool
- [ ] Stashes `event.params` for parameter echoing in the enrichment hook
- [ ] Fails open: exceptions caught and swallowed

**P0-3: `before_tool_call` circuit breaker**

The enricher registers a `before_tool_call` hook that hard-blocks tool invocations when the attempt counter shows the circuit is broken.

Acceptance criteria:
- [ ] Reads `errorCounts` Map synchronously
- [ ] When `attempts >= MAX_ATTEMPTS` (default: 3), returns `{ block: true, blockReason: "..." }`
- [ ] `blockReason` text names the tool, the failure count, the last error category, and instructs the agent to inform the user
- [ ] Does NOT block if the tool is not in the remediation map (passthrough for non-target tools)
- [ ] Fails open: exceptions caught, returns empty object (allows tool call)

**P0-4: Three-layer template cascade**

Error templates are resolved in order: tool-specific > category > global. First match wins.

Acceptance criteria:
- [ ] `globalTemplates` map covers: `timeout`, `rate_limit`, `auth_failure`, `server_unreachable`, `unknown`
- [ ] `categoryTemplates` map covers: `retrieval` (memory_search, memory_query, memory_traverse, memory_fetch), `mutation` (memory_ingest, memory_link, memory_delete), `utility` (memory_list, memory_sources, memory_status, memory_embed_text, memory_evaluate_process, memory_changes)
- [ ] `toolTemplates` map covers tool-specific overrides only where needed (e.g., memory_search validation error: "Use memory_query for type-filtered retrieval")
- [ ] Cascade is deterministic: tool-specific checked first, then category, then global
- [ ] Unknown error categories fall through to global `unknown` template

**P0-5: Severity classifier**

Each error is classified as `transient`, `recoverable`, or `terminal` before template selection.

Acceptance criteria:
- [ ] `transient`: first timeout or rate-limit. Template is one line (~100 chars): "Retry once with same params."
- [ ] `recoverable`: validation error, 2nd consecutive failure, or auth failure. Full three-part template (~400-600 chars): what happened, why, what to do next.
- [ ] `terminal`: 3rd consecutive failure, or server unreachable after retry. Hard stop template (~200 chars): instructs agent to inform user and not retry.
- [ ] Classification considers attempt count from shared Map
- [ ] Truncated input detection: if raw error text contains `GUARD_TRUNCATION_SUFFIX`, classifier defaults to `recoverable` (cannot reliably classify truncated text)

**P0-6: Sensitive parameter redaction**

When echoing parameters back in enriched error text, sensitive values are masked.

Acceptance criteria:
- [ ] `sensitiveParams` registry defines parameter names to redact, per tool and globally
- [ ] Global sensitive params: `token`, `password`, `apiKey`, `api_key`, `secret`, `authorization`, `credentials`
- [ ] Redacted format: `"paramName: [REDACTED]"`
- [ ] Non-sensitive params echoed verbatim
- [ ] Redaction runs before enrichment text is assembled (never persists sensitive values in transcript)

**P0-7: Session lifecycle cleanup**

The shared state Map is cleaned up on session end to prevent memory leaks.

Acceptance criteria:
- [ ] Registers `session_end` hook that clears all entries for the ending session's `sessionKey`
- [ ] Registers `before_reset` hook that clears all entries for the resetting session
- [ ] Process restart implicitly resets the Map (accepted limitation, documented)
- [ ] Map entries are keyed to include `sessionKey`, so cleanup is scoped (no cross-session interference)

### P1 — Nice-to-Have

**P1-1: Enrichment audit events**

Each enrichment emits an audit event through the existing Drawbridge audit sink.

Acceptance criteria:
- [ ] Event type: `tool_error_enriched`
- [ ] Payload: `{ toolName, severity, attempt, maxAttempts, errorCategory, templateSource (global|category|tool), redactedParams: boolean }`
- [ ] Routed through `CompositeSink` (same as existing Drawbridge audit events)
- [ ] Gated by audit verbosity: `standard` and above

**P1-2: Structured `details` metadata**

Enrichment metadata is written to the message's `details` field for diagnostic/observability consumption.

Acceptance criteria:
- [ ] `details.enricher = { severity, attempt, maxAttempts, errorCategory, templateSource, toolName }`
- [ ] Does not overwrite existing `details` fields — merges additively
- [ ] Accessible by compaction-safeguard.ts, future observability tooling, and Dynasty process evaluation

**P1-3: Configurable attempt limits**

`MAX_ATTEMPTS` is configurable per-tool and globally via plugin config.

Acceptance criteria:
- [ ] Default: 3 for all tools
- [ ] Plugin config key: `enricher.maxAttempts` (global) and `enricher.toolOverrides[toolName].maxAttempts`
- [ ] Validated: must be integer >= 1

### P2 — Future Considerations

**P2-1: Dynasty integration.** Export error frequency data from the attempt Map to MCP memory for Dynasty process evaluation. The `after_tool_call` hook is already collecting the data.

**P2-2: Server-side error pass-through.** If the vigil-harbor MCP server starts returning structured errors with recovery hints, the enricher should detect and pass them through without double-enriching. Detection: check for a `recovery_hint` or `recovery_actions` field in the tool result.

**P2-3: Cross-session error patterns.** Aggregate error frequency across sessions to detect systemic issues (e.g., "memory_search has timed out 47 times this week"). Requires persistent storage outside the session-scoped Map.

**P2-4: Adaptive severity thresholds.** Adjust severity classification based on historical error rates. If a tool has been timing out reliably for the past hour, promote first timeout from `transient` to `recoverable` immediately.

---

## Technical Architecture

### Hook Registration Model

Three hooks registered in `createDrawbridgePlugin()`:

```
┌─────────────────────────────────────────────────────────────┐
│              Tool Execution Lifecycle                        │
│                                                             │
│  1. before_tool_call  ──→  Block if circuit broken          │
│     (sequential, can block)   reads shared Map              │
│                                                             │
│  2. Tool executes (or is blocked)                           │
│                                                             │
│  3. after_tool_call   ──→  Increment counter, stash params  │
│     (void, fire-and-forget)   writes shared Map (sync-first)│
│                                                             │
│  4. capToolResultSize (400K truncation)                     │
│                                                             │
│  5. tool_result_persist ──→  Enrich error message           │
│     (sync, sequential chain)  reads shared Map, returns     │
│                               modified AgentMessage         │
│                                                             │
│  6. before_message_write (other plugins may block)          │
│                                                             │
│  7. Session transcript persistence                          │
└─────────────────────────────────────────────────────────────┘
```

### Shared State: The Attempt Map

```typescript
type AttemptEntry = {
  attempts: number;
  lastParams: Record<string, unknown>;
  lastError: string;
  lastTimestamp: number;
};

// Session-scoped, lives on PluginState
const attemptMap: Map<string, AttemptEntry> = new Map();

// Key format: "${sessionKey}::${toolName}"
```

**Data flow between hooks:**

1. `after_tool_call` fires (void, parallel). Handler synchronously writes `attemptMap.set(key, entry)` as its FIRST operation. No `await` before the `Map.set()`. This guarantees the write completes in the same microtask and is visible to `tool_result_persist`.

2. `tool_result_persist` fires (sync, sequential). Handler synchronously reads `attemptMap.get(key)` to determine attempt number, last params, and error category. Assembles enriched message. Returns `{ message: enrichedMessage }`.

3. `before_tool_call` fires on the NEXT invocation (sequential). Handler synchronously reads `attemptMap.get(key)`. If `attempts >= MAX_ATTEMPTS`, returns `{ block: true, blockReason }`.

**Synchronous-write invariant:** The `after_tool_call` handler MUST update the shared Map synchronously before any `await`. OpenClaw dispatches `after_tool_call` with `void` (not awaited), but the handler body before its first `await` executes synchronously within the event loop microtask. A future refactor introducing an `await` before the Map write would silently break the enricher. This invariant must be enforced by code comment and test.

**Context key constraint:** The Map is keyed by `sessionKey` because it is the only identifier available in all three hook contexts:

| Field | before_tool_call | after_tool_call | tool_result_persist |
|-------|-----------------|-----------------|---------------------|
| sessionKey | yes | yes | yes |
| sessionId | yes | yes | no |
| runId | yes | yes | no |
| toolName | yes (required) | yes (required) | optional |

### Error Detection in `tool_result_persist`

The `PluginHookToolResultPersistEvent` has no `isError` field. Detection uses a duck-type cast, matching the pattern established by `compaction-safeguard.ts`:

```typescript
const isError = (event.message as { isError?: boolean }).isError === true;
```

When `toolName` is undefined in `ctx`, extract from the message body:

```typescript
const toolName = ctx.toolName ?? extractToolNameFromMessage(event.message);
```

### Guards

1. **isSynthetic**: Skip enrichment when `event.isSynthetic === true`. Synthetic results are fabricated by the guard/repair step for orphaned tool calls — not real errors.

2. **Non-target tool**: Skip enrichment when `toolName` is not in the remediation map. The enricher only processes vigil-harbor MCP tools.

3. **Successful calls**: Skip enrichment when `isError` is false.

4. **Truncated input**: When raw error text contains `GUARD_TRUNCATION_SUFFIX`, the original error was truncated by the 400K cap. Pattern matching on truncated text is unreliable. Default to severity `recoverable` with a generic template.

### Enrichment Budget

**Hard cap: 800 characters** per enriched error.

Rationale: The 400K truncation at `capToolResultSize` runs BEFORE `tool_result_persist`. There is no re-truncation after enrichment. An 800-char addition to a 400K result is negligible (0.2%). But if the enricher were uncapped, a complex template with full parameter echo could balloon, especially on validation errors with many params.

Template character budgets by severity:
- `transient`: ~100 chars (single line)
- `recoverable`: ~400-600 chars (three-part template)
- `terminal`: ~200 chars (hard stop + user notification instruction)

### Dual Surface

- **`content` blocks** (LLM-facing): Enrichment text appended as a new text block to the message's content array. The original error text is preserved; enrichment is additive.

- **`details` metadata** (diagnostics): Structured enrichment state written to `details.enricher`:
  ```typescript
  {
    severity: "transient" | "recoverable" | "terminal",
    attempt: number,
    maxAttempts: number,
    errorCategory: string,
    templateSource: "global" | "category" | "tool",
    toolName: string
  }
  ```
  Does not overwrite existing `details` fields. Accessible by compaction-safeguard, observability, Dynasty.

### Hook Priority

The enricher's `tool_result_persist` hook priority should be documented. As the currently sole consumer of this hook in the plugin, any priority works. Recommended: `priority: 50` (mid-range). If other plugins register `tool_result_persist` hooks in the future, the enricher should run AFTER content transforms but BEFORE any final validation.

### Lifecycle

- **`session_end`** hook: Iterates Map, deletes all entries prefixed with the ending session's `sessionKey`.
- **`before_reset`** hook: Same cleanup as `session_end`.
- **Process restart**: Map is in-memory; restart implicitly resets all state. This means the circuit breaker resets on restart — accepted limitation. If a tool was genuinely broken, the enricher will re-discover it within 3 attempts.

---

## Interaction with Existing Systems

### Tool Loop Detection (`tool-loop-detection.ts`)

OpenClaw has 4 built-in loop detectors:
- `generic_repeat`: same tool + same params repeated (warning at 10, block at 20)
- `known_poll_no_progress`: polling without progress
- `ping_pong`: A-B-A-B oscillation
- `global_circuit_breaker`: total tool calls capped at 30

**Interaction model:** The enricher fires at error 3. Loop detection fires at repetition 20. They serve different purposes:
- Enricher: "This tool is failing. Here's why and what to do instead."
- Loop detector: "You're calling tools in a loop pattern. Stop."

If both fire on the same call, the model sees two signals. The enricher's `blockReason` should be phrased as tool-error guidance, not loop detection, to avoid confusion. Example: "memory_search has failed 3 consecutive times (timeout). Inform the user that retrieval is unavailable." — not "You are in a tool loop."

### `lastToolError` / `RECOVERABLE_TOOL_ERROR_KEYWORDS`

The core tool handler classifies errors using keyword matching (`"required"`, `"missing"`, `"invalid"`, etc.) for UI-side warning suppression. The enricher classifies for LLM recovery guidance.

**These systems are explicitly decoupled.** They serve different audiences:
- Core classification → determines whether to show a user-facing warning in UI
- Enricher classification → determines what recovery text the LLM sees in its context

They may classify the same error differently. Example: core says "recoverable" (keyword: "missing") and suppresses the UI warning; enricher says "terminal" (3rd consecutive failure) and tells the LLM to stop. This is correct behavior — the UI shouldn't alarm the user on every error, but the LLM should know when to give up.

### `before_message_write` Blocking

After `tool_result_persist` enriches a message, `before_message_write` can still block it (return `{ block: true }`). If another plugin blocks an enriched message:
- The attempt counter was already incremented in `after_tool_call`
- The enriched message is never written to the transcript
- The counter is now out of sync with the transcript

**Known limitation, accepted.** The counter being one ahead is a conservative error — it causes the circuit breaker to trip one attempt earlier than it should. This is safer than tripping one attempt later. The alternative (tracking at `tool_result_persist` time) is worse because `tool_result_persist` is sync-only and can't cleanly do side-effects.

### Compaction Safeguard

The compaction LLM may rewrite enriched text during context compaction. Example: `"ATTEMPT 3 OF 3 - Do not invoke this tool again"` becomes `"Tool memory_search failed three times."` The hard constraint text is lost.

**Solved by `before_tool_call` hard block.** The in-context text is a courtesy for the LLM's understanding. The `before_tool_call` hook reads the attempt Map (not the transcript) and returns `{ block: true }`. The block is enforced at the infrastructure level, independent of what the LLM reads in its context.

---

## Template Cascade

### Global Templates

Applied to all tools when no category or tool-specific template matches.

| Error Category | Severity (1st attempt) | Template |
|---|---|---|
| `timeout` | transient | `TOOL TIMEOUT: {toolName} did not respond within {timeout}s. Retry once with same params.` |
| `rate_limit` | transient | `RATE LIMITED: {toolName} returned 429. Wait briefly, then retry once.` |
| `auth_failure` | recoverable | `AUTH FAILURE: {toolName} returned authentication error. CAUSE: MCP server credentials may have expired. RECOVERY: Inform the user that {toolName} is unavailable due to auth failure. Do not retry.` |
| `server_unreachable` | recoverable | `SERVER UNREACHABLE: {toolName} MCP server is not responding. CAUSE: Server may be down or network interrupted. RECOVERY: (1) If retrieval tool, skip retrieval and inform user. (2) If mutation tool, inform user that the operation did not complete.` |
| `unknown` | recoverable | `TOOL FAILURE: {toolName} returned an error. ERROR: {errorText}. RECOVERY: (1) Retry once with same params. (2) If retry fails, inform the user.` |

### Category Templates

**Retrieval tools** (`memory_search`, `memory_query`, `memory_traverse`, `memory_fetch`):

| Error Category | Template Addition |
|---|---|
| `timeout` (2nd attempt) | `RECOVERY: (1) Retry with narrower query (reduce max_results, add time_after/time_before filters). (2) If query-based, try memory_query with source_type/tags filters instead. (3) If still failing, skip retrieval and respond from available context.` |
| `validation` | `INVALID PARAMS for {toolName}: {echoedParams}. EXPECTED: {expectedFormat}. RECOVERY: Fix parameter and retry. NOTE: memory_search uses semantic query; use memory_query for filtered retrieval by source_type, tags, or metadata.` |

**Mutation tools** (`memory_ingest`, `memory_link`, `memory_delete`):

| Error Category | Template Addition |
|---|---|
| `timeout` (2nd attempt) | `RECOVERY: (1) Retry once — mutation may have completed server-side (idempotent by content hash for ingest). (2) If still failing, inform user the operation may need manual completion.` |
| `validation` | `INVALID PARAMS for {toolName}: {echoedParams}. EXPECTED: {expectedFormat}. NOTE: memory_ingest requires either text or image_data (mutually exclusive). memory_link requires both source_id and target_id as valid UUIDs.` |

**Utility tools** (`memory_list`, `memory_sources`, `memory_status`, `memory_embed_text`, `memory_evaluate_process`, `memory_changes`):

| Error Category | Template Addition |
|---|---|
| `timeout` | `RECOVERY: These are lightweight read operations. Timeout likely indicates MCP server issue. Retry once. If failing, inform user and proceed without this data.` |

### Tool-Specific Templates

Only where a tool has unique failure modes not covered by category templates.

**`memory_search`:**
- Validation error containing "source_type" or "source_system": `"memory_search does not support source_type or source_system filtering in query params. Use memory_query for filtered retrieval by type, tags, or metadata. memory_search is for semantic/fuzzy search by query text."`

**`memory_query`:**
- Validation error on `metadata_filter` operators: `"metadata_filter supports comparison operators: $gt, $gte, $lt, $lte, $ne, $in. Ensure operator values match expected types (numbers for $gt/$lt, arrays for $in)."`

**`memory_traverse`:**
- Validation error on `depth`: `"depth must be 1-3. For deep relationship exploration, chain multiple traverse calls at depth 1."`

**`memory_evaluate_process`:**
- Timeout: `"Process evaluation is long-running (up to 5 minutes). This timeout may be expected. Retry with same params. Inform user this operation takes time."`

---

## Severity Classifier

### Classification Logic

```
classify(errorCategory, attemptCount, isTruncated) → Severity

1. If isTruncated → "recoverable" (can't reliably classify truncated text)
2. If attemptCount >= MAX_ATTEMPTS → "terminal"
3. If errorCategory is "auth_failure" → "recoverable" (never transient — don't retry auth)
4. If errorCategory is "server_unreachable" and attemptCount >= 2 → "terminal"
5. If errorCategory is "timeout" or "rate_limit" and attemptCount == 1 → "transient"
6. If errorCategory is "validation" → "recoverable" (always needs param echo)
7. Default → "recoverable"
```

### Token Budget Rationale

Calvin runs at `maxTokens: 8192`. A typical session includes 30-50 tool calls. If 10% error (3-5 errors per session), and each enrichment averages 400 chars (~100 tokens), that's 300-500 tokens spent on error recovery guidance. This is ~4-6% of the context budget — acceptable.

If enrichment were unbounded (e.g., 2000 chars per error), 5 errors would consume ~2500 tokens (~30% of budget). This is why the 800-char cap and severity-based verbosity matter.

### Error Category Detection

The enricher classifies raw error text into categories by pattern matching:

| Category | Detection Pattern |
|---|---|
| `timeout` | Contains "timeout", "timed out", "ETIMEDOUT", "deadline exceeded" |
| `rate_limit` | Contains "429", "rate limit", "too many requests", "throttle" |
| `auth_failure` | Contains "401", "403", "unauthorized", "forbidden", "auth", "credential" |
| `server_unreachable` | Contains "ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH", "network error", "connection refused" |
| `validation` | Contains "invalid", "required", "missing", "must be", "must have", "schema", "expected" |
| `unknown` | No pattern matched |

When `GUARD_TRUNCATION_SUFFIX` is detected, pattern matching still runs but the result is flagged as low-confidence. Severity defaults to `recoverable` regardless of category.

---

## Tool Remediation Map

Verified against live vigil-harbor MCP server tool inventory (13 tools):

| Tool | Category | Unique Failure Modes | Fallback Tool |
|---|---|---|---|
| `memory_search` | retrieval | source_type param footgun; query too broad | `memory_query` |
| `memory_query` | retrieval | metadata_filter operator errors; complex filter syntax | `memory_search` (if filter not needed) |
| `memory_traverse` | retrieval | invalid record_id; depth > 3 | `memory_fetch` (if known ID) |
| `memory_fetch` | retrieval | invalid record_id; chunk range out of bounds | `memory_list` (to find valid IDs) |
| `memory_ingest` | mutation | text + image_data mutual exclusion; missing required fields | none (unique operation) |
| `memory_link` | mutation | invalid source_id/target_id UUIDs; self-link | `memory_list` (to verify IDs) |
| `memory_delete` | mutation | record not found; bulk delete without confirm_bulk | `memory_list` (to verify existence) |
| `memory_list` | utility | no unique failures beyond global | none |
| `memory_sources` | utility | no unique failures beyond global | none |
| `memory_status` | utility | no unique failures beyond global | none |
| `memory_embed_text` | utility | batch size > 100; empty text | none |
| `memory_evaluate_process` | utility | run_id not found; long timeout (up to 5 min) | none |
| `memory_changes` | utility | invalid ISO 8601 timestamp format | none |

---

## Sensitive Parameter Registry

### Global Sensitive Params

These parameter names are always redacted across all tools:
`token`, `password`, `apiKey`, `api_key`, `secret`, `authorization`, `credentials`, `bearer`, `session_token`

### Per-Tool Sensitive Params

Currently none — vigil-harbor MCP tools don't accept auth-bearing parameters in their schemas. The registry is extensible for future tools.

### Redaction Behavior

```
Input:  { namespace: "personal", query: "find my secrets", api_key: "sk-abc123" }
Output: "namespace: 'personal', query: 'find my secrets', api_key: [REDACTED]"
```

- Sensitive params detected by case-insensitive key matching
- Values replaced with `[REDACTED]` — no partial masking
- Redaction runs BEFORE enrichment text assembly
- Server-side logging (via audit sink) may include full params at `maximum` verbosity — this is intentional for debugging. The redaction protects the LLM context window (persistent in transcript), not server logs.

---

## Success Metrics

### Leading Indicators (1-2 weeks post-deployment)

| Metric | Target | Measurement |
|---|---|---|
| Blind retry reduction | 80% fewer consecutive identical failed tool calls | Audit log: compare sessions before/after enrichment for `same_tool + same_params + isError` sequences |
| Silent stall elimination | 0 empty assistant messages following tool errors | Audit log: tool error followed by empty assistant response |
| Enrichment budget compliance | 100% of enrichments under 800 chars | Audit event: max `enrichmentTextLength` across all events |
| Circuit breaker activation | 0 4th-attempt invocations for any tool | Audit event: `before_tool_call` block count vs. attempt counts |

### Lagging Indicators (1-2 months)

| Metric | Target | Measurement |
|---|---|---|
| Agent task completion rate | 10% improvement on retrieval-dependent tasks | Dynasty evaluation: `processQualityScore` on tasks involving MCP tools |
| Context window efficiency | 15% reduction in wasted tokens on error recovery | Session transcript analysis: tokens spent on failed tool calls + retries |
| User intervention rate | 25% reduction in users needing to manually restart stuck sessions | Support/feedback data |

---

## Open Questions

| # | Question | Owner | Blocking? |
|---|---|---|---|
| 1 | Should the circuit breaker be per-tool or per-tool-per-error-category? (e.g., 3 timeouts on memory_search doesn't block a validation retry) | Engineering | No — start per-tool, refine later |
| 2 | Should enrichment audit events count toward the Drawbridge audit verbosity budget or have their own budget? | Engineering | No — use existing verbosity gates initially |
| 3 | What is the right `ENRICHER_PRIORITY` value for `tool_result_persist`? Needs coordination if other plugins register this hook. | Engineering | No — 50 (mid-range) as default, document rationale |
| 4 | Should the enricher detect and pass through structured errors from a future MCP server upgrade (P2-2)? If so, what's the detection format? | Engineering | No — future consideration, but architecture should not preclude it |

---

## Timeline Considerations

**No hard deadlines.** The enricher is an incremental improvement to agent reliability.

**Phasing:**
- **Phase 1 (P0):** Core three-hook enricher with global templates, severity classifier, circuit breaker, redaction, cleanup. This is a single module addition to the existing Drawbridge plugin.
- **Phase 2 (P1):** Audit integration, details metadata, configurable attempt limits.
- **Phase 3 (P2):** Dynasty integration, server-side pass-through, cross-session patterns.

**Dependencies:**
- `@vigil-harbor/clawmoat-drawbridge` v1.1.1 (current) — no upstream changes needed
- OpenClaw hook system — no upstream changes needed
- vigil-harbor MCP server — no changes needed (enrichment is client-side)

**Risk:** The synchronous-write invariant between `after_tool_call` and `tool_result_persist` is fragile. A future OpenClaw refactor that changes hook dispatch order or introduces async barriers could break the data flow. Mitigation: integration test that verifies the shared Map is readable from `tool_result_persist` after `after_tool_call` writes to it.
