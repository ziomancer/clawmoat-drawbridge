# Drawbridge OpenClaw Plugin — Integration Spec v1

> Wire ClawMoat + Drawbridge into OpenClaw's agent pipeline as a hook-only plugin.
> Scan inbound user messages, outbound model replies, and MCP tool results.

---

## 1. Goal

Calvin (Qwen3.5-35b-a3b) runs on a local machine with tool access (read/write/exec), MCP servers, and Discord channels — some public-facing. Drawbridge provides session-aware content sanitization (prompt injection detection, PII redaction, frequency-based escalation). This plugin wires it into every message flowing through OpenClaw.

**What this plugin does NOT do:**
- Replace OpenClaw's existing tool approval system (`exec-approvals.json`)
- Add new agent tools — this is purely hook-based, invisible to the LLM
- Require changes to OpenClaw core

---

## 2. Plugin Identity

| Field | Value |
|-------|-------|
| `id` | `drawbridge` |
| Type | Hook-only plugin (no capabilities, no tools) |
| Shape | `definePluginEntry` |
| Location | `extensions/drawbridge/` in OpenClaw repo |
| Dependencies | `@vigil-harbor/clawmoat-drawbridge`, `clawmoat` |

---

## 3. Hook Integration Points

### 3.1 `message_received` — Inbound Scan

**When:** Every inbound user message, before agent dispatch.

**Event shape:**
```ts
{ from: string; content: string; timestamp?: number; metadata?: Record<string, unknown> }
```

**Context:** `{ channelId, accountId?, conversationId? }`

**Action:**
1. Run `pipeline.inspect()` with:
   - `content` = event.content
   - `source` = `"user"`
   - `sessionId` = derive from `ctx.channelId + ctx.conversationId` (or `ctx.accountId` fallback)
   - `messageId` = event metadata or timestamp
2. Log audit events to configured sink
3. If `result.safe === false` or `result.terminated === true`:
   - Log block event with findings summary
   - Emit alert if configured

**Return:** void (observational hook — cannot block here). Blocking happens at `before_dispatch`.

### 3.2 `before_dispatch` — Inbound Gate

**When:** After `message_received`, before the message enters the agent loop.

**Event shape:**
```ts
{ content: string; body?: string; channel?: string; sessionKey?: string; senderId?: string; isGroup?: boolean; timestamp?: number }
```

**Returns:** `{ handled: boolean; text?: string }`

**Action:**
1. Read cached scan result from 3.1 (keyed by content hash to avoid double-scan)
2. If `result.safe === false`:
   - Return `{ handled: true, text: "<configurable rejection message>" }`
   - Message never reaches the agent
3. If `result.terminated === true` (tier3 escalation):
   - Return `{ handled: true, text: "<session terminated message>" }`
4. If `result.escalationTier === "tier2"`:
   - Optionally flag but allow through (configurable: `tier2Action: "warn" | "block"`)
5. Otherwise: return `{ handled: false }` — normal dispatch

### 3.3 `message_sending` — Outbound Gate

**When:** Agent reply is about to be sent to the user/channel.

**Event shape:**
```ts
{ to: string; content: string; metadata?: Record<string, unknown> }
```

**Returns:** `{ content?: string; cancel?: boolean }`

**Action:**
1. Run `pipeline.inspect()` with:
   - `content` = event.content
   - `source` = `"assistant"`
   - `sessionId` = same session key as inbound
2. If `result.safe === false`:
   - If sanitization produced redacted content: return `{ content: result.sanitizedContent }`
   - If no salvageable content: return `{ cancel: true }` — message dropped
3. If safe: return `{}` (no modification)

**Outbound profile:** Use `"assistant-outbound"` profile (lower injection thresholds, higher PII sensitivity — the model shouldn't be leaking user data or echoing injected prompts).

### 3.4 `llm_output` — Observational

**When:** Raw model response received, before formatting.

**Event shape:**
```ts
{ runId: string; sessionId: string; provider: string; model: string; assistantTexts: string[]; ... }
```

**Action:** Lightweight scan for audit/telemetry only. No blocking. Captures pre-formatting model output for forensics if `message_sending` later triggers a block.

---

## 4. Pipeline Configuration

### 4.1 Per-Direction Pipeline Instances

The plugin creates **two** `DrawbridgePipeline` instances:

| Instance | Profile | Direction | Used by |
|----------|---------|-----------|---------|
| `inbound` | `"discord"` (or configurable) | User → Agent | `message_received`, `before_dispatch` |
| `outbound` | `"customer-service"` (or configurable) | Agent → User | `message_sending` |

Both share a single `FrequencyTracker` so session escalation is unified across directions.

### 4.2 Plugin Config Schema (openclaw.json)

```jsonc
{
  "plugins": {
    "entries": {
      "drawbridge": {
        "enabled": true,
        "config": {
          // --- Behavior ---
          "tier2Action": "warn",        // "warn" | "block"
          "blockMessage": "Message blocked by content filter.",
          "terminateMessage": "Session terminated due to repeated violations.",

          // --- Profiles ---
          "inboundProfile": "discord",      // BuiltInProfileId or custom
          "outboundProfile": "customer-service",

          // --- Scanning ---
          "blockThreshold": "medium",   // Severity threshold
          "direction": "both",          // "inbound" | "outbound" | "both"

          // --- Sanitization ---
          "redactOutbound": true,       // Redact outbound content vs cancel
          "hashRedactions": true,       // HMAC-hash redacted spans for correlation

          // --- Audit ---
          "auditSink": "log",           // "log" | "vigil-harbor" | "both"
          "auditVerbosity": "normal",   // "quiet" | "normal" | "verbose"

          // --- Channels ---
          "exemptChannels": [],         // Channel IDs to skip scanning
          "exemptSenders": []           // Sender IDs to skip scanning (owner, etc.)
        }
      }
    }
  }
}
```

### 4.3 Shared Frequency Tracker

One `FrequencyTracker` instance per gateway lifetime. Session keys from OpenClaw map directly to Drawbridge session IDs. Escalation tiers persist across the gateway process — a session that hits tier3 stays terminated until gateway restart or explicit reset.

Future: expose a `/drawbridge reset <sessionKey>` command to manually clear a terminated session.

---

## 5. Session Key Derivation

OpenClaw provides `sessionKey` in hook context (composed from channel + conversation + sender). This maps directly to Drawbridge's `sessionId`:

```ts
function deriveSessionId(ctx: HookContext): string {
  // sessionKey is already unique per conversation participant
  return ctx.sessionKey ?? `${ctx.channelId}:${ctx.conversationId ?? ctx.accountId ?? "anon"}`;
}
```

**Security note:** `sessionKey` comes from OpenClaw's authenticated dispatch — the sender is already verified by the channel plugin (Discord OAuth, etc). No additional `validateSessionId` callback needed.

---

## 6. Audit Routing

### 6.1 Console/Log (default)

Audit events written to OpenClaw's standard logger. Low overhead, no persistence.

### 6.2 Vigil Harbor MCP (optional)

If `auditSink` includes `"vigil-harbor"`:
1. Batch audit events per inspection
2. Call `vigil-harbor:memory_ingest` with:
   - `type` = `"drawbridge_audit"`
   - `namespace` = `"security"`
   - `tags` = `["drawbridge", sessionId, escalationTier]`
   - `text` = JSON-serialized audit trail
3. Fire-and-forget — audit ingestion failures must never block message delivery

### 6.3 Alert Escalation

Drawbridge's `AlertManager` produces `AlertPayload` objects. The plugin routes them:

| Alert Severity | Action |
|---------------|--------|
| `info` | Log only |
| `high` | Log + optional Discord notification to admin channel |
| `critical` | Log + Discord notification + session terminated |

Admin notification channel is configurable: `"alertChannel": "1234567890"`.

---

## 7. Scan Result Caching

To avoid double-scanning (once in `message_received`, again in `before_dispatch`):

```ts
// Simple in-memory cache, keyed by content hash, TTL 5s
const scanCache = new Map<string, { result: PipelineResult; ts: number }>();
```

Content hash uses Drawbridge's built-in `sha256()`. Cache entries expire after 5 seconds — enough to span the `message_received` → `before_dispatch` gap, but not enough to serve stale results.

---

## 8. ESM/CJS Interop

Drawbridge is ESM (`"type": "module"`). OpenClaw extensions use ESM. ClawMoat's export style needs runtime verification (documented in memory: may need `import clawmoat from 'clawmoat'; const { ClawMoat } = clawmoat;` fallback).

Drawbridge's `DrawbridgePipeline` accepts an injected `engine` prop, so the interop fix surface is one line in plugin init.

---

## 9. File Layout

```
extensions/drawbridge/
├── openclaw.plugin.json
├── package.json
├── index.ts                  # definePluginEntry + hook registration
├── src/
│   ├── pipeline-factory.ts   # Creates inbound/outbound pipeline instances
│   ├── hooks/
│   │   ├── message-received.ts
│   │   ├── before-dispatch.ts
│   │   ├── message-sending.ts
│   │   └── llm-output.ts
│   ├── session.ts            # Session key derivation + scan cache
│   ├── audit-sink.ts         # Routes audit events to log / VH MCP
│   └── config.ts             # Plugin config types + defaults
└── __tests__/
    ├── inbound.test.ts
    ├── outbound.test.ts
    ├── escalation.test.ts
    └── audit-routing.test.ts
```

---

## 10. Exemptions

Some traffic should bypass scanning:

| Exemption | Reason |
|-----------|--------|
| `exemptChannels` | Admin/dev channels where injection testing is expected |
| `exemptSenders` | Bot owner (you), known admin user IDs |
| Trusted MCP servers | Already handled by Drawbridge's `trustedServers` config |
| System messages | OpenClaw internal messages (no `senderId`) |

---

## 11. Failure Modes

| Failure | Behavior |
|---------|----------|
| ClawMoat import fails | Plugin disables itself, logs error, all messages pass through |
| Pipeline.inspect() throws | Catch, log, allow message through (fail-open) |
| VH MCP audit ingest fails | Silently drop audit event, continue |
| FrequencyTracker OOM (>10k sessions) | Implement max-sessions cap with LRU eviction |

**Design principle:** Drawbridge failures must never block message delivery. Fail-open, log, alert.

---

## 12. Implementation Order

1. **Scaffold** — plugin manifest, package.json, entry point, config types
2. **Inbound hooks** — `message_received` + `before_dispatch` with scan cache
3. **Outbound hook** — `message_sending` with redaction/cancel
4. **Audit routing** — console logger, then VH MCP sink
5. **Config wiring** — openclaw.json schema, exemptions, per-channel overrides
6. **Tests** — unit tests per hook, integration test with mock ClawMoat engine
7. **Observational hook** — `llm_output` (lowest priority, audit-only)

---

## 13. Open Questions

- [ ] **Profile per guild?** Should different Discord guilds get different Drawbridge profiles? (e.g., public guild = strict, private guild = relaxed)
- [ ] **Voice content?** Should STT-transcribed voice messages go through Drawbridge? Currently voice → text → agent, so `message_received` already captures it — but the transcription step happens before the hook fires. Confirm.
- [ ] **Subagent scanning?** OpenClaw has `subagent_spawning` / `subagent_delivery_target` hooks. Should Drawbridge scan content flowing between subagents? Probably not for v1 — internal trust boundary.
- [ ] **Rate limiting vs frequency tracking?** Drawbridge's frequency tracker is threat-score-based, not rate-based. Should the plugin also rate-limit raw message volume independently? Or rely on Discord's built-in rate limits?
