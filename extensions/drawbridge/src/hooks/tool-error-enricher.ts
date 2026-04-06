/**
 * Tool Error Enricher — P0
 *
 * Three-hook system that intercepts MCP tool errors, classifies them,
 * appends structured recovery guidance to the LLM context window,
 * and circuit-breaks after MAX_ATTEMPTS consecutive failures.
 *
 * Architecture:
 *   after_tool_call    → increment counter, stash params (sync-first write)
 *   tool_result_persist → classify error, resolve template, enrich message (SYNC)
 *   before_tool_call   → circuit breaker check (SYNC)
 *   session_end / before_reset → cleanup attempt Map
 *
 * The attemptMap is created in the factory closure, independent of PluginState.
 * No async init required.
 *
 * Synchronous-write invariant:
 *   after_tool_call MUST update the Map synchronously before any await.
 *   OpenClaw dispatches after_tool_call with void (not awaited), but the
 *   handler body before its first await executes synchronously within the
 *   event loop microtask. A future refactor introducing an await before the
 *   Map write would silently break the enricher. Enforced by code + test.
 *
 * before_message_write counter-ahead limitation:
 *   The after_tool_call counter increments before tool_result_persist enriches.
 *   If another plugin's before_message_write blocks the enriched message, the
 *   counter is one ahead of the transcript. This is a CONSERVATIVE error —
 *   circuit breaker trips one attempt early (safer than late). Accepted.
 */

import type {
  ToolResultPersistEvent,
  ToolResultPersistContext,
  AfterToolCallEvent,
  AfterToolCallContext,
  BeforeToolCallEvent,
  BeforeToolCallContext,
  BeforeToolCallResult,
  SessionLifecycleEvent,
  SessionLifecycleContext,
} from "../types/openclaw.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Placeholder — update when compaction-safeguard.ts lands. */
export const GUARD_TRUNCATION_SUFFIX = "... [truncated]";

export const MAX_ATTEMPTS = 3;
export const MAX_ENRICHMENT_CHARS = 800;
const ENRICHER_PRIORITY = 50;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Severity = "transient" | "recoverable" | "terminal";

export type ErrorCategory =
  | "timeout"
  | "rate_limit"
  | "auth_failure"
  | "server_unreachable"
  | "validation"
  | "unknown";

type TemplateCascadeSource = "global" | "category" | "tool";

export interface AttemptEntry {
  attempts: number;
  lastParams: Record<string, unknown>;
  lastError: string;
  lastTimestamp: number;
}

interface EnrichmentResult {
  text: string;
  severity: Severity;
  errorCategory: ErrorCategory;
  templateSource: TemplateCascadeSource;
  attempt: number;
}

// ---------------------------------------------------------------------------
// Remediation map — only these tools are enriched
// ---------------------------------------------------------------------------

export const REMEDIATION_TOOLS: ReadonlySet<string> = new Set([
  "memory_search",
  "memory_query",
  "memory_traverse",
  "memory_fetch",
  "memory_ingest",
  "memory_link",
  "memory_delete",
  "memory_list",
  "memory_sources",
  "memory_status",
  "memory_embed_text",
  "memory_evaluate_process",
  "memory_changes",
]);

// ---------------------------------------------------------------------------
// Tool categories
// ---------------------------------------------------------------------------

const RETRIEVAL_TOOLS = new Set([
  "memory_search",
  "memory_query",
  "memory_traverse",
  "memory_fetch",
]);

const MUTATION_TOOLS = new Set([
  "memory_ingest",
  "memory_link",
  "memory_delete",
]);

const UTILITY_TOOLS = new Set([
  "memory_list",
  "memory_sources",
  "memory_status",
  "memory_embed_text",
  "memory_evaluate_process",
  "memory_changes",
]);

type ToolCategory = "retrieval" | "mutation" | "utility";

function getToolCategory(toolName: string): ToolCategory | undefined {
  if (RETRIEVAL_TOOLS.has(toolName)) return "retrieval";
  if (MUTATION_TOOLS.has(toolName)) return "mutation";
  if (UTILITY_TOOLS.has(toolName)) return "utility";
  return undefined;
}

// ---------------------------------------------------------------------------
// Sensitive parameter redaction
// ---------------------------------------------------------------------------

const GLOBAL_SENSITIVE_PARAMS: ReadonlySet<string> = new Set([
  "token",
  "password",
  "apikey",
  "api_key",
  "secret",
  "authorization",
  "credentials",
  "bearer",
  "session_token",
]);

export function redactParams(params: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (GLOBAL_SENSITIVE_PARAMS.has(key.toLowerCase())) {
      parts.push(`${key}: [REDACTED]`);
    } else {
      parts.push(`${key}: ${JSON.stringify(value)}`);
    }
  }
  return parts.join(", ");
}

// ---------------------------------------------------------------------------
// Error category detection
// ---------------------------------------------------------------------------

const CATEGORY_PATTERNS: ReadonlyArray<[ErrorCategory, RegExp]> = [
  ["timeout", /timeout|timed?\s*out|etimedout|deadline\s*exceeded/i],
  ["rate_limit", /429|rate\s*limit|too\s*many\s*requests|throttle/i],
  ["auth_failure", /401|403|unauthorized|forbidden|auth|credential/i],
  ["server_unreachable", /econnrefused|enotfound|ehostunreach|network\s*error|connection\s*refused/i],
  ["validation", /invalid|required|missing|must\s*be|must\s*have|schema|expected/i],
];

export function classifyErrorCategory(errorText: string): ErrorCategory {
  for (const [category, pattern] of CATEGORY_PATTERNS) {
    if (pattern.test(errorText)) return category;
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Severity classifier
// ---------------------------------------------------------------------------

export function classifySeverity(
  category: ErrorCategory,
  attemptCount: number,
  isTruncated: boolean,
): Severity {
  // 1. Truncated input → can't reliably classify
  if (isTruncated) return "recoverable";
  // 2. Max attempts reached → terminal regardless
  if (attemptCount >= MAX_ATTEMPTS) return "terminal";
  // 3. Auth failure → never transient (don't retry auth)
  if (category === "auth_failure") return "recoverable";
  // 4. Server unreachable after 2+ attempts → terminal
  if (category === "server_unreachable" && attemptCount >= 2) return "terminal";
  // 5. First timeout or rate limit → transient
  if ((category === "timeout" || category === "rate_limit") && attemptCount === 1) return "transient";
  // 6. Validation → always needs param echo
  if (category === "validation") return "recoverable";
  // 7. Default
  return "recoverable";
}

// ---------------------------------------------------------------------------
// Template cascade: tool-specific > category > global
// ---------------------------------------------------------------------------

// --- Global templates ---

function globalTemplate(
  toolName: string,
  category: ErrorCategory,
  errorText: string,
  severity: Severity,
  echoedParams: string,
): string | undefined {
  switch (category) {
    case "timeout":
      if (severity === "transient") {
        return `TOOL TIMEOUT: ${toolName} did not respond in time. Retry once with same params.`;
      }
      return `TOOL TIMEOUT: ${toolName} timed out. ERROR: ${errorText}. RECOVERY: (1) Retry once with same params. (2) If retry fails, inform the user.`;
    case "rate_limit":
      if (severity === "transient") {
        return `RATE LIMITED: ${toolName} returned 429. Wait briefly, then retry once.`;
      }
      return `RATE LIMITED: ${toolName} returned 429. RECOVERY: (1) Wait briefly and retry. (2) If still failing, inform the user.`;
    case "auth_failure":
      return `AUTH FAILURE: ${toolName} returned authentication error. CAUSE: MCP server credentials may have expired. RECOVERY: Inform the user that ${toolName} is unavailable due to auth failure. Do not retry.`;
    case "server_unreachable":
      return `SERVER UNREACHABLE: ${toolName} MCP server is not responding. CAUSE: Server may be down or network interrupted. RECOVERY: Inform the user that ${toolName} is unavailable.`;
    case "validation":
      return `INVALID PARAMS for ${toolName}: ${echoedParams}. ERROR: ${errorText}. RECOVERY: Fix parameter and retry.`;
    case "unknown":
      return `TOOL FAILURE: ${toolName} returned an error. ERROR: ${errorText}. RECOVERY: (1) Retry once with same params. (2) If retry fails, inform the user.`;
    default:
      return undefined;
  }
}

// --- Category templates ---

function categoryTemplate(
  toolName: string,
  category: ErrorCategory,
  toolCategory: ToolCategory,
  errorText: string,
  severity: Severity,
  echoedParams: string,
): string | undefined {
  if (toolCategory === "retrieval") {
    if (category === "timeout" && severity !== "transient") {
      return `TOOL TIMEOUT: ${toolName} timed out. RECOVERY: (1) Retry with narrower query (reduce max_results, add time_after/time_before filters). (2) If query-based, try memory_query with source_type/tags filters instead. (3) If still failing, skip retrieval and respond from available context.`;
    }
    if (category === "validation") {
      return `INVALID PARAMS for ${toolName}: ${echoedParams}. ERROR: ${errorText}. RECOVERY: Fix parameter and retry. NOTE: memory_search uses semantic query; use memory_query for filtered retrieval by source_type, tags, or metadata.`;
    }
  }

  if (toolCategory === "mutation") {
    if (category === "timeout" && severity !== "transient") {
      return `TOOL TIMEOUT: ${toolName} timed out. RECOVERY: (1) Retry once — mutation may have completed server-side (idempotent by content hash for ingest). (2) If still failing, inform user the operation may need manual completion.`;
    }
    if (category === "validation") {
      return `INVALID PARAMS for ${toolName}: ${echoedParams}. ERROR: ${errorText}. NOTE: memory_ingest requires either text or image_data (mutually exclusive). memory_link requires both source_id and target_id as valid UUIDs.`;
    }
  }

  if (toolCategory === "utility") {
    if (category === "timeout") {
      return `TOOL TIMEOUT: ${toolName} timed out. RECOVERY: These are lightweight read operations. Timeout likely indicates MCP server issue. Retry once. If failing, inform user and proceed without this data.`;
    }
  }

  return undefined;
}

// --- Tool-specific templates ---

function toolSpecificTemplate(
  toolName: string,
  category: ErrorCategory,
  errorText: string,
  echoedParams: string,
): string | undefined {
  if (toolName === "memory_search" && category === "validation") {
    if (/source_type|source_system/i.test(errorText)) {
      return `INVALID PARAMS for memory_search: ${echoedParams}. memory_search does not support source_type or source_system filtering in query params. Use memory_query for filtered retrieval by type, tags, or metadata. memory_search is for semantic/fuzzy search by query text.`;
    }
  }

  if (toolName === "memory_query" && category === "validation") {
    if (/metadata_filter|operator|\$gt|\$gte|\$lt|\$lte|\$ne|\$in/i.test(errorText)) {
      return `INVALID PARAMS for memory_query: ${echoedParams}. metadata_filter supports comparison operators: $gt, $gte, $lt, $lte, $ne, $in. Ensure operator values match expected types (numbers for $gt/$lt, arrays for $in).`;
    }
  }

  if (toolName === "memory_traverse" && category === "validation") {
    if (/depth/i.test(errorText)) {
      return `INVALID PARAMS for memory_traverse: ${echoedParams}. depth must be 1-3. For deep relationship exploration, chain multiple traverse calls at depth 1.`;
    }
  }

  if (toolName === "memory_evaluate_process" && category === "timeout") {
    return `TOOL TIMEOUT: memory_evaluate_process is long-running (up to 5 minutes). This timeout may be expected. Retry with same params. Inform user this operation takes time.`;
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Template resolution — cascade with 800-char safety net
// ---------------------------------------------------------------------------

function resolveTemplate(
  toolName: string,
  category: ErrorCategory,
  severity: Severity,
  attempt: number,
  errorText: string,
  params: Record<string, unknown>,
): EnrichmentResult {
  const echoedParams = redactParams(params);
  const toolCategory = getToolCategory(toolName);

  // Terminal severity overrides all templates
  if (severity === "terminal") {
    const text = `ATTEMPT ${attempt} OF ${MAX_ATTEMPTS} — CIRCUIT OPEN. ${toolName} has failed ${attempt} consecutive times (${category}). Do NOT retry. Inform the user that ${toolName} is currently unavailable and suggest manual intervention.`;
    return { text: truncate(text), severity, errorCategory: category, templateSource: "global", attempt };
  }

  // 1. Tool-specific
  const toolTpl = toolSpecificTemplate(toolName, category, errorText, echoedParams);
  if (toolTpl !== undefined) {
    return { text: truncate(toolTpl), severity, errorCategory: category, templateSource: "tool", attempt };
  }

  // 2. Category
  if (toolCategory !== undefined) {
    const catTpl = categoryTemplate(toolName, category, toolCategory, errorText, severity, echoedParams);
    if (catTpl !== undefined) {
      return { text: truncate(catTpl), severity, errorCategory: category, templateSource: "category", attempt };
    }
  }

  // 3. Global
  const gTpl = globalTemplate(toolName, category, errorText, severity, echoedParams);
  if (gTpl !== undefined) {
    return { text: truncate(gTpl), severity, errorCategory: category, templateSource: "global", attempt };
  }

  // Fallback (should not reach — global covers all categories)
  const fallback = `TOOL FAILURE: ${toolName} returned an error. ERROR: ${errorText}. Retry once or inform the user.`;
  return { text: truncate(fallback), severity, errorCategory: category, templateSource: "global", attempt };
}

/** Hard truncation safety net — guards against unexpectedly large param echoes. */
function truncate(text: string): string {
  if (text.length <= MAX_ENRICHMENT_CHARS) return text;
  return text.slice(0, MAX_ENRICHMENT_CHARS - 3) + "...";
}

// ---------------------------------------------------------------------------
// Tool name extraction from message body
// ---------------------------------------------------------------------------

export function extractToolNameFromMessage(message: Record<string, unknown>): string | undefined {
  const content = message.content;

  // content is an array of blocks
  if (Array.isArray(content)) {
    for (const block of content) {
      if (block && typeof block === "object") {
        const b = block as Record<string, unknown>;
        // Check for name or toolName fields — do NOT derive from tool_use_id (opaque)
        if (typeof b.name === "string" && b.name.length > 0) return b.name;
        if (typeof b.toolName === "string" && b.toolName.length > 0) return b.toolName;
      }
    }
  }

  // content is a plain object with name/toolName
  if (content && typeof content === "object" && !Array.isArray(content)) {
    const c = content as Record<string, unknown>;
    if (typeof c.name === "string" && c.name.length > 0) return c.name;
    if (typeof c.toolName === "string" && c.toolName.length > 0) return c.toolName;
  }

  // Check top-level message fields
  if (typeof message.toolName === "string" && message.toolName.length > 0) {
    return message.toolName;
  }
  if (typeof message.name === "string" && message.name.length > 0) {
    return message.name;
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export interface ToolErrorEnricher {
  registerHooks(api: {
    registerHook: (
      event: string,
      handler: (...args: unknown[]) => unknown,
      opts?: { name?: string; priority?: number },
    ) => void;
  }): void;

  /** Exposed for testing — direct handler access. */
  readonly _handlers: {
    handleAfterToolCall(event: AfterToolCallEvent, ctx: AfterToolCallContext): void;
    handleToolResultPersist(
      event: ToolResultPersistEvent,
      ctx: ToolResultPersistContext,
    ): { message: Record<string, unknown> } | undefined;
    handleBeforeToolCall(
      event: BeforeToolCallEvent,
      ctx: BeforeToolCallContext,
    ): BeforeToolCallResult;
    handleSessionCleanup(sessionKey: string): void;
  };

  /** Exposed for testing — read attempt Map state. */
  readonly _attemptMap: Map<string, AttemptEntry>;
}

export function createToolErrorEnricher(): ToolErrorEnricher {
  const attemptMap = new Map<string, AttemptEntry>();

  // -----------------------------------------------------------------------
  // after_tool_call — increment/reset counter, stash params
  // CRITICAL: Map.set() MUST execute before any await — synchronous-write invariant.
  // The early returns above are safe: tool_result_persist bails on the same guards.
  // -----------------------------------------------------------------------
  function handleAfterToolCall(
    event: AfterToolCallEvent,
    ctx: AfterToolCallContext,
  ): void {
    try {
      if (!ctx.sessionKey) return;
      if (!REMEDIATION_TOOLS.has(event.toolName)) return;

      const key = `${ctx.sessionKey}::${event.toolName}`;

      if (event.error !== undefined) {
        // Error path — increment counter (synchronous-first write)
        const existing = attemptMap.get(key);
        attemptMap.set(key, {
          attempts: (existing?.attempts ?? 0) + 1,
          lastParams: event.params ?? {},
          lastError: String(event.error),
          lastTimestamp: Date.now(),
        });
      } else {
        // Success path — reset counter
        attemptMap.set(key, {
          attempts: 0,
          lastParams: event.params ?? {},
          lastError: "",
          lastTimestamp: Date.now(),
        });
      }
    } catch {
      // Fail-open — swallow exceptions
    }
  }

  // -----------------------------------------------------------------------
  // tool_result_persist — classify error, resolve template, enrich (SYNC)
  // This handler MUST be fully synchronous — no await, no Promises.
  // -----------------------------------------------------------------------
  function handleToolResultPersist(
    event: ToolResultPersistEvent,
    ctx: ToolResultPersistContext,
  ): { message: Record<string, unknown> } | undefined {
    try {
      // Guard: skip synthetic results
      if (event.isSynthetic === true) return undefined;

      // Guard: skip non-errors
      const isError = (event.message as { isError?: boolean }).isError === true;
      if (!isError) return undefined;

      // Guard: skip when sessionKey is undefined
      if (!ctx.sessionKey) return undefined;

      // Resolve tool name (from ctx, then from message body)
      const toolName = ctx.toolName ?? extractToolNameFromMessage(event.message);
      if (!toolName) return undefined;

      // Guard: skip non-remediation-map tools
      if (!REMEDIATION_TOOLS.has(toolName)) return undefined;

      // Read attempt state
      const key = `${ctx.sessionKey}::${toolName}`;
      const entry = attemptMap.get(key);
      const attempt = entry?.attempts ?? 1;
      const lastParams = entry?.lastParams ?? {};

      // Extract raw error text
      const rawContent = event.message.content;
      let errorText = "";
      if (typeof rawContent === "string") {
        errorText = rawContent;
      } else if (Array.isArray(rawContent)) {
        const texts = rawContent
          .filter((b): b is { type: string; text: string } =>
            b && typeof b === "object" && typeof (b as Record<string, unknown>).text === "string",
          )
          .map((b) => b.text);
        errorText = texts.join(" ");
      }

      // Truncation detection
      const isTruncated = errorText.includes(GUARD_TRUNCATION_SUFFIX);

      // Classify
      const category = classifyErrorCategory(errorText);
      const severity = classifySeverity(category, attempt, isTruncated);

      // Resolve template
      const enrichment = resolveTemplate(toolName, category, severity, attempt, errorText, lastParams);

      // Truncated text at MAX_ATTEMPTS: severity stays "recoverable" (can't classify
      // truncated text reliably), but warn the LLM that the circuit breaker will
      // block the next invocation.
      if (isTruncated && attempt >= MAX_ATTEMPTS) {
        enrichment.text = truncate(
          enrichment.text + ` WARNING: This is attempt ${attempt} of ${MAX_ATTEMPTS}. The next invocation of ${toolName} will be blocked.`,
        );
      }

      // Build enriched message — additive to content, merge details
      const msg = event.message;
      const existingContent = msg.content;
      const contentArray: unknown[] = Array.isArray(existingContent)
        ? [...existingContent]
        : [{ type: "text", text: String(existingContent ?? "") }];
      contentArray.push({ type: "text", text: enrichment.text });

      const existingDetails = (msg.details ?? {}) as Record<string, unknown>;
      const details = {
        ...existingDetails,
        enricher: {
          severity: enrichment.severity,
          attempt: enrichment.attempt,
          maxAttempts: MAX_ATTEMPTS,
          errorCategory: enrichment.errorCategory,
          templateSource: enrichment.templateSource,
          toolName,
        },
      };

      return { message: { ...msg, content: contentArray, details } };
    } catch (err) {
      // Fail-open — log and return original message unmodified
      console.warn(
        "[drawbridge:tool_error_enricher] Fail-open in tool_result_persist:",
        String((err as Error)?.message ?? err ?? "unknown error").slice(0, 200),
      );
      return undefined;
    }
  }

  // -----------------------------------------------------------------------
  // before_tool_call — circuit breaker
  // -----------------------------------------------------------------------
  function handleBeforeToolCall(
    event: BeforeToolCallEvent,
    ctx: BeforeToolCallContext,
  ): BeforeToolCallResult {
    try {
      if (!ctx.sessionKey) return {};
      if (!REMEDIATION_TOOLS.has(event.toolName)) return {};

      const key = `${ctx.sessionKey}::${event.toolName}`;
      const entry = attemptMap.get(key);
      if (!entry || entry.attempts < MAX_ATTEMPTS) return {};

      return {
        block: true,
        blockReason:
          `${event.toolName} has failed ${entry.attempts} consecutive times ` +
          `(${classifyErrorCategory(entry.lastError)}). ` +
          `Inform the user that ${event.toolName} is currently unavailable and ` +
          `suggest checking the MCP server or network connectivity.`,
      };
    } catch {
      // Fail-open — allow tool call
      return {};
    }
  }

  // -----------------------------------------------------------------------
  // Session cleanup — clear entries for a given sessionKey.
  // O(n) scan over Map — bounded at 13 remediation tools per session.
  // If the Map extends beyond vigil-harbor tools in the future (P2),
  // consider a secondary index by sessionKey.
  // -----------------------------------------------------------------------
  function handleSessionCleanup(sessionKey: string): void {
    try {
      const prefix = `${sessionKey}::`;
      // Collect keys before deleting — avoids mutation during iteration.
      // ES6 Map spec guarantees delete-during-keys() is safe, but collecting
      // first is unambiguous and the set is bounded at 13 remediation tools.
      const toDelete: string[] = [];
      for (const key of attemptMap.keys()) {
        if (key.startsWith(prefix)) toDelete.push(key);
      }
      for (const key of toDelete) attemptMap.delete(key);
    } catch {
      // Fail-open — swallow
    }
  }

  return {
    registerHooks(api) {
      api.registerHook(
        "after_tool_call",
        (event: unknown, ctx: unknown) => {
          handleAfterToolCall(
            event as AfterToolCallEvent,
            ctx as AfterToolCallContext,
          );
        },
        { name: "drawbridge:after_tool_call" },
      );

      api.registerHook(
        "tool_result_persist",
        (event: unknown, ctx: unknown) => {
          return handleToolResultPersist(
            event as ToolResultPersistEvent,
            ctx as ToolResultPersistContext,
          );
        },
        { name: "drawbridge:tool_result_persist", priority: ENRICHER_PRIORITY },
      );

      api.registerHook(
        "before_tool_call",
        (event: unknown, ctx: unknown) => {
          return handleBeforeToolCall(
            event as BeforeToolCallEvent,
            ctx as BeforeToolCallContext,
          );
        },
        { name: "drawbridge:before_tool_call" },
      );

      api.registerHook(
        "session_end",
        (event: unknown, ctx: unknown) => {
          const sessionKey =
            (event as SessionLifecycleEvent)?.sessionKey ??
            (ctx as SessionLifecycleContext)?.sessionKey;
          if (sessionKey) handleSessionCleanup(sessionKey);
        },
        { name: "drawbridge:session_end_enricher" },
      );

      api.registerHook(
        "before_reset",
        (event: unknown, ctx: unknown) => {
          const sessionKey =
            (event as SessionLifecycleEvent)?.sessionKey ??
            (ctx as SessionLifecycleContext)?.sessionKey;
          if (sessionKey) handleSessionCleanup(sessionKey);
        },
        { name: "drawbridge:before_reset_enricher" },
      );
    },

    _handlers: {
      handleAfterToolCall,
      handleToolResultPersist,
      handleBeforeToolCall,
      handleSessionCleanup,
    },

    _attemptMap: attemptMap,
  };
}
