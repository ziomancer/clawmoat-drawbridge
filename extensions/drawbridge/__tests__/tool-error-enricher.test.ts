/**
 * Tool Error Enricher — comprehensive test suite.
 *
 * Tests P0 requirements: error classification, severity, template cascade,
 * circuit breaker, parameter redaction, session cleanup, fail-open, and
 * the synchronous-write invariant.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createToolErrorEnricher,
  classifyErrorCategory,
  classifySeverity,
  redactParams,
  extractToolNameFromMessage,
  normalizeToolName,
  GUARD_TRUNCATION_SUFFIX,
  MAX_ATTEMPTS,
  MAX_ENRICHMENT_CHARS,
  REMEDIATION_TOOLS,
} from "../src/hooks/tool-error-enricher.js";
import type { ToolErrorEnricher } from "../src/hooks/tool-error-enricher.js";
import {
  makeToolResultPersistEvent,
  makeToolResultPersistCtx,
  makeAfterToolCallEvent,
  makeAfterToolCallCtx,
  makeBeforeToolCallEvent,
  makeBeforeToolCallCtx,
} from "./helpers.js";

// ---------------------------------------------------------------------------
// Shared enricher instance — reset before each test
// ---------------------------------------------------------------------------

let enricher: ToolErrorEnricher;

beforeEach(() => {
  enricher = createToolErrorEnricher();
});

// ===========================================================================
// Error category detection
// ===========================================================================

describe("classifyErrorCategory", () => {
  it.each([
    ["Request timeout", "timeout"],
    ["timed out waiting for response", "timeout"],
    ["ETIMEDOUT", "timeout"],
    ["deadline exceeded", "timeout"],
  ] as const)("detects timeout: %s", (input, expected) => {
    expect(classifyErrorCategory(input)).toBe(expected);
  });

  it.each([
    ["HTTP 429 Too Many Requests", "rate_limit"],
    ["rate limit exceeded", "rate_limit"],
    ["too many requests", "rate_limit"],
    ["request throttled", "rate_limit"],
  ] as const)("detects rate_limit: %s", (input, expected) => {
    expect(classifyErrorCategory(input)).toBe(expected);
  });

  it.each([
    ["HTTP 401 Unauthorized", "auth_failure"],
    ["HTTP 403 Forbidden", "auth_failure"],
    ["unauthorized access", "auth_failure"],
    ["forbidden resource", "auth_failure"],
    ["auth token expired", "auth_failure"],
    ["invalid credential", "auth_failure"],
    ["authentication failed", "auth_failure"],
    ["failed to authenticate with server", "auth_failure"],
  ] as const)("detects auth_failure: %s", (input, expected) => {
    expect(classifyErrorCategory(input)).toBe(expected);
  });

  it.each([
    ["ECONNREFUSED", "server_unreachable"],
    ["ENOTFOUND", "server_unreachable"],
    ["getaddrinfo ENOTFOUND postgres", "server_unreachable"],
    ["EHOSTUNREACH", "server_unreachable"],
    ["network error occurred", "server_unreachable"],
    ["connection refused", "server_unreachable"],
    ["fetch failed", "server_unreachable"],
  ] as const)("detects server_unreachable: %s", (input, expected) => {
    expect(classifyErrorCategory(input)).toBe(expected);
  });

  it.each([
    ["invalid params", "validation"],
    ["required field missing", "validation"],
    ["missing parameter: query", "validation"],
    ["must be a string", "validation"],
    ["must have at least one item", "validation"],
    ["schema validation failed", "validation"],
    ["expected number", "validation"],
  ] as const)("detects validation: %s", (input, expected) => {
    expect(classifyErrorCategory(input)).toBe(expected);
  });

  it("falls back to unknown for unrecognized errors", () => {
    expect(classifyErrorCategory("something went wrong")).toBe("unknown");
    expect(classifyErrorCategory("")).toBe("unknown");
  });
});

// ===========================================================================
// Severity classifier
// ===========================================================================

describe("classifySeverity", () => {
  it("returns transient for 1st timeout", () => {
    expect(classifySeverity("timeout", 1, false)).toBe("transient");
  });

  it("returns transient for 1st rate_limit", () => {
    expect(classifySeverity("rate_limit", 1, false)).toBe("transient");
  });

  it("returns recoverable for auth_failure (never transient)", () => {
    expect(classifySeverity("auth_failure", 1, false)).toBe("recoverable");
  });

  it("returns recoverable for 2nd consecutive failure", () => {
    expect(classifySeverity("timeout", 2, false)).toBe("recoverable");
  });

  it("returns terminal at MAX_ATTEMPTS", () => {
    expect(classifySeverity("timeout", MAX_ATTEMPTS, false)).toBe("terminal");
  });

  it("returns terminal for server_unreachable at attempt >= 2", () => {
    expect(classifySeverity("server_unreachable", 2, false)).toBe("terminal");
  });

  it("returns recoverable for validation (always needs param echo)", () => {
    expect(classifySeverity("validation", 1, false)).toBe("recoverable");
    expect(classifySeverity("validation", 2, false)).toBe("recoverable");
  });

  it("returns recoverable for truncated input regardless of category", () => {
    expect(classifySeverity("timeout", 1, true)).toBe("recoverable");
    expect(classifySeverity("rate_limit", 1, true)).toBe("recoverable");
  });

  it("returns recoverable for truncated input even at MAX_ATTEMPTS", () => {
    // Spec classifier order: isTruncated is checked before attemptCount.
    // Truncated text at MAX_ATTEMPTS still returns "recoverable" — can't reliably classify.
    // The before_tool_call circuit breaker still blocks (reads Map, not severity).
    expect(classifySeverity("timeout", MAX_ATTEMPTS, true)).toBe("recoverable");
  });

  it("returns recoverable for unknown category", () => {
    expect(classifySeverity("unknown", 1, false)).toBe("recoverable");
  });
});

// ===========================================================================
// Parameter redaction
// ===========================================================================

describe("redactParams", () => {
  it("redacts global sensitive params", () => {
    const result = redactParams({ token: "secret-123", query: "test" });
    expect(result).toContain("token: [REDACTED]");
    expect(result).toContain('query: "test"');
    expect(result).not.toContain("secret-123");
  });

  it("redacts case-insensitively", () => {
    const result = redactParams({ ApiKey: "sk-abc", PASSWORD: "hunter2" });
    expect(result).toContain("ApiKey: [REDACTED]");
    expect(result).toContain("PASSWORD: [REDACTED]");
  });

  it("echoes non-sensitive params verbatim", () => {
    const result = redactParams({ namespace: "personal", max_results: 5 });
    expect(result).toContain('namespace: "personal"');
    expect(result).toContain("max_results: 5");
  });

  it("handles empty params", () => {
    expect(redactParams({})).toBe("");
  });

  it("redacts all known sensitive param names", () => {
    const sensitive = ["token", "password", "apiKey", "api_key", "secret", "authorization", "credentials", "bearer", "session_token"];
    for (const key of sensitive) {
      const result = redactParams({ [key]: "value" });
      expect(result).toContain("[REDACTED]");
      expect(result).not.toContain('"value"');
    }
  });
});

// ===========================================================================
// extractToolNameFromMessage
// ===========================================================================

describe("extractToolNameFromMessage", () => {
  it("extracts name from content array block", () => {
    const msg = { content: [{ type: "tool_result", name: "memory_search", text: "error" }] };
    expect(extractToolNameFromMessage(msg)).toBe("memory_search");
  });

  it("extracts toolName from content array block", () => {
    const msg = { content: [{ type: "tool_result", toolName: "memory_query", text: "error" }] };
    expect(extractToolNameFromMessage(msg)).toBe("memory_query");
  });

  it("returns undefined for string content", () => {
    const msg = { content: "Request timeout" };
    expect(extractToolNameFromMessage(msg)).toBeUndefined();
  });

  it("returns undefined when content array has no tool-identifying blocks", () => {
    const msg = { content: [{ type: "text", text: "error" }] };
    expect(extractToolNameFromMessage(msg)).toBeUndefined();
  });

  it("returns undefined for tool_use_id without name (opaque ID)", () => {
    const msg = { content: [{ type: "tool_result", tool_use_id: "toolu_abc123", text: "error" }] };
    expect(extractToolNameFromMessage(msg)).toBeUndefined();
  });

  it("returns undefined for undefined content", () => {
    expect(extractToolNameFromMessage({})).toBeUndefined();
  });

  it("returns undefined for null content", () => {
    expect(extractToolNameFromMessage({ content: null })).toBeUndefined();
  });

  it("falls back to top-level toolName on message", () => {
    const msg = { toolName: "memory_fetch", content: "error" };
    expect(extractToolNameFromMessage(msg)).toBe("memory_fetch");
  });
});

// ===========================================================================
// Template cascade
// ===========================================================================

describe("template cascade", () => {
  function enrichWithError(toolName: string, errorText: string, attempt = 1): string | undefined {
    const { handleAfterToolCall, handleToolResultPersist } = enricher._handlers;
    // Seed the attempt map
    const ctx = { sessionKey: "test-key" };
    for (let i = 0; i < attempt; i++) {
      handleAfterToolCall(
        { toolName, params: { query: "test" }, error: errorText },
        ctx,
      );
    }

    const result = handleToolResultPersist(
      makeToolResultPersistEvent({
        message: { isError: true, content: [{ type: "text", text: errorText }] },
      }),
      { sessionKey: "test-key", toolName },
    );

    if (!result) return undefined;
    const content = result.message.content as Array<{ type: string; text: string }>;
    return content[content.length - 1]?.text;
  }

  it("uses tool-specific template for memory_search source_type validation", () => {
    const text = enrichWithError("memory_search", "invalid params: source_type not supported");
    expect(text).toContain("memory_search does not support source_type");
    expect(text).toContain("memory_query");
  });

  it("uses tool-specific template for memory_query metadata_filter error", () => {
    const text = enrichWithError("memory_query", "invalid metadata_filter operator $foo");
    expect(text).toContain("metadata_filter supports comparison operators");
  });

  it("uses tool-specific template for memory_traverse depth error", () => {
    const text = enrichWithError("memory_traverse", "invalid depth: must be 1-3");
    expect(text).toContain("depth must be 1-3");
  });

  it("uses tool-specific template for memory_evaluate_process timeout", () => {
    const text = enrichWithError("memory_evaluate_process", "Request timeout");
    expect(text).toContain("long-running (up to 5 minutes)");
  });

  it("uses category template for retrieval tool timeout (2nd attempt)", () => {
    const text = enrichWithError("memory_search", "Request timeout", 2);
    expect(text).toContain("Retry with narrower query");
    expect(text).toContain("memory_query");
  });

  it("uses category template for mutation tool validation", () => {
    const text = enrichWithError("memory_ingest", "invalid params: text required");
    expect(text).toContain("memory_ingest requires either text or image_data");
  });

  it("uses category template for utility tool timeout", () => {
    const text = enrichWithError("memory_list", "Request timeout");
    // 1st attempt is transient — global template
    // Check it still gets a reasonable template
    expect(text).toBeDefined();
    expect(text).toContain("Retry");
  });

  it("uses global template for unknown error category", () => {
    const text = enrichWithError("memory_search", "kaboom zort plonk");
    expect(text).toContain("TOOL FAILURE");
    expect(text).toContain("Retry once");
  });

  it("uses terminal template at MAX_ATTEMPTS", () => {
    const text = enrichWithError("memory_search", "Request timeout", MAX_ATTEMPTS);
    expect(text).toContain("CIRCUIT OPEN");
    expect(text).toContain("Do NOT retry");
    expect(text).toContain("Inform the user");
  });
});

// ===========================================================================
// Circuit breaker (before_tool_call)
// ===========================================================================

describe("circuit breaker", () => {
  it("blocks at MAX_ATTEMPTS consecutive failures", () => {
    const { handleAfterToolCall, handleBeforeToolCall } = enricher._handlers;
    const ctx = { sessionKey: "session-1" };

    // Fail 3 times
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      handleAfterToolCall(
        { toolName: "memory_search", error: "timeout" },
        ctx,
      );
    }

    const result = handleBeforeToolCall({ toolName: "memory_search" }, ctx);
    expect(result.block).toBe(true);
    expect(result.blockReason).toContain("memory_search");
    expect(result.blockReason).toContain("failed");
    expect(result.blockReason).toContain("Inform the user");
  });

  it("does NOT block when attempts < MAX_ATTEMPTS", () => {
    const { handleAfterToolCall, handleBeforeToolCall } = enricher._handlers;
    const ctx = { sessionKey: "session-1" };

    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);

    const result = handleBeforeToolCall({ toolName: "memory_search" }, ctx);
    expect(result.block).toBeUndefined();
  });

  it("does NOT block non-remediation-map tools", () => {
    const { handleBeforeToolCall } = enricher._handlers;
    const result = handleBeforeToolCall(
      { toolName: "some_other_tool" },
      { sessionKey: "session-1" },
    );
    expect(result.block).toBeUndefined();
  });

  it("resets after successful call", () => {
    const { handleAfterToolCall, handleBeforeToolCall } = enricher._handlers;
    const ctx = { sessionKey: "session-1" };

    // Fail twice
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);

    // Succeed
    handleAfterToolCall({ toolName: "memory_search" }, ctx);

    // Fail once more — should not be blocked (counter reset)
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);

    const result = handleBeforeToolCall({ toolName: "memory_search" }, ctx);
    expect(result.block).toBeUndefined();
  });
});

// ===========================================================================
// after_tool_call counter
// ===========================================================================

describe("after_tool_call counter", () => {
  it("increments on error", () => {
    const { handleAfterToolCall } = enricher._handlers;
    const ctx = { sessionKey: "s1" };

    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    expect(enricher._attemptMap.get("s1::memory_search")?.attempts).toBe(1);

    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    expect(enricher._attemptMap.get("s1::memory_search")?.attempts).toBe(2);
  });

  it("resets to 0 on success", () => {
    const { handleAfterToolCall } = enricher._handlers;
    const ctx = { sessionKey: "s1" };

    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    handleAfterToolCall({ toolName: "memory_search" }, ctx);

    expect(enricher._attemptMap.get("s1::memory_search")?.attempts).toBe(0);
  });

  it("stashes params for echoing", () => {
    const { handleAfterToolCall } = enricher._handlers;
    const ctx = { sessionKey: "s1" };
    const params = { query: "test", namespace: "personal" };

    handleAfterToolCall({ toolName: "memory_search", params, error: "timeout" }, ctx);
    expect(enricher._attemptMap.get("s1::memory_search")?.lastParams).toEqual(params);
  });

  it("ignores non-remediation-map tools", () => {
    const { handleAfterToolCall } = enricher._handlers;
    handleAfterToolCall(
      { toolName: "some_other_tool", error: "timeout" },
      { sessionKey: "s1" },
    );
    expect(enricher._attemptMap.size).toBe(0);
  });
});

// ===========================================================================
// tool_result_persist enrichment
// ===========================================================================

describe("tool_result_persist enrichment", () => {
  it("skips when isError is false and no details.status error", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: { isError: false, content: [{ type: "text", text: "success" }] },
      }),
      makeToolResultPersistCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("enriches when isError is false but details.status is 'error' (OpenClaw MCP wrapping)", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: false,
          content: [{ type: "text", text: '{"status": "error", "tool": "vigil-harbor__memory_search", "error": "fetch failed"}' }],
          details: { status: "error", tool: "vigil-harbor__memory_search", error: "fetch failed" },
        },
      }),
      makeToolResultPersistCtx(),
    );
    expect(result).toBeDefined();
    const content = result!.message.content as Array<{ type: string; text: string }>;
    // Enrichment appended
    expect(content.length).toBe(2);
    // Uses details.error for classification (cleaner than JSON content)
    expect(content[1]!.text).toContain("SERVER UNREACHABLE");
  });

  it("enriches when content starts with 'Error:' (MCP app-level error as content)", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: false,
          content: [{ type: "text", text: 'Error: search failed\nDetails: getaddrinfo ENOTFOUND postgres\nQuery: "test"\nSuggestion: verify container is running' }],
          details: { mcpServer: "vigil-harbor", mcpTool: "memory_search" },
        },
      }),
      makeToolResultPersistCtx(),
    );
    expect(result).toBeDefined();
    const content = result!.message.content as Array<{ type: string; text: string }>;
    expect(content.length).toBe(2);
    // ENOTFOUND classified as server_unreachable
    expect(content[1]!.text).toContain("SERVER UNREACHABLE");
  });

  it("does NOT trigger content detection on successful results containing 'error' mid-text", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: false,
          content: [{ type: "text", text: "Found 3 records. No errors detected in the dataset." }],
          details: { mcpServer: "vigil-harbor", mcpTool: "memory_search" },
        },
      }),
      makeToolResultPersistCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("compensates attempt counter when after_tool_call missed the error", () => {
    // No prior after_tool_call — counter is unset
    expect(enricher._attemptMap.size).toBe(0);

    enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: false,
          content: [{ type: "text", text: '{"status": "error", "error": "fetch failed"}' }],
          details: { status: "error", error: "fetch failed" },
        },
      }),
      makeToolResultPersistCtx(),
    );

    // Counter should have been compensated to 1
    expect(enricher._attemptMap.get("test-session-key::memory_search")?.attempts).toBe(1);
  });

  it("skips when isSynthetic is true", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({ isSynthetic: true }),
      makeToolResultPersistCtx(),
    );
    expect(result).toBeUndefined();
  });

  it("skips non-remediation-map tools", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      makeToolResultPersistCtx({ toolName: "some_other_tool" }),
    );
    expect(result).toBeUndefined();
  });

  it("skips when sessionKey is undefined", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      makeToolResultPersistCtx({ sessionKey: undefined }),
    );
    expect(result).toBeUndefined();
  });

  it("appends enrichment text block to content array", () => {
    // Seed attempt map
    enricher._handlers.handleAfterToolCall(
      makeAfterToolCallEvent(),
      makeAfterToolCallCtx(),
    );

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      makeToolResultPersistCtx(),
    );

    expect(result).toBeDefined();
    const content = result!.message.content as Array<{ type: string; text: string }>;
    // Original content preserved + enrichment appended
    expect(content.length).toBe(2);
    expect(content[0]!.text).toBe("Request timeout"); // original
    expect(content[1]!.text).toContain("memory_search"); // enrichment
  });

  it("preserves original error text", () => {
    enricher._handlers.handleAfterToolCall(makeAfterToolCallEvent(), makeAfterToolCallCtx());

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      makeToolResultPersistCtx(),
    );

    const content = result!.message.content as Array<{ type: string; text: string }>;
    expect(content[0]!.text).toBe("Request timeout");
  });

  it("merges details.enricher metadata additively", () => {
    enricher._handlers.handleAfterToolCall(makeAfterToolCallEvent(), makeAfterToolCallCtx());

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: true,
          content: [{ type: "text", text: "Request timeout" }],
          details: { existing: "data" },
        },
      }),
      makeToolResultPersistCtx(),
    );

    const details = result!.message.details as Record<string, unknown>;
    expect(details.existing).toBe("data"); // preserved
    expect(details.enricher).toBeDefined();

    const enricherDetails = details.enricher as Record<string, unknown>;
    expect(enricherDetails.severity).toBeDefined();
    expect(enricherDetails.attempt).toBeDefined();
    expect(enricherDetails.maxAttempts).toBe(MAX_ATTEMPTS);
    expect(enricherDetails.errorCategory).toBeDefined();
    expect(enricherDetails.templateSource).toBeDefined();
    expect(enricherDetails.toolName).toBe("memory_search");
  });

  it("falls back to extracting toolName from message body", () => {
    enricher._handlers.handleAfterToolCall(
      makeAfterToolCallEvent({ toolName: "memory_query" }),
      makeAfterToolCallCtx(),
    );

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: true,
          content: [{ type: "tool_result", name: "memory_query", text: "invalid params" }],
        },
      }),
      makeToolResultPersistCtx({ toolName: undefined }), // no toolName in ctx
    );

    expect(result).toBeDefined();
    const details = result!.message.details as Record<string, unknown>;
    expect((details.enricher as Record<string, unknown>).toolName).toBe("memory_query");
  });

  it("handles string content (not array)", () => {
    enricher._handlers.handleAfterToolCall(makeAfterToolCallEvent(), makeAfterToolCallCtx());

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: { isError: true, content: "Request timeout" },
      }),
      makeToolResultPersistCtx(),
    );

    expect(result).toBeDefined();
    const content = result!.message.content as Array<{ type: string; text: string }>;
    expect(content.length).toBe(2);
    expect(content[0]!.text).toBe("Request timeout");
  });
});

// ===========================================================================
// Sync-handler guarantee
// ===========================================================================

describe("sync-handler guarantee", () => {
  it("tool_result_persist handler returns a plain object, not a Promise", () => {
    enricher._handlers.handleAfterToolCall(makeAfterToolCallEvent(), makeAfterToolCallCtx());

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      makeToolResultPersistCtx(),
    );

    // Must not be a Promise — handler is synchronous
    expect(result).not.toBeInstanceOf(Promise);
  });

  it("before_tool_call handler returns a plain object, not a Promise", () => {
    const result = enricher._handlers.handleBeforeToolCall(
      makeBeforeToolCallEvent(),
      makeBeforeToolCallCtx(),
    );
    expect(result).not.toBeInstanceOf(Promise);
  });
});

// ===========================================================================
// Session cleanup
// ===========================================================================

describe("session cleanup", () => {
  it("clears all entries for a sessionKey", () => {
    const { handleAfterToolCall, handleSessionCleanup } = enricher._handlers;
    const ctx = { sessionKey: "session-A" };

    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    handleAfterToolCall({ toolName: "memory_query", error: "timeout" }, ctx);
    expect(enricher._attemptMap.size).toBe(2);

    handleSessionCleanup("session-A");
    expect(enricher._attemptMap.size).toBe(0);
  });

  it("does not affect other sessions", () => {
    const { handleAfterToolCall, handleSessionCleanup } = enricher._handlers;

    handleAfterToolCall(
      { toolName: "memory_search", error: "timeout" },
      { sessionKey: "session-A" },
    );
    handleAfterToolCall(
      { toolName: "memory_search", error: "timeout" },
      { sessionKey: "session-B" },
    );
    expect(enricher._attemptMap.size).toBe(2);

    handleSessionCleanup("session-A");
    expect(enricher._attemptMap.size).toBe(1);
    expect(enricher._attemptMap.has("session-B::memory_search")).toBe(true);
  });
});

// ===========================================================================
// sessionKey undefined — no-op guards
// ===========================================================================

describe("sessionKey undefined guards", () => {
  it("after_tool_call no-ops when sessionKey is undefined", () => {
    enricher._handlers.handleAfterToolCall(
      { toolName: "memory_search", error: "timeout" },
      { sessionKey: undefined },
    );
    expect(enricher._attemptMap.size).toBe(0);
  });

  it("tool_result_persist no-ops when sessionKey is undefined", () => {
    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      { sessionKey: undefined, toolName: "memory_search" },
    );
    expect(result).toBeUndefined();
  });

  it("before_tool_call returns empty (allows call) when sessionKey is undefined", () => {
    const result = enricher._handlers.handleBeforeToolCall(
      { toolName: "memory_search" },
      { sessionKey: undefined },
    );
    expect(result).toEqual({});
  });
});

// ===========================================================================
// Fail-open guarantees
// ===========================================================================

describe("fail-open guarantees", () => {
  it("after_tool_call swallows exceptions", () => {
    // Force an error by providing a getter that throws
    const badEvent = {
      get toolName(): string { throw new Error("boom"); },
    } as unknown as Parameters<typeof enricher._handlers.handleAfterToolCall>[0];

    // Should not throw
    expect(() => {
      enricher._handlers.handleAfterToolCall(badEvent, { sessionKey: "s1" });
    }).not.toThrow();
  });

  it("tool_result_persist returns undefined on exception", () => {
    // Poison the attempt map to trigger an error during template resolution
    const key = "test-key::memory_search";
    enricher._attemptMap.set(key, {
      attempts: 1,
      // lastParams getter that throws
      get lastParams(): never { throw new Error("boom"); },
      lastError: "timeout",
      lastTimestamp: Date.now(),
    } as unknown as import("../src/hooks/tool-error-enricher.js").AttemptEntry);

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent(),
      makeToolResultPersistCtx({ sessionKey: "test-key" }),
    );

    // Fail-open: returns undefined (original message unmodified)
    expect(result).toBeUndefined();
  });

  it("before_tool_call returns empty object on exception", () => {
    // Poison the attempt map
    const key = "s1::memory_search";
    Object.defineProperty(enricher._attemptMap, "get", {
      value: () => { throw new Error("boom"); },
    });

    const result = enricher._handlers.handleBeforeToolCall(
      { toolName: "memory_search" },
      { sessionKey: "s1" },
    );

    expect(result).toEqual({});
  });
});

// ===========================================================================
// Enrichment budget
// ===========================================================================

describe("enrichment budget", () => {
  it("all enrichment text stays under MAX_ENRICHMENT_CHARS", () => {
    const tools = [...REMEDIATION_TOOLS];
    const errorTexts = [
      "Request timeout",
      "HTTP 429 Too Many Requests",
      "HTTP 401 Unauthorized",
      "ECONNREFUSED",
      "invalid params: source_type not supported in memory_search. Also metadata_filter operator $foo unknown. depth must be positive.",
      "something completely unexpected happened and this is a rather long error message that keeps going",
    ];

    for (const tool of tools) {
      for (const errorText of errorTexts) {
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
          // Fresh enricher for each combo
          const e = createToolErrorEnricher();
          const ctx = { sessionKey: "budget-test" };

          for (let i = 0; i < attempt; i++) {
            e._handlers.handleAfterToolCall(
              { toolName: tool, params: { query: "test", namespace: "personal", max_results: 10, source_type: "document", tags: ["a", "b"] }, error: errorText },
              ctx,
            );
          }

          const result = e._handlers.handleToolResultPersist(
            {
              message: { isError: true, content: [{ type: "text", text: errorText }] },
              isSynthetic: false,
            },
            { sessionKey: "budget-test", toolName: tool },
          );

          if (result) {
            const content = result.message.content as Array<{ type: string; text: string }>;
            const enrichmentText = content[content.length - 1]!.text;
            expect(enrichmentText.length).toBeLessThanOrEqual(MAX_ENRICHMENT_CHARS);
          }
        }
      }
    }
  });
});

// ===========================================================================
// Integration: full lifecycle
// ===========================================================================

describe("integration: full lifecycle", () => {
  it("call fails 3x → circuit breaks → new session unaffected", () => {
    const { handleAfterToolCall, handleBeforeToolCall, handleToolResultPersist, handleSessionCleanup } = enricher._handlers;
    const ctx1 = { sessionKey: "session-1" };
    const ctx2 = { sessionKey: "session-2" };

    // Session 1: fail 3 times
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx1);
    }

    // Session 1: circuit broken
    const blocked = handleBeforeToolCall({ toolName: "memory_search" }, ctx1);
    expect(blocked.block).toBe(true);

    // Session 2: unaffected
    const allowed = handleBeforeToolCall({ toolName: "memory_search" }, ctx2);
    expect(allowed.block).toBeUndefined();

    // Session 1: cleanup
    handleSessionCleanup("session-1");
    const afterCleanup = handleBeforeToolCall({ toolName: "memory_search" }, ctx1);
    expect(afterCleanup.block).toBeUndefined();
  });

  it("enrichment output evolves with attempt count", () => {
    const { handleAfterToolCall, handleToolResultPersist } = enricher._handlers;
    const ctx = { sessionKey: "evolve-test" };
    const errorText = "Request timeout";

    // Attempt 1: transient
    handleAfterToolCall({ toolName: "memory_search", error: errorText }, ctx);
    const r1 = handleToolResultPersist(
      { message: { isError: true, content: [{ type: "text", text: errorText }] }, isSynthetic: false },
      { sessionKey: "evolve-test", toolName: "memory_search" },
    );
    const t1 = (r1!.message.content as Array<{ text: string }>).at(-1)!.text;
    expect(t1).toContain("Retry once");
    expect((r1!.message.details as Record<string, unknown>).enricher).toMatchObject({ severity: "transient", attempt: 1 });

    // Attempt 2: recoverable (category template)
    handleAfterToolCall({ toolName: "memory_search", error: errorText }, ctx);
    const r2 = handleToolResultPersist(
      { message: { isError: true, content: [{ type: "text", text: errorText }] }, isSynthetic: false },
      { sessionKey: "evolve-test", toolName: "memory_search" },
    );
    const t2 = (r2!.message.content as Array<{ text: string }>).at(-1)!.text;
    expect(t2).toContain("narrower query");
    expect((r2!.message.details as Record<string, unknown>).enricher).toMatchObject({ severity: "recoverable", attempt: 2 });

    // Attempt 3: terminal
    handleAfterToolCall({ toolName: "memory_search", error: errorText }, ctx);
    const r3 = handleToolResultPersist(
      { message: { isError: true, content: [{ type: "text", text: errorText }] }, isSynthetic: false },
      { sessionKey: "evolve-test", toolName: "memory_search" },
    );
    const t3 = (r3!.message.content as Array<{ text: string }>).at(-1)!.text;
    expect(t3).toContain("CIRCUIT OPEN");
    expect(t3).toContain("Do NOT retry");
    expect((r3!.message.details as Record<string, unknown>).enricher).toMatchObject({ severity: "terminal", attempt: 3 });
  });

  it("counter-ahead limitation: circuit trips if counter is ahead of transcript", () => {
    // Simulates the before_message_write blocking scenario.
    // after_tool_call increments the counter, but the enriched message
    // is blocked by before_message_write and never persisted.
    // The counter is now one ahead — conservative error.
    const { handleAfterToolCall, handleBeforeToolCall } = enricher._handlers;
    const ctx = { sessionKey: "counter-ahead" };

    // 2 real failures (both reach transcript)
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);

    // 3rd failure — after_tool_call increments counter to 3,
    // but imagine before_message_write blocks the enriched message.
    // The counter is at 3 even though only 2 errors are in the transcript.
    handleAfterToolCall({ toolName: "memory_search", error: "timeout" }, ctx);

    // Circuit is now open — this is the conservative error.
    // A 4th call would be blocked.
    const result = handleBeforeToolCall({ toolName: "memory_search" }, ctx);
    expect(result.block).toBe(true);
    // Acknowledged: the circuit tripped after the 3rd counter increment,
    // even though only 2 errors may be in the transcript. This is safer
    // than tripping one attempt late.
  });
});

// ===========================================================================
// Tool name normalization (MCP server prefix stripping)
// ===========================================================================

describe("normalizeToolName", () => {
  it("returns unprefixed name as-is", () => {
    expect(normalizeToolName("memory_search")).toBe("memory_search");
  });

  it("strips MCP server prefix", () => {
    expect(normalizeToolName("vigil-harbor__memory_search")).toBe("memory_search");
    expect(normalizeToolName("vigil-harbor__memory_status")).toBe("memory_status");
    expect(normalizeToolName("vigil-harbor__memory_ingest")).toBe("memory_ingest");
  });

  it("returns original if unprefixed name is not in remediation set", () => {
    expect(normalizeToolName("vigil-harbor__some_other_tool")).toBe("vigil-harbor__some_other_tool");
  });

  it("returns original for non-prefixed unknown tools", () => {
    expect(normalizeToolName("some_other_tool")).toBe("some_other_tool");
  });
});

// ===========================================================================
// Prefixed tool names (live OpenClaw MCP format)
// ===========================================================================

describe("prefixed tool names", () => {
  it("after_tool_call increments counter for prefixed tool name", () => {
    enricher._handlers.handleAfterToolCall(
      { toolName: "vigil-harbor__memory_search", error: "fetch failed" },
      { sessionKey: "prefix-test" },
    );
    // Stored under normalized key
    expect(enricher._attemptMap.get("prefix-test::memory_search")?.attempts).toBe(1);
  });

  it("tool_result_persist enriches prefixed tool errors", () => {
    enricher._handlers.handleAfterToolCall(
      { toolName: "vigil-harbor__memory_search", error: "fetch failed" },
      { sessionKey: "prefix-test" },
    );

    const result = enricher._handlers.handleToolResultPersist(
      makeToolResultPersistEvent({
        message: {
          isError: false,
          content: [{ type: "text", text: 'Error: search failed\nDetails: getaddrinfo ENOTFOUND postgres' }],
          details: { mcpServer: "vigil-harbor", mcpTool: "memory_search" },
        },
      }),
      { sessionKey: "prefix-test", toolName: "vigil-harbor__memory_search" },
    );

    expect(result).toBeDefined();
    const content = result!.message.content as Array<{ type: string; text: string }>;
    expect(content.length).toBe(2);
    expect(content[1]!.text).toContain("SERVER UNREACHABLE");
  });

  it("before_tool_call blocks prefixed tool after MAX_ATTEMPTS", () => {
    const ctx = { sessionKey: "prefix-block" };
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      enricher._handlers.handleAfterToolCall(
        { toolName: "vigil-harbor__memory_search", error: "timeout" },
        ctx,
      );
    }
    const result = enricher._handlers.handleBeforeToolCall(
      { toolName: "vigil-harbor__memory_search" },
      ctx,
    );
    expect(result.block).toBe(true);
  });
});

// ===========================================================================
// Remediation map completeness
// ===========================================================================

describe("remediation map", () => {
  it("contains exactly 13 vigil-harbor MCP tools", () => {
    expect(REMEDIATION_TOOLS.size).toBe(13);
  });

  it("includes all expected tools", () => {
    const expected = [
      "memory_search", "memory_query", "memory_traverse", "memory_fetch",
      "memory_ingest", "memory_link", "memory_delete",
      "memory_list", "memory_sources", "memory_status",
      "memory_embed_text", "memory_evaluate_process", "memory_changes",
    ];
    for (const tool of expected) {
      expect(REMEDIATION_TOOLS.has(tool)).toBe(true);
    }
  });
});

// ===========================================================================
// Truncation detection
// ===========================================================================

describe("truncation detection", () => {
  it("defaults to recoverable severity when truncation suffix detected", () => {
    const { handleAfterToolCall, handleToolResultPersist } = enricher._handlers;
    const truncatedError = `Some error text that was cut off${GUARD_TRUNCATION_SUFFIX}`;

    handleAfterToolCall(
      { toolName: "memory_search", error: truncatedError },
      { sessionKey: "trunc-test" },
    );

    const result = handleToolResultPersist(
      {
        message: { isError: true, content: [{ type: "text", text: truncatedError }] },
        isSynthetic: false,
      },
      { sessionKey: "trunc-test", toolName: "memory_search" },
    );

    expect(result).toBeDefined();
    const details = (result!.message.details as Record<string, unknown>).enricher as Record<string, unknown>;
    expect(details.severity).toBe("recoverable");
  });

  it("warns about imminent block when truncated AND at MAX_ATTEMPTS", () => {
    const { handleAfterToolCall, handleToolResultPersist } = enricher._handlers;
    const truncatedError = `timeout something${GUARD_TRUNCATION_SUFFIX}`;

    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      handleAfterToolCall(
        { toolName: "memory_search", error: truncatedError },
        { sessionKey: "trunc-max" },
      );
    }

    const result = handleToolResultPersist(
      {
        message: { isError: true, content: [{ type: "text", text: truncatedError }] },
        isSynthetic: false,
      },
      { sessionKey: "trunc-max", toolName: "memory_search" },
    );

    expect(result).toBeDefined();
    const details = (result!.message.details as Record<string, unknown>).enricher as Record<string, unknown>;
    // Severity stays recoverable (can't classify truncated text)
    expect(details.severity).toBe("recoverable");
    // But enrichment text warns about the imminent block
    const content = result!.message.content as Array<{ type: string; text: string }>;
    const enrichmentText = content[content.length - 1]!.text;
    expect(enrichmentText).toContain("will be blocked");
  });
});
