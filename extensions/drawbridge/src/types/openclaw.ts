/**
 * Structural type stubs for OpenClaw hook events.
 * OpenClaw's plugin loader matches on shape — no runtime import needed.
 * The entry point uses the real `definePluginEntry` from the SDK.
 */

export interface HookContext {
  channelId?: string;
  accountId?: string;
  conversationId?: string;
  sessionKey?: string;
  senderId?: string;
}

export interface MessageReceivedEvent {
  from: string;
  content: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

export interface BeforeDispatchEvent {
  content: string;
  body?: string;
  channel?: string;
  sessionKey?: string;
  senderId?: string;
  isGroup?: boolean;
  timestamp?: number;
}

export interface BeforeDispatchContext {
  channelId?: string;
  accountId?: string;
  conversationId?: string;
  sessionKey?: string;
  senderId?: string;
}

export interface BeforeDispatchResult {
  handled: boolean;
  text?: string;
}

export interface MessageSendingEvent {
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
}

export interface MessageSendingResult {
  content?: string;
  cancel?: boolean;
}

export interface LlmOutputEvent {
  runId: string;
  sessionId: string;
  provider: string;
  model: string;
  assistantTexts: string[];
  lastAssistant?: unknown;
  usage?: {
    input?: number;
    output?: number;
    total?: number;
  };
}

export interface GatewayStopEvent {
  reason?: string;
}

// ---------------------------------------------------------------------------
// Tool error enricher hook events
// ---------------------------------------------------------------------------

/** Event shape for `tool_result_persist` — intercepts tool result messages before transcript write. */
export interface ToolResultPersistEvent {
  /** AgentMessage — duck-typed. Check `(message as { isError?: boolean }).isError`. */
  message: Record<string, unknown>;
  /** Synthetic results are fabricated by guard/repair for orphaned tool calls — not real errors. */
  isSynthetic?: boolean;
}

export interface ToolResultPersistContext {
  sessionKey?: string;
  toolName?: string;
}

/** Event shape for `after_tool_call` — fires after tool execution (void, fire-and-forget). */
export interface AfterToolCallEvent {
  toolName: string;
  params?: Record<string, unknown>;
  /** Defined when the tool call failed. Undefined on success. */
  error?: string;
}

export interface AfterToolCallContext {
  sessionKey?: string;
}

/** Event shape for `before_tool_call` — fires before tool invocation (sequential, can block). */
export interface BeforeToolCallEvent {
  toolName: string;
}

export interface BeforeToolCallContext {
  sessionKey?: string;
}

export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
}

/** Event shape for `session_end` / `before_reset` — cleanup hooks. */
export interface SessionLifecycleEvent {
  sessionKey?: string;
}

export interface SessionLifecycleContext {
  sessionKey?: string;
}
