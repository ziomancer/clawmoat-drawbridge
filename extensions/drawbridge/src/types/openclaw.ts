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
