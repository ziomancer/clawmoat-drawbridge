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
  pipeline: DrawbridgePipeline;
  tracker: FrequencyTracker;
  engine?: ClawMoatPolicyEngine;
  policies?: Record<string, unknown>;
  exemptTools?: string[];
  restrictedTools?: string[];
  escalateWarnings?: boolean;
  scanParams?: boolean;
}

export interface ClawMoatPolicyEngine {
  evaluateTool(
    tool: string,
    args: Record<string, unknown>,
  ): ToolPolicyResult;
}

export interface ToolPolicyResult {
  decision: "allow" | "deny" | "warn" | "review";
  reason?: string;
  severity?: string;
  tool?: string;
  [key: string]: unknown;
}

export interface ToolCallGuardResult {
  block: boolean;
  blockReason?: string;
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
