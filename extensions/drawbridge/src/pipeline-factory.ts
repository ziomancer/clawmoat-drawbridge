/**
 * Plugin state factory — async initialization.
 * Resolves ClawMoat engine (ESM import with createRequire fallback),
 * constructs shared FrequencyTracker, creates inbound/outbound pipelines,
 * manages scan cache with TTL/cap/sweep.
 */

import {
  DrawbridgePipeline,
  FrequencyTracker,
  sha256,
} from "@vigil-harbor/clawmoat-drawbridge";
import type { PipelineResult } from "@vigil-harbor/clawmoat-drawbridge";
import type { ResolvedConfig } from "./config.js";
import { createAuditSink } from "./audit-sink.js";
import type { AuditSink, VigilHarborIngestFn, AlertNotifyFn } from "./audit-sink.js";

// ---------------------------------------------------------------------------
// Scan cache
// ---------------------------------------------------------------------------

interface ScanCacheEntry {
  result: PipelineResult;
  ts: number;
}

const CACHE_TTL_MS = 5_000;
const CACHE_MAX_SIZE = 1_000;
const CACHE_SWEEP_INTERVAL_MS = 60_000;

export function cacheKey(content: string, sessionId: string): string {
  return sha256(content + "\0" + sessionId);
}

// ---------------------------------------------------------------------------
// Plugin state
// ---------------------------------------------------------------------------

export interface PluginState {
  inbound: DrawbridgePipeline;
  outbound: DrawbridgePipeline;
  tracker: FrequencyTracker;
  config: ResolvedConfig;
  cache: Map<string, ScanCacheEntry>;
  auditSink: AuditSink;
  teardown: () => void;
}

export interface InitOptions {
  config: ResolvedConfig;
  vhIngest?: VigilHarborIngestFn;
  alertNotify?: AlertNotifyFn;
}

/**
 * Resolve the ClawMoat engine — ESM dynamic import with CJS fallback.
 * Returns the engine instance or null on failure.
 */
async function resolveClawMoatEngine(): Promise<unknown> {
  let esmError: unknown;
  let cjsError: unknown;

  try {
    // ESM path — named export
    const mod = await import("clawmoat");
    const ClawMoat = (mod as Record<string, unknown>).ClawMoat ?? (mod as Record<string, unknown>).default;
    if (typeof ClawMoat === "function") {
      return new (ClawMoat as new () => unknown)();
    }
    // If default export is already an instance or has a different shape
    if (ClawMoat && typeof (ClawMoat as Record<string, unknown>).scan === "function") {
      return ClawMoat;
    }
  } catch (err) {
    esmError = err;
  }

  try {
    const { createRequire } = await import("node:module");
    const require = createRequire(import.meta.url);
    const mod = require("clawmoat");
    const ClawMoat = mod.ClawMoat ?? mod.default ?? mod;
    if (typeof ClawMoat === "function") {
      return new (ClawMoat as new () => unknown)();
    }
    if (ClawMoat && typeof ClawMoat.scan === "function") {
      return ClawMoat;
    }
  } catch (err) {
    cjsError = err;
  }

  // Log actual errors so operators can distinguish "not installed" from
  // "installed but broken" (native binding missing, version mismatch, etc.)
  if (esmError) console.warn("[drawbridge] ESM import failed:", (esmError as Error).message);
  if (cjsError) console.warn("[drawbridge] CJS fallback failed:", (cjsError as Error).message);
  return null;
}

/**
 * Initialize plugin state — async (ClawMoat import).
 * Returns null on failure (sentinel for no-op plugin).
 */
export async function initializePluginState(opts: InitOptions): Promise<PluginState | null> {
  const { config } = opts;

  // 1. Resolve ClawMoat engine
  const engine = await resolveClawMoatEngine();
  if (!engine) {
    console.warn("[drawbridge] ClawMoat engine could not be loaded — plugin disabled. Check that clawmoat and its native dependencies are installed.");
    return null;
  }

  // 2. Create shared FrequencyTracker
  // Deep-merge nested objects to prevent partial overrides from dropping
  // sibling keys (e.g. { thresholds: { tier1: 5 } } must not erase tier2/tier3).
  const freq = config.frequency;
  const tracker = new FrequencyTracker({
    enabled: freq?.enabled ?? true,
    halfLifeMs: freq?.halfLifeMs ?? 60_000,
    rollingWindowMs: freq?.rollingWindowMs ?? 300_000,
    rollingThreshold: freq?.rollingThreshold ?? 10,
    weights: {
      "drawbridge.prompt_injection.*": 15,
      "drawbridge.credential.*": 10,
      "drawbridge.structural.*": 5,
      ...freq?.weights,
    },
    thresholds: {
      tier1: 15, tier2: 40, tier3: 80,
      ...freq?.thresholds,
    },
    memory: {
      maxSessions: 10_000,
      sessionTtlMs: 1_800_000,
      maxNewSessionsPerMinute: 100,
      ...freq?.memory,
    },
  });

  // 3. Create audit sink
  const auditSink = createAuditSink(config.auditSink, opts.vhIngest, opts.alertNotify);

  // 4. Create pipelines with shared tracker + engine
  const inbound = new DrawbridgePipeline({
    profile: config.inboundProfile,
    engine,
    tracker,
    scanner: { blockThreshold: config.blockThreshold, direction: "inbound" },
    sanitize: { hashRedactions: config.hashRedactions },
    audit: {
      verbosity: config.auditVerbosity,
      onEvent: (event) => auditSink.emit(event),
    },
    alerting: {
      onAlert: (payload) => auditSink.alert(payload),
    },
  });

  const outbound = new DrawbridgePipeline({
    profile: config.outboundProfile,
    engine,
    tracker,
    scanner: { blockThreshold: config.blockThreshold, direction: "outbound" },
    sanitize: {
      enabled: config.redactOutbound,
      hashRedactions: config.hashRedactions,
    },
    audit: {
      verbosity: config.auditVerbosity,
      onEvent: (event) => auditSink.emit(event),
    },
    alerting: {
      onAlert: (payload) => auditSink.alert(payload),
    },
  });

  // 5. Scan cache with periodic sweep
  const cache = new Map<string, ScanCacheEntry>();

  const sweepInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of cache) {
      if (now - entry.ts > CACHE_TTL_MS) cache.delete(key);
    }
  }, CACHE_SWEEP_INTERVAL_MS);

  // Prevent the interval from keeping the process alive
  if (typeof sweepInterval === "object" && "unref" in sweepInterval) {
    sweepInterval.unref();
  }

  return {
    inbound,
    outbound,
    tracker,
    config,
    cache,
    auditSink,
    teardown: () => clearInterval(sweepInterval),
  };
}

/**
 * Read from scan cache. Returns null on miss or expired entry.
 */
export function cacheGet(cache: Map<string, ScanCacheEntry>, key: string): PipelineResult | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return entry.result;
}

/**
 * Write to scan cache. Skips if cache is at max capacity.
 */
export function cacheSet(cache: Map<string, ScanCacheEntry>, key: string, result: PipelineResult): void {
  if (cache.size >= CACHE_MAX_SIZE) return;
  cache.set(key, { result, ts: Date.now() });
}
