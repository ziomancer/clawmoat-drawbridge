/**
 * Content sanitization — position-based redaction of findings.
 *
 * Standalone function that works with findings from either the scanner
 * (ClawMoat-derived) or the syntactic pre-filter. The pipeline (v1.0)
 * will feed findings from both stages into sanitizeContent().
 */

import { createHmac } from "node:crypto";
import type {
  DrawbridgeFinding,
  RedactionDetail,
  SanitizeConfig,
  SanitizeResult,
} from "../types/scanner.js";
import { SEVERITY_RANK, isSeverity } from "../types/common.js";
import { DEFAULT_SANITIZE_CONFIG } from "../types/scanner.js";

/** Compute redaction hash: HMAC-SHA256 if configured, empty string otherwise. */
function computeRedactionHash(content: string, config: SanitizeConfig): string {
  if (!config.hashRedactions || !config.hmacKey) return "";
  return createHmac("sha256", config.hmacKey).update(content).digest("hex");
}

/** Internal range for replacement planning */
interface RedactionRange {
  start: number;
  end: number;
  ruleId: string;
  severityRank: number;
  fallback: boolean;
}

function severityRank(severity: string): number {
  return isSeverity(severity) ? SEVERITY_RANK[severity] : SEVERITY_RANK.critical;
}

/**
 * Redact content based on findings from the scanner or pre-filter.
 *
 * Replaces matched substrings (identified by findings[].source.matched
 * and findings[].source.position) with a configurable placeholder.
 *
 * Findings are applied in reverse position order to preserve character
 * positions during replacement (replacing from end to start).
 *
 * Only findings with blocked=true are redacted by default.
 * Pass redactAll=true to redact all findings regardless of threshold.
 */
export function sanitizeContent(
  content: string,
  findings: DrawbridgeFinding[],
  config?: Partial<SanitizeConfig> & { redactAll?: boolean },
): SanitizeResult {
  const mergedConfig = { ...DEFAULT_SANITIZE_CONFIG, ...config };
  const redactAll = config?.redactAll ?? false;

  const empty: SanitizeResult = {
    sanitized: content,
    redactionCount: 0,
    charactersRemoved: 0,
    redactedRuleIds: [],
    originalLength: content.length,
    fallbackRedactions: 0,
    redactions: [],
  };

  // 1. Select findings to redact
  const selected = findings.filter((f) => redactAll || f.blocked);
  if (selected.length === 0) return empty;

  // 2. Build replacement ranges
  const ranges: RedactionRange[] = [];
  for (const finding of selected) {
    const matched = finding.source.matched;
    if (!matched) continue;

    if (finding.source.position >= 0 && finding.source.position < content.length &&
        content.slice(finding.source.position, finding.source.position + matched.length) === matched) {
      // Verified position — redact exactly this occurrence.
      // Note: if matched extends past EOF, slice returns a shorter string,
      // the equality check fails, and the fallback path handles it safely.
      ranges.push({
        start: finding.source.position,
        end: Math.min(finding.source.position + matched.length, content.length),
        ruleId: finding.ruleId,
        severityRank: severityRank(finding.source.severity),
        fallback: false,
      });
    } else {
      // Position is bad (wrong, negative, out-of-bounds). For a content-filtering
      // library, failing to redact is worse than over-redacting, so redact ALL
      // occurrences of the matched string.
      const MAX_FALLBACK_PER_FINDING = 1_000;
      let fallbackCount = 0;
      let searchFrom = 0;
      while (searchFrom < content.length && fallbackCount < MAX_FALLBACK_PER_FINDING) {
        const idx = content.indexOf(matched, searchFrom);
        if (idx === -1) break;
        ranges.push({
          start: idx,
          end: Math.min(idx + matched.length, content.length),
          ruleId: finding.ruleId,
          severityRank: severityRank(finding.source.severity),
          fallback: true,
        });
        searchFrom = idx + matched.length;
        fallbackCount++;
      }
    }
  }

  if (ranges.length === 0) return empty;

  // 3. Sort by start position ascending for merge
  ranges.sort((a, b) => a.start - b.start);

  // 4. Merge overlapping ranges (higher severity ruleId wins).
  // Note: after merge, ruleId reflects the highest-severity contributing finding
  // while fallback reflects whether *any* contributing range used fallback.
  // These may come from different findings — the merged entry represents the
  // union of all overlapping redactions, not a single finding.
  const merged: RedactionRange[] = [ranges[0]!];
  for (let i = 1; i < ranges.length; i++) {
    const current = ranges[i]!;
    const last = merged[merged.length - 1]!;

    if (current.start <= last.end) {
      // Overlap — extend range, keep higher severity ruleId
      last.end = Math.max(last.end, current.end);
      if (current.severityRank > last.severityRank) {
        last.ruleId = current.ruleId;
        last.severityRank = current.severityRank;
      }
      // If any contributing range was a fallback, mark merged as fallback
      if (current.fallback) last.fallback = true;
    } else {
      merged.push(current);
    }
  }

  // 5. Apply replacements from end to start (preserves positions)
  let result = content;
  let charactersRemoved = 0;
  const redactedRuleIds = new Set<string>();
  const redactions: RedactionDetail[] = [];

  for (let i = merged.length - 1; i >= 0; i--) {
    const range = merged[i]!;
    const placeholder = mergedConfig.includeRuleId
      ? `[REDACTED:${range.ruleId}]`
      : mergedConfig.placeholder;

    const removed = range.end - range.start;
    const removedContent = content.slice(range.start, range.end);
    charactersRemoved += removed;
    redactedRuleIds.add(range.ruleId);

    redactions.push({
      ruleId: range.ruleId,
      position: range.start,
      matchedLength: removed,
      sha256: computeRedactionHash(removedContent, mergedConfig),
      replacement: placeholder,
      fallback: range.fallback,
    });

    result = result.slice(0, range.start) + placeholder + result.slice(range.end);
  }

  // Reverse so redactions are in ascending position order
  redactions.reverse();

  return {
    sanitized: result,
    redactionCount: merged.length,
    charactersRemoved,
    redactedRuleIds: [...redactedRuleIds],
    originalLength: content.length,
    fallbackRedactions: redactions.filter(r => r.fallback).length,
    redactions,
  };
}
