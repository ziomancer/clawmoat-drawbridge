/**
 * Content sanitization — position-based redaction of findings.
 *
 * Standalone function that works with findings from either the scanner
 * (ClawMoat-derived) or the syntactic pre-filter. The pipeline (v1.0)
 * will feed findings from both stages into sanitizeContent().
 */

import type {
  DrawbridgeFinding,
  SanitizeConfig,
  SanitizeResult,
} from "../types/scanner.js";
import { SEVERITY_RANK, isSeverity } from "../types/common.js";
import { DEFAULT_SANITIZE_CONFIG } from "../types/scanner.js";

/** Internal range for replacement planning */
interface RedactionRange {
  start: number;
  end: number;
  ruleId: string;
  severityRank: number;
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

  // 1. Select findings to redact
  const selected = findings.filter((f) => redactAll || f.blocked);

  if (selected.length === 0) {
    return {
      sanitized: content,
      redactionCount: 0,
      charactersRemoved: 0,
      redactedRuleIds: [],
      originalLength: content.length,
    };
  }

  // 2. Build replacement ranges
  const ranges: RedactionRange[] = [];
  for (const finding of selected) {
    const matched = finding.source.matched;
    if (!matched) continue;

    let start: number;
    if (finding.source.position >= 0 && finding.source.position < content.length) {
      // Verify the slice at this position actually matches the reported string.
      // If the scanner returned a wrong position (compromised engine, stale offset),
      // fall through to indexOf rather than redacting the wrong content.
      if (content.slice(finding.source.position, finding.source.position + matched.length) === matched) {
        start = finding.source.position;
      } else {
        start = content.indexOf(matched);
        if (start === -1) continue;
      }
    } else {
      // Fallback: find first occurrence in content (handles negative and out-of-bounds).
      // NOTE (v1.1): indexOf always finds the first occurrence, not necessarily the one
      // the scanner flagged. Improving this requires richer position data from the scanner.
      start = content.indexOf(matched);
      if (start === -1) continue;
    }

    ranges.push({
      start,
      end: Math.min(start + matched.length, content.length),
      ruleId: finding.ruleId,
      severityRank: severityRank(finding.source.severity),
    });
  }

  if (ranges.length === 0) {
    return {
      sanitized: content,
      redactionCount: 0,
      charactersRemoved: 0,
      redactedRuleIds: [],
      originalLength: content.length,
    };
  }

  // 3. Sort by start position ascending for merge
  ranges.sort((a, b) => a.start - b.start);

  // 4. Merge overlapping ranges (higher severity ruleId wins)
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
    } else {
      merged.push(current);
    }
  }

  // 5. Apply replacements from end to start (preserves positions)
  let result = content;
  let charactersRemoved = 0;
  const redactedRuleIds = new Set<string>();

  for (let i = merged.length - 1; i >= 0; i--) {
    const range = merged[i]!;
    const placeholder = mergedConfig.includeRuleId
      ? `[REDACTED:${range.ruleId}]`
      : mergedConfig.placeholder;

    const removed = range.end - range.start;
    charactersRemoved += removed;
    redactedRuleIds.add(range.ruleId);
    result = result.slice(0, range.start) + placeholder + result.slice(range.end);
  }

  return {
    sanitized: result,
    redactionCount: merged.length,
    charactersRemoved,
    redactedRuleIds: [...redactedRuleIds],
    originalLength: content.length,
  };
}
