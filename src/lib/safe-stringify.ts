/**
 * Shared JSON.stringify with circular reference protection.
 * Used by DrawbridgeScanner.scanObject and DrawbridgePipeline.inspect.
 */

/**
 * Returns a JSON.stringify replacer that replaces circular references
 * with "[Circular]" and caps depth at maxDepth with "[Depth limit]".
 */
function circularReplacer(maxDepth = 10) {
  const seen = new WeakSet();
  let depth = 0;

  return function (this: unknown, _key: string, value: unknown): unknown {
    if (typeof value === "object" && value !== null) {
      if (seen.has(value)) return "[Circular]";
      if (depth >= maxDepth) return "[Depth limit]";
      seen.add(value);
      depth++;
    }
    return value;
  };
}

/** Safely stringify any value, handling circular references. */
export function safeStringify(content: unknown): string {
  try {
    return JSON.stringify(content);
  } catch {
    return JSON.stringify(content, circularReplacer(), 0);
  }
}
