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
  const depths = new WeakMap<object, number>();

  return function (this: unknown, _key: string, value: unknown): unknown {
    if (typeof value === "object" && value !== null) {
      if (seen.has(value)) return "[Circular]";

      // Derive depth from parent (this) rather than a shared counter.
      // JSON.stringify sets `this` to the object holding the current key.
      let parentDepth = -1;
      if (typeof this === "object" && this !== null) {
        parentDepth = depths.get(this) ?? -1;
      }
      const currentDepth = parentDepth + 1;

      if (currentDepth >= maxDepth) return "[Depth limit]";
      seen.add(value);
      depths.set(value, currentDepth);
    }
    return value;
  };
}

/** Safely stringify any value, handling circular references and depth limits. Never throws. */
export function safeStringify(content: unknown): string {
  try {
    return JSON.stringify(content, circularReplacer(), 0);
  } catch {
    try {
      return String(content);
    } catch {
      return "[Unserializable]";
    }
  }
}
