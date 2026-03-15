/**
 * Shared JSON.stringify with circular reference protection.
 * Used by DrawbridgeScanner.scanObject and DrawbridgePipeline.inspect.
 */

/**
 * Returns a JSON.stringify replacer that replaces circular references
 * with "[Circular]" and caps depth at maxDepth with "[Depth limit]".
 */
function circularReplacer(maxDepth: number) {
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

/**
 * Safely stringify any value, handling circular references and depth limits.
 * Never throws.
 *
 * Depth is capped at `maxDepth` (default 32). Objects deeper than this will
 * have interior nodes replaced with "[Depth limit]". This applies to all
 * inputs — prior to v1.0, depth limiting only triggered on circular references.
 */
export function safeStringify(content: unknown, maxDepth = 32): string {
  try {
    return JSON.stringify(content, circularReplacer(maxDepth), 0);
  } catch {
    // JSON.stringify can throw on BigInt values or bad toJSON methods.
    // Return a JSON-safe diagnostic rather than "[object Object]".
    return '"[Unserializable]"';
  }
}
