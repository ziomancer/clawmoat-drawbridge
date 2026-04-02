/**
 * Input normalization for security-relevant content analysis.
 *
 * Strips invisible characters, normalizes confusable characters (NFKC +
 * homoglyph mapping), and detects RTL overrides — all before any pattern
 * matching runs in the pre-filter.
 *
 * Pure function — no side effects, no state, no logging.
 */

// ---------------------------------------------------------------------------
// Invisible character patterns
// ---------------------------------------------------------------------------

/**
 * Characters that are invisible/zero-width and serve no legitimate purpose
 * in security-relevant content. Their presence in injection-adjacent text
 * is itself a signal.
 *
 * Covers: null byte, soft hyphen, zero-width space/ZWNJ/ZWJ, LRM/RLM,
 * bidi embeddings/overrides/isolates, narrow no-break space, word joiner,
 * invisible math operators, and BOM.
 *
 * Deliberately excludes U+2028/U+2029 (line/paragraph separators) because
 * they have visible effect (line breaks) and are recognized as line
 * terminators by JavaScript regex `m` flag — stripping them would weaken
 * `^SYSTEM:` detection.
 */
const INVISIBLE_AND_NULL = /[\x00\u00AD\u200B-\u200F\u202A-\u202F\u2060-\u2069\uFEFF]/g;

/**
 * RTL/LTR override and isolate characters that can visually disguise text
 * direction. Subset of INVISIBLE_AND_NULL — detected before stripping to
 * produce a dedicated flag.
 */
const RTL_OVERRIDES = /[\u202A-\u202E\u2066-\u2069]/;

// ---------------------------------------------------------------------------
// Homoglyph table (Cyrillic / Greek / Latin Extended → Latin)
//
// NFKC normalization handles fullwidth Latin, mathematical alphanumeric
// symbols, and other compatibility characters. This table covers visual
// lookalikes that have distinct NFKC canonical forms.
// ---------------------------------------------------------------------------

const HOMOGLYPH_MAP: ReadonlyMap<string, string> = new Map([
  // Cyrillic → Latin
  ["\u0430", "a"], // а → a
  ["\u0435", "e"], // е → e
  ["\u043E", "o"], // о → o
  ["\u0440", "p"], // р → p
  ["\u0441", "c"], // с → c
  ["\u0443", "y"], // у → y
  ["\u0456", "i"], // і → i
  ["\u0455", "s"], // ѕ → s
  // Greek → Latin
  ["\u03B1", "a"], // α → a
  ["\u03B5", "e"], // ε → e
  ["\u03BF", "o"], // ο → o
  ["\u03C1", "p"], // ρ → p
  ["\u03BA", "k"], // κ → k
  ["\u03B9", "i"], // ι → i
  ["\u03BD", "v"], // ν → v
  // Latin Extended
  ["\u0131", "i"], // ı → i (dotless i)
  ["\u0261", "g"], // ɡ → g
]);

function applyHomoglyphMap(text: string): string {
  let result = "";
  for (const ch of text) {
    result += HOMOGLYPH_MAP.get(ch) ?? ch;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface NormalizationResult {
  /** Content ready for pattern matching */
  normalized: string;
  /** Number of invisible/null characters stripped */
  invisibleCharsStripped: number;
  /** Whether NFKC or homoglyph mapping changed anything */
  confusablesNormalized: boolean;
  /** Whether RTL override characters were present */
  rtlOverridesDetected: boolean;
}

/**
 * Normalize content for security pattern detection.
 *
 * Order of operations:
 * 1. Detect RTL overrides (before stripping)
 * 2. Strip invisible + null byte characters
 * 3. Apply NFKC normalization + homoglyph mapping
 *
 * The caller's content is not mutated. Returns a new result object.
 */
export function normalizeForDetection(content: string): NormalizationResult {
  // 1. Detect RTL overrides before stripping
  const rtlOverridesDetected = RTL_OVERRIDES.test(content);

  // 2. Strip invisible + null byte characters
  const stripped = content.replace(INVISIBLE_AND_NULL, "");
  const invisibleCharsStripped = content.length - stripped.length;

  // 3. NFKC normalization (fullwidth, math symbols, compatibility chars)
  const nfkc = stripped.normalize("NFKC");

  // 4. Homoglyph mapping (Cyrillic, Greek, Latin Extended → Latin)
  const normalized = applyHomoglyphMap(nfkc);

  // confusablesNormalized = true if NFKC or homoglyph mapping changed anything
  const confusablesNormalized = normalized !== stripped;

  return {
    normalized,
    invisibleCharsStripped,
    confusablesNormalized,
    rtlOverridesDetected,
  };
}
