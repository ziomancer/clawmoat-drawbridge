/**
 * PreFilter: two-stage input validation (syntactic pre-filter + schema validation).
 *
 * Spec reference: Input Validation Layers v2.3
 *
 * NOT IMPLEMENTED in v0.1. Placeholder for pipeline type stability.
 */

import type { ContentSource } from "../types/common.js";
import type { PreFilterResult, TwoPassConfig } from "../types/validation.js";

export class PreFilter {
  constructor(_config?: Partial<TwoPassConfig>) {
    // Configuration accepted but not acted on in v0.1
  }

  /** @throws {Error} Not implemented in v0.1 */
  run(_content: string | unknown, _source: ContentSource): PreFilterResult {
    throw new Error(
      "PreFilter.run() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }
}
