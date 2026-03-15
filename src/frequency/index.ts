/**
 * FrequencyTracker: session suspicion tracking with exponential decay scoring.
 *
 * Spec reference: Input Validation Layers v2.3, §Within-Session Frequency Tracking
 *
 * NOT IMPLEMENTED in v0.1. Placeholder for pipeline type stability.
 */

import type { FrequencyConfig, FrequencyUpdateResult, SessionSuspicionState } from "../types/frequency.js";

export class FrequencyTracker {
  constructor(_config?: FrequencyConfig) {
    // Configuration accepted but not acted on in v0.1
  }

  /** @throws {Error} Not implemented in v0.1 */
  update(_ruleIds: string[]): FrequencyUpdateResult {
    throw new Error(
      "FrequencyTracker.update() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }

  /** @throws {Error} Not implemented in v0.1 */
  getState(_sessionId: string): SessionSuspicionState | null {
    throw new Error(
      "FrequencyTracker.getState() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }

  /** @throws {Error} Not implemented in v0.1 */
  reset(_sessionId: string): void {
    throw new Error(
      "FrequencyTracker.reset() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }
}
