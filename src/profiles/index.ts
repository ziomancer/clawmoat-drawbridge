/**
 * ProfileResolver: resolves context profiles for deployment-specific tuning.
 *
 * Spec reference: Context-Aware Sanitization v2.1
 *
 * NOT IMPLEMENTED in v0.1. Placeholder for pipeline type stability.
 */

import type { BuiltInProfileId, ContextProfile, CustomProfileDefinition } from "../types/profiles.js";

export class ProfileResolver {
  constructor(_config?: BuiltInProfileId | CustomProfileDefinition) {
    // Configuration accepted but not acted on in v0.1
  }

  /** @throws {Error} Not implemented in v0.1 */
  resolve(): ContextProfile {
    throw new Error(
      "ProfileResolver.resolve() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }
}
