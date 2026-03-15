/**
 * AuditEmitter: structured audit trail with configurable verbosity tiers.
 *
 * Spec reference: Audit Trail Enhancement v2.2
 *
 * NOT IMPLEMENTED in v0.1. Placeholder for pipeline type stability.
 */

import type { AuditConfig, AuditEvent } from "../types/audit.js";

export class AuditEmitter {
  constructor(_config?: AuditConfig) {
    // Configuration accepted but not acted on in v0.1
  }

  /** @throws {Error} Not implemented in v0.1 */
  emit(_event: AuditEvent): void {
    throw new Error(
      "AuditEmitter.emit() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }

  /** @throws {Error} Not implemented in v0.1 */
  async flush(): Promise<void> {
    throw new Error(
      "AuditEmitter.flush() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }
}
