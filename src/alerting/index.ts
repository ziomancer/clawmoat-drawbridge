/**
 * AlertManager: alert rules, delivery channels, and escalation.
 *
 * Spec reference: Audit Alerting v2.3
 *
 * NOT IMPLEMENTED in v0.1. Placeholder for pipeline type stability.
 */

import type { AlertingConfig } from "../types/alerting.js";
import type { AuditEvent } from "../types/audit.js";

export class AlertManager {
  constructor(_config?: AlertingConfig) {
    // Configuration accepted but not acted on in v0.1
  }

  /** @throws {Error} Not implemented in v0.1 */
  evaluate(_event: AuditEvent): void {
    throw new Error(
      "AlertManager.evaluate() is not implemented in v0.1. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }
}
