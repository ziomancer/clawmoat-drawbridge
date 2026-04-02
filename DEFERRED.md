# Deferred Items

Tracked items that were intentionally deferred or are blocked on dependencies.

## Blocked

### writeFailSpike alert rule
- **Location:** `src/alerting/index.ts:159`
- **Status:** Blocked — `write_failed` audit event type does not exist yet
- **Description:** Alert Rule 5 (write fail spike detection) cannot be implemented until the `write_failed` event is added to the Drawbridge audit event taxonomy. The `AlertRuleId` type and `AlertRuleConfigs` interface already define the rule shape; the `evaluate()` switch statement has a placeholder comment. Test stubs exist in `src/alerting/__tests__/alerting.test.ts:399`.
- **To unblock:** Add `write_failed` to `AuditEventType` in `src/types/audit.ts`, define its event interface, assign a verbosity tier, then wire it through the pipeline.

## Deferred Enhancements

### Per-severity rate-limit buckets (alerting)
- **Source:** Pass 3, Phase 2.2 (optional)
- **Description:** Current rate limiter uses a single global bucket with critical alerts exempt. A more granular approach would maintain separate rate-limit counters per severity tier (critical: unlimited, high: own budget, medium/low: shared budget). Marked as nice-to-have in the hardening instructions — the minimal fix (exempt critical) is sufficient for the security finding.
- **Effort:** Low-medium. Requires splitting `minuteTimestamps`/`hourTimestamps` into per-severity arrays and threading severity through `isRateLimited()`.

### Per-field runtime event shape validation (alerting)
- **Source:** Pass 3, Phase 3.2 (optional)
- **Description:** Before casting audit events to specific types (e.g., `FrequencyAuditEvent`), validate that expected fields exist and have correct types. Currently the top-level try/catch in `evaluate()` catches these as TypeError and returns null, which is safe but loses diagnostic information. Explicit guards would allow logging the specific malformed field.
- **Effort:** Low. Add `typeof` guards before each `as` cast in the rule evaluator methods.
