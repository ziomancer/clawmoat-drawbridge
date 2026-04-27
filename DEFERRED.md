# Deferred Items

Tracked items that were intentionally deferred or are blocked on dependencies.

## Deferred Enhancements

### Enricher → write_failed emission
- **Status:** Deferred to v1.3.x patch
- **Description:** The tool error enricher could emit `write_failed` when it
  classifies an error on write/edit/apply_patch tools. Currently only the guard
  hook handler emits `write_failed` (on blocked writes). Adding enricher emission
  would capture actual runtime write failures, not just policy-blocked ones.

### Per-severity rate-limit buckets (alerting)
- **Source:** Pass 3, Phase 2.2 (optional)
- **Description:** Current rate limiter uses a single global bucket with critical alerts exempt. A more granular approach would maintain separate rate-limit counters per severity tier (critical: unlimited, high: own budget, medium/low: shared budget). Marked as nice-to-have in the hardening instructions — the minimal fix (exempt critical) is sufficient for the security finding.
- **Effort:** Low-medium. Requires splitting `minuteTimestamps`/`hourTimestamps` into per-severity arrays and threading severity through `isRateLimited()`.

### Per-field runtime event shape validation (alerting)
- **Source:** Pass 3, Phase 3.2 (optional)
- **Description:** Before casting audit events to specific types (e.g., `FrequencyAuditEvent`), validate that expected fields exist and have correct types. Currently the top-level try/catch in `evaluate()` catches these as TypeError and returns null, which is safe but loses diagnostic information. Explicit guards would allow logging the specific malformed field.
- **Effort:** Low. Add `typeof` guards before each `as` cast in the rule evaluator methods.
