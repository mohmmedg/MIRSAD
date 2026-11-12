# Finding confirmation contract

## Decision

Separate detection from confirmation. A report can label a finding
`CONFIRMED` only after a bounded verifier records a method, timestamp and
concrete evidence. External-engine results additionally require a canonical
raw-artifact link and execution identifier. Everything else remains a
candidate, with the reason exposed in the scan reconciliation data.

## Constraints

- The scope is the authorised, isolated Juice Shop lab.
- Live verification remains read-only and bounded; scanner agreement is not
  proof and no arbitrary exploitation or data extraction is added.
- Existing raw observations and provenance are retained after correlation.

## Council record

| Role | Recommendation | Outcome |
| --- | --- | --- |
| Architecture | Apply a final confirmation gate before correlation; preserve candidate reasons and fix shared-control identity by origin. | Approve with conditions |
| Reliability | Require reproducible evidence/provenance; do not convert watchdog cancellation to `PARTIAL` without an atomic partial snapshot. | Approve with conditions |
| Skeptical security review | Do not treat multiple scanner matches as confirmation; keep replays lab-scoped and non-destructive. | Approve with conditions |

The rebuttal review required that external proof also include `execution_id`,
and that an internal direct observation (TLS/header) not be demoted merely
because it has no external artifact. Both conditions are implemented.

## Alternatives rejected

- Promote a result when two scanners agree: agreement can repeat the same
  signature false positive and is not an independent proof.
- Turn every watchdog cancellation into `PARTIAL`: this can publish an
  incoherent snapshot. The worker continues to fail/retry unless an atomic
  partial result exists.
- Add autonomous exploit payloads: outside the lab scope and inconsistent
  with the evidence-first safety boundary.

## Acceptance evidence

`py -3.12 -m pytest tests/test_finding_confirmation.py
tests/test_detection_reporting_fixes_2026_10_10.py
tests/integration/test_acceptance_matrix_80.py -q` completed with 92 passing
tests. The tests cover demotion, external provenance, internal verification,
and same-origin versus cross-origin shared-control correlation.
