# Scan evidence reliability decision

## Decision

Treat canonical evidence and truthful terminal stage state as completion
requirements for every external scanner in a full assessment.

## Evidence

The prior Juice Shop assessment completed with a Ghauri finding but a conflicting
SQLMap result, ZAP findings without linked raw artifacts, an advanced-security
timeout, and a DNS stage that remained visibly running until late finalization.

## Council review

| Role | Position | Condition |
| --- | --- | --- |
| Architecture | Approve | Recompute completion from external engines and artifact persistence. |
| Reliability | Approve | Reconcile raw evidence, provenance, persistence and reporting before success. |
| Skeptical review | Approve with conditions | Use a dedicated, resource-limited and resettable lab before destructive testing. |

## Selected implementation

- Create explicit `advanced_security` and truthful DNS stage lifecycles.
- Preserve ZAP's final JSON report as a canonical encrypted artifact and bind
  `alert:*` locators to it.
- Make watchdog cancellation opt-in; a quiet scanner remains observable but is
  not killed solely because stdout is quiet.
- Mark the scan `partial` when an external engine fails/partially completes or
  when an external finding lacks a canonical evidence link.

## Acceptance

The next isolated lab run must show terminal state for every stage, a canonical
artifact link for every external finding, explicit status for every engine, and
an evidence reconciliation result in the scan pipeline.
