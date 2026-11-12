# MIRSAD — Integrity and Scan Quality Repair Notes

**Patch type:** selective source patch, not a full project distribution. All archive entries preserve their original paths under `MIRSAD - admin -/MIRSAD/`. No `.env`, `.env.production`, database files, secrets, or Docker volumes are included.

## Apply safely

1. Back up your current source tree and any persistent database or volumes before deployment. This package does not run migrations or cleanup commands.
2. Extract the ZIP **in the directory containing** the original `MIRSAD - admin -` directory. Overwrite only source files listed in this archive. If your checkout uses a different directory name, copy the files manually with paths relative to the `MIRSAD` project root.
3. Read the code changes and run your backend test suite in a disposable/staging environment before deploying to production. Do not run destructive security tests against a third-party target.
4. Existing configuration can override defaults. Review `ADVANCED_SECURITY_PHASE_TIMEOUT_SECONDS`, `ADVANCED_SECURITY_PHASE_MAX_REQUESTS`, and `ADVANCED_SECURITY_PHASE_MAX_ENDPOINTS` before staging a scan.

## Implemented changes by file

| Original project path | Purpose |
|---|---|
| `backend/app/core/architecture/manager.py` | Propagate web, external, advanced, subdomain and verification failures into terminal scan status; avoid duplicate verification pass; record conservative endpoint coverage. |
| `backend/app/core/canonical_artifacts.py` | Attach actual encrypted raw artifact SHA-256 alongside artifact IDs; do not fabricate digests for unmatched artifacts. |
| `backend/app/core/config.py` | Configurable, bounded advanced-stage wall time, requests and endpoint counts. |
| `backend/app/core/finding_confirmation.py` | Candidate-first evidence gate; enforce parseable HTTP exchange, timestamp, replay, impact, raw reference/digest, tool version and independent high/critical check. |
| `backend/app/core/ground_truth.py` | Offline, version-pinned, operator-curated Juice Shop scoring with explicit undefined metrics. |
| `backend/app/core/request_budget.py` | Concurrency-safe, per-phase request quota; shared overall request budget remains in effect. |
| `backend/app/core/scan_coverage.py` | Discovered versus security-tested endpoint/method matrix with skipped reasons; mask URL query values. |
| `backend/app/core/scan_health.py` | Reusable tool, subdomain, web and verification terminal-state semantics. |
| `backend/app/modules/advanced_security.py` | Individual phase timeouts/quotas/endpoint caps; record stop reasons and calculate accurate terminal state. |
| `backend/app/modules/correlator/correlator.py` | Stable fingerprint including rule, host, method, normalized route and parameter; never merge different hosts; retain evidence provenance. |
| `backend/app/modules/normalizer/normalizer.py` | Transfer real artifact digests, tool versions and replay fields from tool payloads without manufacturing proof. |
| `backend/app/modules/reporting/exporters.py` | Candidate-aware PDF/HTML/CSV/JSON/SARIF; exclude unconfirmed findings from managerial claims and confirmed risk. |
| `backend/app/modules/reporting/generator.py` | Explicit confirmed versus candidate sections; display raw digest/replay and coverage; redact secrets. |
| `backend/app/modules/risk_engine/engine.py` | Candidates/hardening observations do not increase confirmed risk, even in legacy snapshots. |
| `backend/app/modules/web_scan/scanner.py` | Honor external-stage and source-intelligence failures for final web status. |
| `backend/app/schemas/platform.py` | Optional backward-compatible fields for evidence metadata and endpoint coverage. |
| `backend/app/worker.py` | Persist queue jobs with accurately mapped final states. |
| `backend/scripts/score_juice_shop_ground_truth.py` | Read-only CLI to score a technical JSON scan against a versioned lab manifest. |
| `backend/tests/test_finding_confirmation.py` | Updated pre-existing tests to require the new evidence standard. |
| `backend/tests/unit/test_accuracy_upgrade.py` | Updated legacy risk and dedup tests to match the safer contract. |
| `backend/verification_tests/test_scan_trust_contract.py` | New offline red/green regression tests for evidence, risk, status, phase budget, coverage, reports, fingerprints, and ground truth. |

## Ground truth usage

Run from `MIRSAD/backend`:

```bash
python scripts/score_juice_shop_ground_truth.py scan-technical.json juice-shop-version-manifest.json --output lab-metrics.json
```

The manifest **must** be curated from the exact installed OWASP Juice Shop version. Format:

```json
{
  "lab": "OWASP Juice Shop",
  "version": "<verified-installed-version>",
  "positive_scenarios": [
    {"id":"<known-positive-id>","rule_id":"<rule>","path":"/path","method":"GET","parameter":"id"}
  ],
  "negative_scenarios": []
}
```

The placeholder is not a real challenge manifest. No Juice Shop challenges are claimed as tested by the included offline regression suite. `null` precision/recall/FPR/coverage means an appropriate denominator was not available. An unknown confirmed finding is **unclassified**, not automatically a false positive.

## Important limitations / remaining work

- There was **no live OWASP Juice Shop, authenticated browser session, real PostgreSQL database, Docker environment, or long-running destructive scanner** in this repair environment. Production stack integration and end-to-end effectiveness remain **unverified**.
- An artifact reference with a plausible SHA-256 is **not proof** that its encrypted content was independently rehashed during reporting. Cross-check against the stored `RawArtifactRow` and a real verifier are still necessary. A second-verification status string is not independent cryptographic proof by itself; an analyst must verify the source record.
- A trustworthy version-specific challenge catalog, authenticated route capture, two-account BOLA/IDOR journeys, business-logic scenarios and a complete API/JS route coverage plan require a separately configured **authorized** regression lab. This patch provides a conservative measurement path but does **not** claim those workflows now run automatically.
- The conservative gate may demote existing `VERIFIED` findings to Candidates when their stored artifacts or HTTP proof are incomplete. This is intentional and avoids claiming what historical scans cannot prove.
- Existing/legacy snapshots may now display risk 0 if no findings were confirmed. This means **no confirmed risk score**, never that the asset is safe or SQL injection absent.
- Full project tests requiring `aiosqlite`, integration database fixtures or service containers were not run in this environment.

## Non-destructive checks performed for the patch

- `python -m compileall -q backend/app backend/scripts/score_juice_shop_ground_truth.py`
- Selected Pytest tests with `PYTHONPATH=. pytest --noconftest ...` from `backend/` (no database fixtures); scope guard scenarios need explicit permitted lab targets.
- Archive ZIP integrity and selective-path audit.

**Note:** A report containing partial or skipped tests must be labeled PARTIAL and must publish those skipped reasons. A confirmed finding must carry reproducible, redacted evidence; non-confirmed candidates remain visible only as unproven signals, not established vulnerabilities.
