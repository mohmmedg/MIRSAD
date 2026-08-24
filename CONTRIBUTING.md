# Contributing

This is a personal thesis/portfolio project, but it follows the same
contribution discipline as a real team project — mainly so it's a habit,
not a one-off.

## Before you start

- **Never point `ALLOWED_TARGETS` at anything you don't have explicit
  written authorization to scan.** This applies to development, testing,
  and demos alike. See [Security Considerations in the
  README](./README.md#security-considerations).
- Read the [README](./README.md) — architecture, endpoints, and known
  limitations — before changing behavior.

## Development setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
```

## Before opening a PR / committing

Run the same checks CI runs, locally, in this order:

```bash
ruff check app/ tests/          # lint
mypy app/ --ignore-missing-imports   # type check
pip-audit -r requirements.txt   # dependency vulnerabilities
pytest tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=75
```

All four must pass. If `ruff` finds fixable issues, `ruff check --fix` first
and re-review the diff — don't blindly commit auto-fixes without reading
them.

## Adding a new endpoint

Every new scan/analysis endpoint should follow the pattern already used by
`network.py` / `web.py`:

1. `Depends(verify_api_key)` on the route (or the whole router).
2. Call `verify_target_in_scope()` (which also runs the SSRF check) before
   doing any actual scanning/probing — fail fast with a `403`, don't let an
   out-of-scope target reach a scanner module.
3. Wrap the call with `log_scan_request(...)` so it shows up in the audit
   log, including on rejection (`scope_violation` / `ssrf_blocked`).
4. Add both a unit test (module logic, mocked I/O) and an integration test
   (via `TestClient`) — see [Testing conventions](#testing-conventions)
   below.

## Adding a new rule to the rule-based engine

Rules live in `app/modules/rule_based_analysis/rules.py` as plain
dictionaries — no code changes needed elsewhere. Every rule needs all four
fields, because they feed the three audience reports from one source:

- `title` — short technical title
- `remediation` — concrete technical fix (technical report)
- `business_impact` — plain, non-technical framing of the risk (managerial
  report)
- `plain_summary` — everyday language, no jargon at all (non-technical
  report)

Add a unit test in `tests/unit/test_rule_based_analyzer.py` asserting the
new rule fires (and, just as importantly, that it doesn't fire on inputs it
shouldn't).

## Testing conventions

- **Unit tests** (`tests/unit/`) — one module at a time, all external I/O
  mocked (`asyncio.create_subprocess_exec` for `nmap`, `httpx.AsyncClient`
  for HTTP, the Gemini client for AI calls). No real network access, no
  real subprocess execution.
- **Integration tests** (`tests/integration/`) — exercise the FastAPI app
  via `TestClient`, still with external I/O mocked at the same boundaries.
- Keep coverage at or above 75% (enforced in CI) — this is a floor, not a
  target; new code should generally come with tests that actually exercise
  its branches, not just satisfy the percentage.
- Test both the "happy path" and the security-relevant rejection paths
  (out-of-scope target, SSRF-risk target, missing/invalid API key) for any
  new scan/analysis endpoint.

## Commit style

Small, focused commits. If a change touches both a security-relevant path
(scope guard, SSRF guard, auth) and something unrelated, split it into
separate commits — security-relevant changes should be easy to review and
easy to revert independently.

## Code style

- Ruff handles formatting/lint — don't hand-format against it.
- Type hints are required (`mypy` is enforced in CI); avoid `Any` unless
  you have a real reason and a comment explaining it (see
  `nvd_client.py`/`ai_analysis/analyzer.py` for examples of documented
  exceptions).
- Comments explaining a security-relevant *why* (not just *what*) are
  encouraged — several exist throughout `core/config.py` and the scanner
  modules; follow that pattern for new security-sensitive code.
