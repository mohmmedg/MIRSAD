# Compliance Center + CI/CD Security Gate

This release adds a deterministic compliance and CI/CD layer on top of the existing Finding Contract.

## Flow

Finding -> Risk -> Compliance Evidence / SARIF -> CI Gate

Gemini is not a compliance authority and cannot change a deterministic pass/fail decision.

## Supported control families

- OWASP ASVS
- OWASP API Security
- NIST CSF
- CIS Controls
- Custom target-scope control

## API

- `GET /api/v1/compliance/frameworks`
- `GET /api/v1/compliance/controls`
- `POST /api/v1/compliance/assess`
- `GET /api/v1/compliance/assessments`
- `POST /api/v1/compliance/sarif`
- `GET /api/v1/compliance/ci-policy`
- `PUT /api/v1/compliance/ci-policy`
- `POST /api/v1/compliance/ci-gate`

All routes are tenant scoped. Admin policy changes require the existing step-up MFA protection.

## Local CI

After a scan, save its UnifiedScanResult as `security-results.json`:

```bash
python scripts/security_gate.py security-results.json --sarif security-results.sarif --critical-fail 0 --high-fail 0
```

Exit code `0` means the gate passed; `1` means it failed.

## GitHub Actions

The included `.github/workflows/security-gate.yml` can call a deployed scanner. Configure repository secrets:

- `SECURITY_API_URL`
- `SECURITY_API_KEY`
- `SECURITY_TARGET`

`SECURITY_TARGET` must be an asset you are authorized to test.

The workflow runs the deterministic gate and uploads SARIF to GitHub Code Scanning.

If those secrets are absent (for example, a forked pull request), the remote scan step skips safely rather than exposing credentials.

## Deployment

Run Supabase migration `0006_compliance_ci_gate.sql` after migrations `0001` through `0007`.

For Docker Compose, keep at least one API service and one durable worker, with Postgres and Redis persistent volumes. In production use TLS at the ingress, explicit `CORS_ORIGINS`, `ENFORCE_TARGET_SCOPE=true`, strong Supabase credentials, and a dedicated database connection for durable scheduling where required.

## First production validation

1. Apply all Supabase migrations.
2. Configure target allow-list.
3. Configure Supabase authentication and MFA.
4. Start Postgres/Redis, API, worker and frontend.
5. Sign in as an owner/admin.
6. Run a full scan only against an authorized target.
7. Open Compliance & CI/CD and run the assessment.
8. Export SARIF and confirm it appears in GitHub Code Scanning.
9. Configure the CI policy thresholds.
10. Trigger the GitHub Security Gate workflow and confirm a deliberate High/Critical finding fails the gate.
