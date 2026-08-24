# Security Gemini Monster — Global Production Final

## Release status

This package is frozen as a production release candidate. No new product features are included after this release; changes are limited to correctness, security, integration, deployment, and release documentation.

## Included platform

- Supabase Auth + server-side RBAC + tenant isolation/RLS
- Mandatory MFA/AAL2 for administrators and step-up MFA for sensitive operations
- Admin Security Center: users, roles, API keys, sessions, policies, audit, health
- Network, Web, and API Security scanners
- Unified Finding Contract + deterministic risk engine
- Security Event → Alert → Incident correlation pipeline
- Gemini explanation layer that cannot override deterministic findings or CI/compliance decisions
- Continuous Attack Surface Monitoring
- Redis-backed durable worker + PostgreSQL lease/single-job ownership
- Compliance Center with OWASP ASVS, OWASP API Security, NIST CSF, CIS Controls, and Custom scope control
- SARIF 2.1.0 export
- Deterministic CI/CD Security Gate with severity thresholds
- GitHub Actions security gate workflow
- Production Docker Compose with separate API, worker, Redis, and Nginx frontend
- Production fail-closed target scope and SSRF protections
- Security headers, CSP, HSTS, no-new-privileges, non-root containers

## Database migrations

Apply in order:

1. `supabase/migrations/0001_security_platform.sql`
2. `supabase/migrations/0002_mfa_security_events_incidents.sql`
3. `supabase/migrations/0003_scanner_finding_correlation.sql`
4. `supabase/migrations/0004_continuous_attack_surface.sql`
5. `supabase/migrations/0005_durable_continuous_scheduler.sql`
6. `supabase/migrations/0006_compliance_ci_gate.sql`

The compliance control table uses a tenant-scoped composite key so the same control catalog can exist independently for every tenant.

## Release verification performed

- Backend compile check: PASS
- Backend test suite: **157/157 PASS**
- Docker Compose YAML parsing: PASS
- Release integrity checks: PASS
- Secret-pattern scan: PASS
- Dangerous-code pattern scan: PASS
- Frontend dependency install/build could not be completed in the execution environment because npm registry access timed out. The production image intentionally installs dependencies during Docker build and does not ship `node_modules`.
- Docker runtime execution was not claimed because the execution environment did not provide a Docker daemon/CLI.

## Production requirements

Set these server-side before deployment:

- `ENVIRONMENT=production`
- `AUTH_PROVIDER=supabase`
- `SUPABASE_URL`
- `SUPABASE_JWT_ISSUER`
- `SUPABASE_JWT_AUDIENCE=authenticated`
- `DATABASE_URL`
- `SCHEDULER_DATABASE_URL`
- `REDIS_URL`
- `ENFORCE_TARGET_SCOPE=true`
- `ALLOWED_TARGETS`
- `CORS_ORIGINS`
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`

Keep `SUPABASE_SERVICE_ROLE_KEY`, database credentials, Redis credentials, and `GEMINI_API_KEY` server-side only. Never put them in `VITE_*` variables.

## Safe deployment order

1. Create/verify the Supabase production project.
2. Apply migrations 0001–0006.
3. Create the production environment file from `backend/.env.production.example`.
4. Set an explicit authorized target allow-list.
5. Start Redis, API, worker, and frontend.
6. Verify `/health` and `/readiness`.
7. Sign in as Owner and enroll MFA.
8. Verify tenant isolation and target-scope rejection with a non-authorized target.
9. Run one authorized Full Scan.
10. Verify Finding → Risk → Alert → Incident.
11. Run Compliance Assessment and export SARIF.
12. Configure GitHub Actions only after the production API gate works manually.

## Release boundary

Do not treat the project as vulnerability-free solely because the automated suite passes. Production security still requires external dependency monitoring, TLS termination, secret rotation, least-privilege Supabase configuration, backups, logging/monitoring, and an authorized external penetration test before making security guarantees to customers.
