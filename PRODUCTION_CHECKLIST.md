# Production release checklist

## Required
- [ ] Set `ENVIRONMENT=production`.
- [ ] Set a random `API_KEY` and keep it server-side; never commit `.env`.
- [ ] Set `ENFORCE_TARGET_SCOPE=true` and a minimal `ALLOWED_TARGETS` list.
- [ ] Set strong PostgreSQL credentials and `DATABASE_URL`.
- [ ] Set `REDIS_URL` and run the dedicated `worker` service.
- [ ] Set exact `CORS_ORIGINS` to the deployed frontend origin(s).
- [ ] Put the API behind an HTTPS reverse proxy/load balancer.
- [ ] Do not expose PostgreSQL or Redis ports publicly.
- [ ] Restrict worker egress to authorized scan targets and required upstream services.
- [ ] Rotate any credential that appeared in source, `.env`, browser bundles, logs, or shared archives.
- [ ] Run backend tests, frontend build/smoke tests, dependency audits, and Docker E2E in CI.

## Before public/multi-tenant launch
- [ ] Real user authentication with short-lived sessions/tokens.
- [ ] Per-user/tenant authorization and PostgreSQL RLS.
- [ ] Secret manager/KMS instead of environment variables for long-lived secrets.
- [ ] Centralized immutable audit storage.
- [ ] Error tracking with secret/PII scrubbing.
- [ ] Metrics/tracing and alerting.
- [ ] Backup + restore drills for PostgreSQL.
- [ ] Worker concurrency/quotas and per-tenant job limits.
- [ ] WAF/reverse-proxy request limits and body-size limits.
- [ ] Security review/penetration test of the scanner itself.

## Authentication / RBAC / Tenant bootstrap

- `AUTH_ALLOW_REGISTRATION=false` is the secure default.
- For first-time bootstrap only, set `AUTH_ALLOW_REGISTRATION=true` on the server, create the first Tenant/Admin, then immediately set it back to `false` and restart the backend.
- Set `AUTH_JWT_SECRET` to a cryptographically random secret (32+ bytes; 64+ random characters recommended). Never commit it.
- Set `GEMINI_API_KEY` only in the backend/server secret environment. Never expose it through the frontend build.
- Keep `ENABLE_LEGACY_API_KEY=false` unless a legacy integration is explicitly required.
- Keep `ENFORCE_TARGET_SCOPE=true` in production and configure `ALLOWED_TARGETS` explicitly.

## Supabase release gate

- [ ] `AUTH_PROVIDER=supabase` on production backend.
- [ ] `SUPABASE_URL` and `DATABASE_URL` are server-side secrets/config only.
- [ ] `VITE_SUPABASE_ANON_KEY` is the only Supabase credential exposed to the browser; never `service_role`.
- [ ] Supabase JWT has a verified issuer and audience.
- [ ] `tenant_id` is supplied from trusted Supabase `app_metadata` for shared tenants.
- [ ] `role` is supplied from trusted `app_metadata` and is never accepted from ordinary user-controlled metadata.
- [ ] RLS is enabled and forced on `scan_jobs`, `scans`, `assets`, and `audit_logs`.
- [ ] Cross-tenant read/write tests pass against the real Supabase database before launch.
- [ ] `E2E_BEARER_TOKEN` is used for authenticated E2E; no production API key is baked into the frontend.
- [ ] Database backups / PITR and restore testing are enabled in Supabase.


## Supabase / Admin security gates

- [ ] `SUPABASE_SERVICE_ROLE_KEY` exists only on the server.
- [ ] Never put the service-role key in `frontend/.env`, `VITE_*`, Git, Vercel client environment, or browser bundles.
- [ ] `SUPABASE_AUTO_PROVISION` is reviewed before enabling public registration.
- [ ] The first tenant owner is verified, then public registration is disabled unless intentionally required.
- [ ] `ENFORCE_TARGET_SCOPE=true` and explicit `ALLOWED_TARGETS` are enabled in production.
- [ ] Admin role changes are tested for tenant isolation and stale-token revocation.
