# Security Gemini Monster — Production Deployment

This deployment profile uses Supabase Postgres/Auth, a dedicated Redis queue, a durable worker, and an Nginx-served production frontend. PostgreSQL and Redis are not exposed publicly.

## 1. Requirements

- Docker Engine + Docker Compose v2
- A Supabase project with Auth enabled
- Supabase CLI for migrations
- A Redis instance (the compose file creates a private one)
- A DNS name and HTTPS reverse proxy in front of `127.0.0.1:8080`

## 2. Configure Supabase

Copy `backend/.env.production.example` to `backend/.env.production` and set:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY` (server only)
- `DATABASE_URL` (Supabase Postgres pooler)
- `ALLOWED_TARGETS`
- `CORS_ORIGINS`
- optional `GEMINI_API_KEY`

Copy `.env.production.example` to `.env.production` and set the two public browser values.

Never put `SUPABASE_SERVICE_ROLE_KEY` into the frontend or any `VITE_*` variable.

## 3. Apply database migrations

Run from the repository root:

```bash
export SUPABASE_PROJECT_REF=YOUR_PROJECT_REF
./scripts/deploy/apply_supabase_migrations.sh
```

The current release contains migrations `0001` through `0007`. Verify `supabase db push` reports all migrations applied, including `0007_security_session_enforcement.sql`.

## 4. Target authorization

Production fails closed unless `ENFORCE_TARGET_SCOPE=true`. Set `ALLOWED_TARGETS` to only domains/IPs/CIDRs you are authorized to assess.

Do not use a wildcard or a broad public CIDR. Keep the list minimal.

## 5. Start production services

```bash
docker compose -f docker-compose.production.yml --env-file .env.production build

docker compose -f docker-compose.production.yml --env-file .env.production up -d

docker compose -f docker-compose.production.yml ps
```

Check:

```bash
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/readiness
```

## 6. Put HTTPS in front

Use a host-level Nginx, Caddy, Cloudflare Tunnel, or another reverse proxy. The example is in `deploy/nginx/security-gemini.conf.example`.

Expose only HTTPS publicly. Keep `8080` bound to localhost.

## 7. First login and MFA

Open the HTTPS URL, create or sign in to the Owner account, then complete Supabase MFA enrollment. Keep Owner MFA enabled before performing administrative operations.

## 8. First authorized scan

Add only an authorized target to `ALLOWED_TARGETS`, then run a Full Scan from the dashboard. Start with a staging/lab asset before production assets.

The pipeline is:

`Scanner → Finding → Risk → Event → Alert → Incident → Report`

## 9. Continuous ASM

Create a schedule only for targets already authorized by the target scope. Redis + worker handle durable jobs; the API process does not own long-running scans.

## 10. GitHub CI/CD

For a deployed gate, create a dedicated API key with the smallest required scanner/report scopes. Store the following as GitHub Actions secrets:

- `SECURITY_API_URL`
- `SECURITY_API_KEY`
- `SECURITY_TARGET`

Do not store these in source control. Configure the CI workflow to fail only at your chosen severity threshold.

## 11. Backups and recovery

Enable Supabase PITR/backups and test a restore before declaring production ready. Redis is a queue/cache; PostgreSQL remains the durable application state.

## 12. Operational checks

Before public exposure verify:

- Supabase RLS and cross-tenant tests
- MFA for Owner/Admin
- exact CORS origin
- target scope enforcement
- no service-role key in frontend assets
- Redis/DB are not internet reachable
- HTTPS/HSTS
- backup restore
- worker restart recovery
- rate limiting
- dependency/image scanning
- authorized-target evidence for every assessment


### Mandatory durable-worker database setting

In production, set `SCHEDULER_DATABASE_URL` to a server-side PostgreSQL connection with the minimum privileges required to enumerate and update `continuous_schedules` across tenants. Do not expose it to the frontend. The API now fails closed if this value is missing, because a normal tenant-scoped DB connection cannot safely own the global scheduler under FORCE RLS.


### Current database migrations
The current production schema requires migrations 0001 through 0007, including `0007_security_session_enforcement.sql` for forced session invalidation after role/activation changes.
