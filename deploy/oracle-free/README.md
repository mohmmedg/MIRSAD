# MIRSAD: Oracle Cloud Always Free (limited, experimental backend)

This is a resource-constrained **development/staging deployment**, not proof that every scanner engine runs on Oracle ARM64. The full `docker-compose.production.yml` includes DefectDojo, ZAP and PostgreSQL: **do not start that full stack on a 12 GB Oracle Always Free VM**. This stack intentionally uses only Caddy + FastAPI + one worker + Redis; frontend remains on Vercel and persistent relational data remains in Supabase.

## Prerequisites

1. Create an Oracle **Always Free Ampere A1** Ubuntu VM in your home region, within your current Always Free allocation (typically 2 OCPU / 12 GB RAM maximum for continuous use). Verify the selected shape and costs in Oracle before creation; A1 capacity is not guaranteed. Configure an OCI network security list to allow only TCP 22 (from your trusted IP), 80, and 443. Do **not** open 6379 or 8000 to the Internet. Review Oracle's security testing policy before any scanner use; only test expressly authorized targets, use non-aggressive modes, and complete any notification/approval obligations that apply.
2. Point a DNS `A` record, e.g. `api.example.com`, to your Oracle instance's public IPv4. In OCI, reserve a static public IP if available in your free quota. Caddy needs port 80/443 reachable for automatic HTTPS.
3. SSH into the VM, install Docker Engine and Compose plugin from [Docker's official Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/). The login user needs Docker permissions; restrict who can use Docker because it grants root-equivalent access.
4. Clone this repository and keep secrets **outside Git**.

## Set up production values

```bash
git clone https://github.com/mohmmedg/MIRSAD.git
cd MIRSAD
# For this proposal branch until PR is merged:
git fetch origin deploy/vercel-supabase-gateway-20261112
git checkout deploy/vercel-supabase-gateway-20261112
cp backend/.env.production.example backend/.env.production
chmod 600 backend/.env.production
# Edit using your preferred terminal editor, never print its values in logs.
nano backend/.env.production
```

Set these values in `backend/.env.production`: `ENVIRONMENT=production`, `SUPABASE_URL`, `SUPABASE_JWT_ISSUER`, `SUPABASE_JWT_AUDIENCE`, `DATABASE_URL`, `SCHEDULER_DATABASE_URL`, `CORS_ORIGINS` (your actual Vercel domain), `ENFORCE_TARGET_SCOPE=true`, `ALLOWED_TARGETS` (only owned/authorized targets), and backend-only secrets. Set `DB_AUTO_CREATE_SCHEMA=false` when using your existing migrated Supabase schema. Prefer a Supabase pooler connection appropriate to the existing backend/worker and database client settings. Avoid pasting connection strings, password, or service-role key into Vercel `VITE_*` values.

Create `deploy/oracle-free/.env` with only:
```dotenv
MIRSAD_API_DOMAIN=api.example.com
REDIS_PASSWORD=REPLACE_WITH_A_LONG_RANDOM_HEX_PASSWORD
DATABASE_URL=REPLACE_WITH_SUPABASE_POOLER_URL
SCHEDULER_DATABASE_URL=REPLACE_WITH_SUPABASE_POOLER_URL
ALLOWED_TARGETS=your-owned-lab.example
```
```bash
chmod 600 deploy/oracle-free/.env
docker compose --env-file deploy/oracle-free/.env -f deploy/oracle-free/compose.yaml config --quiet
docker compose --env-file deploy/oracle-free/.env -f deploy/oracle-free/compose.yaml up -d --build
docker compose --env-file deploy/oracle-free/.env -f deploy/oracle-free/compose.yaml ps
curl -fsS https://api.example.com/health
```
Use a secure external secret manager for secrets if possible. The `compose config` command may print secrets when run without `--quiet`; avoid sending its output to public logs.

**ARM64 compatibility gate:** The backend Dockerfile installs pinned scanner binaries, Semgrep, browser dependencies and templates at **build time** regardless of the runtime `ENABLE_*` flags. Expect large downloads and possible ARM64 compilation or binary compatibility issues. Before relying on this instance, confirm that `docker compose build backend` completes on your selected ARM64 VM and validate each scanner version with a harmless, explicitly authorized lab target. If it fails, use a custom slim ARM64 backend Dockerfile or paid AMD64 VM; do not silently emulate unsupported scanner tools or report them as installed.

## Connect Vercel

In the existing `mirsad` Vercel project, add **server-only** `MIRSAD_BACKEND_URL=https://api.example.com` to Production and Preview, then redeploy. Leave `VITE_API_BASE_URL` unset so `/api/v1/*` routes use the same-origin Vercel gateway. For direct progress WebSockets, set `VITE_WS_BASE_URL=wss://api.example.com` and redeploy the UI (the Vercel HTTP gateway cannot upgrade to WebSockets). Backend CORS must allow the deployed Vercel frontend domain(s). Never set `SUPABASE_SERVICE_ROLE_KEY` with a `VITE_` prefix.

## Security and operating limits

- Disable public self-service scanning until the backend's authentication and per-tenant target authorization are verified. `ALLOWED_TARGETS` is an additional safeguard, not an authorization substitute. Avoid scanning sites you do not own or lack explicit authorization for.
- Restrict outbound target networks, avoid privileged/host network modes, run only essential capabilities, keep OCI security groups closed, and implement scan rate/concurrency limits.
- This is not a high-availability system: the Free instance can be unavailable, worker and API share CPU, and container filesystem storage must be backed up. Exercise restore and alerting before production.
- If `/health` succeeds but `/readiness` or authenticated `/api/v1/auth/me` fails, inspect logs and DB connectivity before enabling scans.
- No automated Oracle provisioning or completed scanner execution is claimed by this document.
