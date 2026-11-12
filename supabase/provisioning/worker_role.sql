-- MIRSAD: dedicated DB role for the scan worker / scheduler.
--
-- Why: scan_jobs (and other tables) use FORCE ROW LEVEL SECURITY with a
-- tenant_id = app.tenant_id policy. The worker must find a job BEFORE it knows
-- the tenant, and its sweeps (orphan recovery, pending recovery, stale-job
-- cleanup, schedules) span all tenants. A role without BYPASSRLS sees 0 rows,
-- so queued scans were silently ACKed and never ran. The API keeps using the
-- restricted `mirsad` role; only the worker/scheduler use this one.
--
-- Idempotent; re-running rotates the password. Run once as the superuser,
-- against the `mirsad` database, from the project root:
--
--   docker compose exec -T postgres18 psql -U postgres -d mirsad -v ON_ERROR_STOP=1 \
--     -v worker_password="<password>" < supabase/provisioning/worker_role.sql
--
-- Then put the URL-encoded password in the root .env as
-- WORKER_PG_PASSWORD_URLENCODED and run `docker compose up -d worker backend`.

SELECT format('CREATE ROLE mirsad_worker LOGIN BYPASSRLS PASSWORD %L', :'worker_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mirsad_worker') \gexec

SELECT format('ALTER ROLE mirsad_worker LOGIN BYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', :'worker_password') \gexec

-- Same table privileges as the application role (inherited), no SET ROLE.
GRANT mirsad TO mirsad_worker WITH INHERIT TRUE, SET FALSE;
