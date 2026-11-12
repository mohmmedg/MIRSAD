-- MIRSAD enterprise durability / tenant identity hardening.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Re-key legacy assets so identical targets in different tenants can coexist.
UPDATE public.assets
SET asset_id = left(encode(digest(tenant_id || ':' || lower(target), 'sha256'), 'hex'), 16)
WHERE asset_id <> left(encode(digest(tenant_id || ':' || lower(target), 'sha256'), 'hex'), 16);
ALTER TABLE public.scan_jobs ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz;
ALTER TABLE public.scan_jobs ADD COLUMN IF NOT EXISTS lease_owner varchar(128);
ALTER TABLE public.scan_jobs ADD COLUMN IF NOT EXISTS lease_until timestamptz;
ALTER TABLE public.scan_jobs ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_running_heartbeat ON public.scan_jobs(status, heartbeat_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_lease_until ON public.scan_jobs(lease_until);

ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS canonical_identity varchar(2048);
UPDATE public.assets SET canonical_identity = COALESCE(NULLIF(canonical_identity,''), target) WHERE canonical_identity IS NULL OR canonical_identity='';
ALTER TABLE public.assets ALTER COLUMN canonical_identity SET DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_tenant_identity ON public.assets(tenant_id, canonical_identity);

-- Stream consumers are infrastructure state; the stream/group is created by the worker
-- at startup so migrations remain safe for hosted Postgres-only deployments.

-- Recreate the intended tenant-scoped identity contract after legacy re-keying.
DROP INDEX IF EXISTS ux_assets_tenant_identity;
CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_tenant_identity ON public.assets(tenant_id, canonical_identity);


CREATE TABLE IF NOT EXISTS public.verification_attempts (
  verification_id varchar(64) primary key, tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64), job_id varchar(64), finding_id varchar(128) not null, rule_id varchar(128) not null,
  method varchar(128) not null, verifier varchar(128) not null default 'deterministic-engine', result varchar(32) not null,
  confidence double precision not null default 0, evidence jsonb not null default '[]'::jsonb, request_id varchar(128), response_id varchar(128),
  started_at timestamptz not null, completed_at timestamptz not null, reason text
);
CREATE INDEX IF NOT EXISTS idx_verification_attempts_tenant_finding ON public.verification_attempts(tenant_id, finding_id, completed_at desc);
ALTER TABLE public.verification_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verification_attempts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.verification_attempts;
CREATE POLICY tenant_isolation ON public.verification_attempts USING (tenant_id = current_setting('app.tenant_id', true)) WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
