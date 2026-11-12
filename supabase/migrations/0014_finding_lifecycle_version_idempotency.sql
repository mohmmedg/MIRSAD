-- Local-First support: optimistic concurrency (version) + idempotent retries
-- for the finding-lifecycle PATCH endpoint. Additive only: existing rows get
-- version=1, existing callers that omit base_version/idempotency_key keep the
-- exact previous behaviour (unconditional overwrite), see
-- backend/app/core/assessment_lifecycle.py for the read path.

alter table public.finding_lifecycle
  add column if not exists version integer not null default 1;

create table if not exists public.finding_lifecycle_idempotency (
  tenant_id text not null,
  idempotency_key text not null,
  result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  primary key (tenant_id, idempotency_key)
);

alter table public.finding_lifecycle_idempotency enable row level security;

drop policy if exists finding_lifecycle_idempotency_tenant_isolation on public.finding_lifecycle_idempotency;
create policy finding_lifecycle_idempotency_tenant_isolation on public.finding_lifecycle_idempotency
  for all to authenticated
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

-- Housekeeping: idempotency keys only need to survive long enough to cover
-- realistic retry windows (background sync after a reconnect). A periodic
-- job/cron can delete rows older than a few days; not enforced in SQL here
-- to avoid depending on pg_cron being enabled on every environment.
create index if not exists idx_finding_lifecycle_idempotency_created_at
  on public.finding_lifecycle_idempotency (created_at);
