-- 0004: tenant-scoped Continuous Attack Surface Monitoring
create table if not exists public.continuous_schedules (
  schedule_id text primary key, tenant_id text not null, target text not null, request jsonb not null,
  interval_seconds integer not null default 3600, enabled boolean not null default true,
  created_at timestamptz not null default now(), last_run timestamptz, last_status text, last_error text
);
create index if not exists continuous_schedules_tenant_idx on public.continuous_schedules(tenant_id, enabled);
alter table public.continuous_schedules enable row level security;
create policy continuous_schedules_tenant_isolation on public.continuous_schedules
using (tenant_id = current_setting('app.tenant_id', true))
with check (tenant_id = current_setting('app.tenant_id', true));

-- Assets retain a deterministic surface snapshot in data.surface_snapshot; no destructive schema change required.
