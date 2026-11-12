create table if not exists public.finding_lifecycle (
  lifecycle_id varchar(64) primary key,
  tenant_id varchar(64) not null,
  scan_id varchar(64) not null,
  finding_id varchar(128) not null,
  status varchar(32) not null default 'DISCOVERED',
  note text not null default '',
  actor_user_id varchar(64),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_finding_lifecycle_tenant_scan on public.finding_lifecycle(tenant_id, scan_id);
create index if not exists idx_finding_lifecycle_finding on public.finding_lifecycle(tenant_id, finding_id);
alter table public.finding_lifecycle enable row level security;
alter table public.finding_lifecycle force row level security;
drop policy if exists tenant_isolation on public.finding_lifecycle;
create policy tenant_isolation on public.finding_lifecycle using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));
