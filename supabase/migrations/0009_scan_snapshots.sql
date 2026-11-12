-- Durable, immutable source of truth for completed scan/report reads.
create table if not exists public.scan_snapshots (
  scan_id text primary key,
  tenant_id text not null,
  snapshot_version text not null default '2',
  data jsonb not null,
  created_at timestamptz not null default now(),
  finalized_at timestamptz
);
create index if not exists ix_scan_snapshots_tenant_created on public.scan_snapshots(tenant_id, created_at desc);
alter table public.scan_snapshots enable row level security;
alter table public.scan_snapshots force row level security;
drop policy if exists tenant_isolation on public.scan_snapshots;
create policy tenant_isolation on public.scan_snapshots
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

-- Upgrade pre-existing snapshot rows to the canonical snapshot contract.
alter table public.scan_snapshots alter column snapshot_version set default '2';
update public.scan_snapshots set snapshot_version = '2' where snapshot_version = '1';
