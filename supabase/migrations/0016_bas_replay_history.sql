-- 4.4: durable history of BAS (breach-and-attack-simulation) replay runs.
-- ContinuousScheduleRow.request["last_summary"] already caches the MOST
-- RECENT replay outcome inline (no migration needed for that - see
-- continuous.py::_execute_bas_replay), but that overwrites itself every
-- run and has no tenant-isolated query surface of its own. This table adds
-- the durable, queryable history on top, following the same tenant_id +
-- RLS pattern as 0009_scan_snapshots.sql.
create table if not exists public.bas_replay_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id text not null,
  schedule_id text not null,
  scan_id text not null,
  total_targets integer not null,
  still_live_count integer not null,
  resolved_count integer not null,
  unknown_count integer not null,
  outcomes jsonb not null,
  replayed_at timestamptz not null default now()
);
create index if not exists ix_bas_replay_runs_tenant_replayed
  on public.bas_replay_runs(tenant_id, replayed_at desc);
create index if not exists ix_bas_replay_runs_schedule
  on public.bas_replay_runs(schedule_id, replayed_at desc);

alter table public.bas_replay_runs enable row level security;
alter table public.bas_replay_runs force row level security;
drop policy if exists tenant_isolation on public.bas_replay_runs;
create policy tenant_isolation on public.bas_replay_runs
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

comment on table public.bas_replay_runs is
  'One row per BAS replay execution (see attack_simulation/simulator.py + continuous.py::_execute_bas_replay). Append-only history; the schedule row itself only ever caches the latest summary.';
