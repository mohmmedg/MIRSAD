-- 0005: durable multi-replica Continuous ASM scheduler
-- Postgres is the source of truth; Redis only transports/coordinates work.
alter table public.continuous_schedules
  add column if not exists next_run_at timestamptz,
  add column if not exists lease_owner text,
  add column if not exists lease_until timestamptz;

create index if not exists continuous_schedules_due_idx
  on public.continuous_schedules(enabled, next_run_at);

update public.continuous_schedules
set next_run_at = coalesce(last_run + make_interval(secs => interval_seconds), created_at, now())
where next_run_at is null;

comment on column public.continuous_schedules.next_run_at is
  'Durable due-time. Worker replicas enqueue only when this timestamp is due.';
comment on column public.continuous_schedules.lease_owner is
  'Short-lived worker ownership marker for an executing schedule.';
comment on column public.continuous_schedules.lease_until is
  'Expiry of the worker lease; expired leases can be recovered by another worker.';
