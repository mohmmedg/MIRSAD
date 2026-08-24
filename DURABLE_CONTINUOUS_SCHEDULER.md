# Durable Continuous ASM Scheduler

Continuous ASM no longer runs `asyncio` scheduler tasks inside API replicas.

## Runtime

`Postgres continuous_schedules` is the source of truth.

1. Worker replicas poll due schedules.
2. Redis `SET NX` provides short-lived cross-replica enqueue ownership.
3. Due work is persisted in Redis `continuous_scan_queue`.
4. Worker claims a Postgres execution lease.
5. The scanner runs only in a worker process.
6. Completion/failure is written back to Postgres.
7. Expired leases can be recovered by another worker.

This prevents duplicate scans when multiple API/worker replicas are running.

## Required production setting

For PostgreSQL/Supabase, configure:

`SCHEDULER_DATABASE_URL`

to a dedicated scheduler database role that can enumerate and update `continuous_schedules` across tenants. Keep this URL server-side only. It is never accepted from API requests.

For local SQLite development it can be omitted.

## Operational guarantees

- No scheduler state is held only in process memory.
- API restart does not delete schedules.
- Worker restart does not delete schedules.
- Multiple workers coordinate through Redis.
- A crashed worker leaves an expiring lease rather than a permanently locked schedule.
- A disabled schedule is skipped even if an old queue item remains.
- Tenant context is restored before scanner/SOC writes.
