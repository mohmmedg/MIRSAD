# Durable Scheduler Release Report — 2026-08-22

Implemented the final Continuous ASM scheduling hardening.

## Changes
- Removed in-process `asyncio` schedule ownership from the API.
- Added durable `next_run_at`, `lease_owner`, and `lease_until` fields.
- Added Redis cross-replica enqueue lock.
- Added durable Redis `continuous_scan_queue`.
- Continuous scans execute only in the worker process.
- Added worker execution leases with expiry/recovery.
- Added optional `SCHEDULER_DATABASE_URL` for a privileged scheduler DB role across tenants.
- Added migration `0005_durable_continuous_scheduler.sql`.
- Added multi-replica scheduler regression tests.

## Verification
- Python compileall: PASS
- Backend test suite: **149/149 PASSED**
