-- Fast durable lookup for active scan recovery.
-- The live progress UI primarily uses Redis, but this index keeps the
-- authoritative DB fallback fast after refresh/reconnect/cache misses.
create index if not exists idx_scan_jobs_tenant_status_created
  on public.scan_jobs (tenant_id, status, created_at desc);

create index if not exists idx_scans_tenant_created
  on public.scans (tenant_id, created_at desc);
