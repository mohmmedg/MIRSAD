-- 0003: scanner finding correlation and incident linkage
alter table if exists public.security_alerts
  add column if not exists incident_id text;
create index if not exists security_alerts_tenant_incident_idx
  on public.security_alerts(tenant_id, incident_id);

-- Scanner pipeline events are intentionally tenant-scoped; RLS remains enforced.
