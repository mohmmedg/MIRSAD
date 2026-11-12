-- Per-account scan ownership and safe deletion.
alter table if exists public.scans
  add column if not exists created_by_user_id varchar(64);

alter table if exists public.scan_jobs
  add column if not exists created_by_user_id varchar(64);

create index if not exists idx_scans_owner_created_at
  on public.scans(created_by_user_id, created_at desc);

create index if not exists idx_scan_jobs_owner_created_at
  on public.scan_jobs(created_by_user_id, created_at desc);

-- Personal Supabase tenants encode the owner in tenant_id. This safely
-- attributes legacy rows that were already isolated to one user's personal
-- tenant. Organization-shared legacy rows remain unowned and are not exposed
-- by the per-account history endpoint until a new owner is recorded.
update public.scans
set created_by_user_id = substring(tenant_id from 9)
where created_by_user_id is null
  and tenant_id like 'supabase:%'
  and length(tenant_id) > 9;

update public.scan_jobs
set created_by_user_id = substring(tenant_id from 9)
where created_by_user_id is null
  and tenant_id like 'supabase:%'
  and length(tenant_id) > 9;
