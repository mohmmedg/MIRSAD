-- 0007: security session invalidation epoch for role/activation changes
alter table public.users
  add column if not exists security_changed_at timestamptz;
create index if not exists idx_users_tenant_security_changed
  on public.users(tenant_id, security_changed_at);

comment on column public.users.security_changed_at is
  'Any access/refresh session issued before this timestamp is invalid after a privileged security change.';
