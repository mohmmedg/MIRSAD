drop policy if exists finding_lifecycle_tenant_isolation on public.finding_lifecycle;
create policy finding_lifecycle_tenant_isolation on public.finding_lifecycle
  for all to authenticated
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

create or replace function public.touch_finding_lifecycle_updated_at()
returns trigger
language plpgsql
set search_path = pg_catalog
as $$
begin
  new.updated_at = pg_catalog.now();
  return new;
end;
$$;

revoke all on function public.touch_finding_lifecycle_updated_at() from public;

drop trigger if exists trg_finding_lifecycle_updated_at on public.finding_lifecycle;
create trigger trg_finding_lifecycle_updated_at
before update on public.finding_lifecycle
for each row execute function public.touch_finding_lifecycle_updated_at();
