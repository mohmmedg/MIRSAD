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
