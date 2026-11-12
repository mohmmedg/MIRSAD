alter table public.security_configuration_baseline enable row level security;
create policy security_configuration_baseline_service_only on public.security_configuration_baseline
  for all to service_role using (true) with check (true);
