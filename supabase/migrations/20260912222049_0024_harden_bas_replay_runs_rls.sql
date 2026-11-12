drop policy if exists tenant_isolation on public.bas_replay_runs;
create policy tenant_isolation on public.bas_replay_runs
  using (tenant_id = (select current_setting('app.tenant_id', true)))
  with check (tenant_id = (select current_setting('app.tenant_id', true)));
