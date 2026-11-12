-- Per-execution isolation for parallel scanner work.
create table if not exists public.scan_executions (
  execution_id varchar(64) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  job_id varchar(64) not null references public.scan_jobs(job_id) on delete cascade,
  attempt integer not null default 1,
  job_type varchar(32) not null,
  target varchar(2048) not null,
  status varchar(24) not null,
  current_engine varchar(64),
  metadata jsonb not null default '{}'::jsonb,
  started_at timestamptz not null default now(),
  finished_at timestamptz
);
create table if not exists public.scan_execution_events (
  event_id varchar(64) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  execution_id varchar(64) not null references public.scan_executions(execution_id) on delete cascade,
  operation_id varchar(64),
  sequence integer not null,
  event_type varchar(64) not null,
  stage varchar(128),
  tool varchar(128),
  message text not null default '',
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists idx_scan_exec_tenant_scan_started on public.scan_executions(tenant_id,scan_id,started_at desc);
create index if not exists idx_scan_exec_events_execution_seq on public.scan_execution_events(execution_id,sequence);
create index if not exists idx_scan_exec_events_execution_time on public.scan_execution_events(execution_id,created_at);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['scan_executions','scan_execution_events'] LOOP EXECUTE format('alter table public.%I enable row level security',t); EXECUTE format('alter table public.%I force row level security',t); EXECUTE format('drop policy if exists tenant_isolation on public.%I',t); EXECUTE format('create policy tenant_isolation on public.%I using (tenant_id = current_setting(''app.tenant_id'', true)) with check (tenant_id = current_setting(''app.tenant_id'', true))',t); END LOOP; END $$;
