-- 0028: additive canonical result/evidence hardening.
-- No existing rows are deleted or rewritten by this migration.

create table if not exists public.raw_artifacts (
  artifact_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  execution_id varchar(64) references public.scan_executions(execution_id) on delete set null,
  engine_result_id varchar(128),
  tool varchar(64),
  kind varchar(32) not null,
  content bytea,
  sha256 varchar(64) not null,
  size_bytes bigint not null default 0,
  storage_ref text,
  encoding varchar(64),
  part_index integer,
  parent_artifact_id varchar(128) references public.raw_artifacts(artifact_id) on delete set null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.engine_results (
  engine_result_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  execution_id varchar(64) references public.scan_executions(execution_id) on delete set null,
  engine varchar(64) not null,
  version varchar(1000),
  command jsonb not null default '[]'::jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  duration_seconds double precision,
  exit_code integer,
  status varchar(24) not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.finding_sources (
  source_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  finding_id varchar(128) not null,
  engine varchar(64) not null,
  engine_result_id varchar(128),
  execution_id varchar(64),
  raw_artifact_id varchar(128),
  raw_locator varchar(256),
  observation jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.raw_artifacts add column if not exists encoding varchar(64);
alter table public.raw_artifacts add column if not exists part_index integer;
alter table public.raw_artifacts add column if not exists parent_artifact_id varchar(128);
alter table public.finding_sources add column if not exists raw_locator varchar(256);
alter table public.finding_sources add column if not exists observation jsonb not null default '{}'::jsonb;

create table if not exists public.verification_events (
  event_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  finding_id varchar(128) not null,
  method varchar(128) not null,
  status_from varchar(32),
  status_to varchar(32) not null,
  evidence jsonb not null default '{}'::jsonb,
  request_ref varchar(256),
  response_ref varchar(256),
  created_at timestamptz not null default now()
);

create table if not exists public.reparse_jobs (
  reparse_job_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  artifact_id varchar(128) not null references public.raw_artifacts(artifact_id) on delete cascade,
  status varchar(24) not null default 'PENDING',
  parser varchar(128),
  result_version integer not null default 1,
  error_message text,
  created_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists public.reparse_results (
  reparse_result_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  artifact_id varchar(128) not null references public.raw_artifacts(artifact_id) on delete cascade,
  reparse_job_id varchar(128) not null references public.reparse_jobs(reparse_job_id) on delete cascade,
  result_version integer not null,
  finding jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.defectdojo_mappings (
  mapping_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  finding_id varchar(128),
  engine_result_id varchar(128),
  engagement_id bigint,
  test_id bigint,
  defectdojo_finding_id bigint,
  fingerprint varchar(128),
  idempotency_key varchar(256) not null,
  mapping_type varchar(32) not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, idempotency_key)
);

create table if not exists public.external_sync_jobs (
  job_id varchar(128) primary key,
  tenant_id varchar(64) not null references public.tenants(tenant_id) on delete cascade,
  scan_id varchar(64) not null references public.scans(scan_id) on delete cascade,
  provider varchar(64) not null,
  status varchar(24) not null default 'PENDING',
  attempt_count integer not null default 0,
  next_retry_at timestamptz not null default now(),
  last_error_code varchar(64),
  last_error_message text,
  idempotency_key varchar(256) not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, idempotency_key)
);

create index if not exists idx_raw_artifacts_tenant_scan on public.raw_artifacts(tenant_id,scan_id,created_at);
create index if not exists idx_engine_results_tenant_scan on public.engine_results(tenant_id,scan_id,created_at);
create index if not exists idx_finding_sources_tenant_finding on public.finding_sources(tenant_id,finding_id,created_at);
create index if not exists idx_verification_events_tenant_finding on public.verification_events(tenant_id,finding_id,created_at);
create index if not exists idx_reparse_jobs_pending on public.reparse_jobs(status,created_at);
create index if not exists idx_external_sync_jobs_due on public.external_sync_jobs(status,next_retry_at);
create index if not exists idx_reparse_results_scan on public.reparse_results(tenant_id,scan_id,result_version,created_at);

-- Raw evidence is append-only. Direct mutation is forbidden; ON DELETE CASCADE
-- from scans is allowed because the scan row is already absent when PostgreSQL
-- invokes the child cascade trigger.
create or replace function public.prevent_raw_artifact_mutation() returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  if tg_op = 'UPDATE' then
    if (old.content,old.sha256,old.size_bytes,old.storage_ref,old.tool,old.scan_id)
       is distinct from (new.content,new.sha256,new.size_bytes,new.storage_ref,new.tool,new.scan_id) then
      raise exception 'raw_artifacts evidence fields are immutable';
    end if;
    return new;
  elsif tg_op = 'DELETE' then
    if exists (select 1 from public.scans s where s.scan_id = old.scan_id) then
      raise exception 'raw_artifacts cannot be deleted directly';
    end if;
    return old;
  end if;
  return new;
end $$;

do $$
begin
  if not exists (select 1 from pg_trigger where tgname = 'trg_raw_artifacts_immutable' and tgrelid = 'public.raw_artifacts'::regclass) then
    create trigger trg_raw_artifacts_immutable
    before update or delete on public.raw_artifacts
    for each row execute function public.prevent_raw_artifact_mutation();
  end if;
end $$;

do $$
declare t text;
begin
  foreach t in array array['raw_artifacts','engine_results','finding_sources','verification_events','reparse_jobs','reparse_results','defectdojo_mappings','external_sync_jobs'] loop
    execute format('alter table public.%I enable row level security',t);
    execute format('alter table public.%I force row level security',t);
    if not exists (select 1 from pg_policies where schemaname='public' and tablename=t and policyname='tenant_isolation') then
      execute format('create policy tenant_isolation on public.%I using (tenant_id = current_setting(''app.tenant_id'', true)) with check (tenant_id = current_setting(''app.tenant_id'', true))',t);
    end if;
  end loop;
end $$;
