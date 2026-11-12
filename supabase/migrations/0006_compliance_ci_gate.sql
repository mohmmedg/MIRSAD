-- 0006: Compliance Center + CI/CD Security Gate
create table if not exists public.compliance_controls (
  control_id text not null,
  tenant_id text not null,
  framework text not null,
  title text not null,
  description text not null default '',
  enabled boolean not null default true,
  tags jsonb not null default '[]'::jsonb,
  max_severity text not null default 'Low',
  updated_at timestamptz not null default now(),
  primary key (tenant_id, control_id)
);
create index if not exists compliance_controls_tenant_idx on public.compliance_controls(tenant_id, framework);

create table if not exists public.compliance_assessments (
  assessment_id text primary key,
  tenant_id text not null,
  framework text not null,
  score double precision not null default 0,
  passed integer not null default 0,
  failed integer not null default 0,
  controls jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists compliance_assessments_tenant_idx on public.compliance_assessments(tenant_id, created_at desc);

create table if not exists public.ci_security_policies (
  tenant_id text primary key,
  critical_fail integer not null default 0,
  high_fail integer not null default 0,
  medium_fail integer not null default 0,
  enabled boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.compliance_controls enable row level security;
alter table public.compliance_controls force row level security;
alter table public.compliance_assessments enable row level security;
alter table public.compliance_assessments force row level security;
alter table public.ci_security_policies enable row level security;
alter table public.ci_security_policies force row level security;

drop policy if exists tenant_isolation on public.compliance_controls;
create policy tenant_isolation on public.compliance_controls using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));
drop policy if exists tenant_isolation on public.compliance_assessments;
create policy tenant_isolation on public.compliance_assessments using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));
drop policy if exists tenant_isolation on public.ci_security_policies;
create policy tenant_isolation on public.ci_security_policies using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));
