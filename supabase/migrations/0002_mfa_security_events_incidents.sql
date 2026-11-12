-- 0002: MFA/AAL security event, alert and incident center
create table if not exists public.security_events (
  event_id text primary key, tenant_id text not null, event_type text not null,
  severity text not null, actor_user_id text, target text, data jsonb not null default '{}'::jsonb,
  risk_score integer not null default 0, detected boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists security_events_tenant_created_idx on public.security_events(tenant_id, created_at desc);
create index if not exists security_events_tenant_type_idx on public.security_events(tenant_id, event_type);

create table if not exists public.security_alerts (
  alert_id text primary key, tenant_id text not null, event_id text, title text not null,
  severity text not null, status text not null default 'open', risk_score integer not null default 0,
  data jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(),
  acknowledged_at timestamptz
);
create index if not exists security_alerts_tenant_status_idx on public.security_alerts(tenant_id,status,created_at desc);

create table if not exists public.security_incidents (
  incident_id text primary key, tenant_id text not null, title text not null, description text not null default '',
  severity text not null, status text not null default 'open', assignee_user_id text, sla_due_at timestamptz,
  related_asset_id text, related_scan_id text, related_finding_id text, related_user_id text,
  evidence jsonb not null default '[]'::jsonb, timeline jsonb not null default '[]'::jsonb,
  ai_explanation text, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists security_incidents_tenant_status_idx on public.security_incidents(tenant_id,status,updated_at desc);

alter table public.security_events enable row level security;
alter table public.security_events force row level security;
drop policy if exists tenant_isolation on public.security_events;
create policy tenant_isolation on public.security_events using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));

alter table public.security_alerts enable row level security;
alter table public.security_alerts force row level security;
drop policy if exists tenant_isolation on public.security_alerts;
create policy tenant_isolation on public.security_alerts using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));

alter table public.security_incidents enable row level security;
alter table public.security_incidents force row level security;
drop policy if exists tenant_isolation on public.security_incidents;
create policy tenant_isolation on public.security_incidents using (tenant_id = current_setting('app.tenant_id', true)) with check (tenant_id = current_setting('app.tenant_id', true));

-- Existing tenants: make MFA mandatory for privileged administration.
update public.admin_settings set security_policy = security_policy || '{"require_mfa":true}'::jsonb;
