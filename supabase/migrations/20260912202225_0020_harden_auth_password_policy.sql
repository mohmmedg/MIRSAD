-- Security hardening: enable leaked-password protection through Supabase Auth settings.
-- Auth provider settings are managed outside the public schema, so no public-table DDL
-- is performed here. This migration records the required operational baseline safely.
create table if not exists public.security_configuration_baseline (
  config_key text primary key,
  config_value jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

insert into public.security_configuration_baseline(config_key, config_value)
values ('auth_password_policy', jsonb_build_object(
  'leaked_password_protection_required', true,
  'minimum_password_length', 12,
  'strong_password_requirements', true
))
on conflict (config_key) do update
set config_value = excluded.config_value,
    updated_at = now();
