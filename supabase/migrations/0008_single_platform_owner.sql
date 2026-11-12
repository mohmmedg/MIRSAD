-- MIRSAD platform owner singleton.
-- Only one application user may hold the owner role.
create unique index if not exists ux_users_single_platform_owner
on public.users ((role))
where role = 'owner';
