# Admin Security Center

This release extends the hardened Supabase build with a tenant-scoped administration center.

## Included
- User lifecycle and RBAC management
- Permission matrix endpoint
- Security, scan, AI and notification policy storage
- Tenant-scoped feature flags
- Refresh-session listing and revocation
- Hashed, scoped, expiring API keys; plaintext is returned only at creation
- Operational health and backup/recovery status
- Audit events for privileged changes
- RLS for admin settings, feature flags and API keys

## Safety
- Service-role credentials remain server-side.
- API-key secrets are never persisted in plaintext.
- Backup status is informational; use Supabase/Postgres managed backups and verify restores separately.
- Scan governance settings are administrative policy data; enforcement should be wired into every scan/job admission path before production launch.
