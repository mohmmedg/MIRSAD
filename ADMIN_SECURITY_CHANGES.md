# Admin & Security Hardening Changes

This release keeps the existing frontend visual identity and adds a protected tenant administration layer.

## Backend
- Added `/api/v1/admin/overview`, `/api/v1/admin/users`, `/api/v1/admin/users/{user_id}`, and `/api/v1/admin/audit`.
- Admin endpoints require `admin` or `owner` server-side RBAC.
- Admins can manage viewer/analyst accounts.
- Owners can manage privileged accounts but cannot transfer ownership.
- Users cannot deactivate themselves.
- User changes are written to the tenant audit log.
- Optional `SUPABASE_SERVICE_ROLE_KEY` synchronizes role/status changes to Supabase `app_metadata`.
- Existing database RBAC is authoritative after provisioning; stale JWT role claims cannot restore a revoked role.
- First auto-provisioned user of a new Supabase tenant becomes `owner`.
- Disabled users are rejected by the backend.
- RLS initialization now covers assets and audit logs in addition to scan jobs/scans.
- Removed a duplicate stale `backend/backend` tree and generated caches.

## Frontend
- Added an Admin Control Center visible only to owner/admin roles.
- Added tenant user table, role controls, enable/disable controls, overview counters and audit log.
- Added authenticated admin API client methods.
- Added client-side role detection for navigation/UI only; backend remains authoritative.

## Validation
- Python compile check: passed.
- Backend full test suite: **141 passed**.
- Frontend production build was previously verified in the supplied project state, but could not be re-run in this isolated build environment because npm dependency installation timed out/no network. Run `npm.cmd ci` then `npm.cmd run build` locally.
