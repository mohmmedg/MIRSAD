# Supabase deployment

Supabase is the hosted Auth + PostgreSQL foundation. FastAPI remains the security/policy boundary; Redis remains the queue.

1. Create a Supabase project.
2. Run `migrations/0001_security_platform.sql`.
3. Configure Supabase Auth and put `tenant_id` and `role` in `app_metadata` for multi-user tenants.
4. Set `AUTH_PROVIDER=supabase`, `SUPABASE_URL`, issuer/audience and `DATABASE_URL` in server-side `backend/.env`.
5. Set only `VITE_SUPABASE_URL` and the public `VITE_SUPABASE_ANON_KEY` in `frontend/.env`. Never expose `service_role`.

If no tenant claim is present, the backend auto-provisions an isolated tenant derived from the Supabase subject. For shared tenants, configure the tenant claim explicitly.
