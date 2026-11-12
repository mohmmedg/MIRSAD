-- Keep sensitive system tables closed to client roles while making the RLS intent explicit.
-- Backend/service-role access is not affected by these policies.
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.refresh_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_no_client_access ON public.tenants;
CREATE POLICY tenants_no_client_access ON public.tenants
  AS RESTRICTIVE FOR ALL TO public
  USING (false) WITH CHECK (false);

DROP POLICY IF EXISTS users_no_client_access ON public.users;
CREATE POLICY users_no_client_access ON public.users
  AS RESTRICTIVE FOR ALL TO public
  USING (false) WITH CHECK (false);

DROP POLICY IF EXISTS refresh_tokens_no_client_access ON public.refresh_tokens;
CREATE POLICY refresh_tokens_no_client_access ON public.refresh_tokens
  AS RESTRICTIVE FOR ALL TO public
  USING (false) WITH CHECK (false);
