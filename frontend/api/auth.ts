import type { VercelRequest, VercelResponse } from "@vercel/node"
import { handleOptions, setSecureCors } from "./_security"

// SECURITY (2026-10-21): this endpoint used to expose unauthenticated `signup`
// (admin.createUser with email_confirm:true using the service-role key) and a
// `login` password proxy. That bypassed the disabled self-service signup and
// email verification, and gave unlimited credential-stuffing with no rate limit.
//
// The SPA talks to Supabase Auth directly (src/auth/supabase.ts) and never
// calls this function, so it is now intentionally inert and the service-role
// key is no longer used here. Account creation for organizations goes through
// the authenticated, step-up-protected POST /api/v1/admin/users on the backend.
export default function handler(req: VercelRequest, res: VercelResponse) {
  setSecureCors(req, res)
  if (handleOptions(req, res)) return
  return res.status(410).json({ error: "This endpoint has been removed." })
}
