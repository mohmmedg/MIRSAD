import type { VercelRequest, VercelResponse } from "@vercel/node"
import { createClient } from "@supabase/supabase-js"
import { handleOptions, isPlainRecord, safeServerError, setSecureCors } from "./_security"

const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY

function getClient() {
  if (!supabaseUrl || !supabaseKey) return null
  return createClient(supabaseUrl, supabaseKey, { auth: { persistSession: false, autoRefreshToken: false } })
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  setSecureCors(req, res)
  if (handleOptions(req, res)) return
  if (!['GET', 'PUT'].includes(req.method || '')) return res.status(405).json({ error: 'Method not allowed' })

  const supabase = getClient()
  if (!supabase) return safeServerError(res)

  try {
    const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : ''
    if (!/^Bearer [A-Za-z0-9._~+\/-]+=*$/.test(authHeader)) return res.status(401).json({ error: 'Authentication required.' })
    const token = authHeader.slice(7)
    const { data, error } = await supabase.auth.getUser(token)
    if (error || !data.user) return res.status(401).json({ error: 'Authentication required.' })

    const user = data.user
    if (req.method === 'GET') {
      return res.status(200).json({ id: user.id, email: user.email, user_metadata: user.user_metadata })
    }

    const body = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : {}
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : undefined
    const metadata = body.metadata
    if (email !== undefined && (!email || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
      return res.status(400).json({ error: 'Invalid email address.' })
    }
    if (metadata !== undefined && (!isPlainRecord(metadata) || JSON.stringify(metadata).length > 8192)) {
      return res.status(400).json({ error: 'Invalid profile data.' })
    }
    // SECURITY (2026-10-21): user_metadata is read by the backend during provisioning
    // (tenant_name). Only harmless display fields may be written here, so a profile
    // update can never steer tenant resolution or any authorization decision.
    if (metadata !== undefined) {
      const ALLOWED_PROFILE_KEYS = new Set(['full_name', 'display_name', 'language', 'avatar_url'])
      const unknownKeys = Object.keys(metadata).filter((k) => !ALLOWED_PROFILE_KEYS.has(k))
      if (unknownKeys.length > 0) return res.status(400).json({ error: 'Invalid profile data.' })
      if (!Object.values(metadata).every((v) => typeof v === 'string' && v.length <= 512)) {
        return res.status(400).json({ error: 'Invalid profile data.' })
      }
    }
    if (email === undefined && metadata === undefined) return res.status(400).json({ error: 'No changes were submitted.' })

    if (email !== undefined) {
      const { error: updateError } = await supabase.auth.admin.updateUserById(user.id, { email })
      if (updateError) return res.status(400).json({ error: 'Unable to update account data.' })
    }
    if (metadata !== undefined) {
      const { error: metadataError } = await supabase.auth.admin.updateUserById(user.id, { user_metadata: metadata })
      if (metadataError) return res.status(400).json({ error: 'Unable to update account data.' })
    }
    return res.status(200).json({ message: 'User updated successfully', user: { id: user.id, email: email ?? user.email } })
  } catch (err) {
    console.error('User API request failed', err instanceof Error ? err.name : 'unknown')
    return safeServerError(res)
  }
}
