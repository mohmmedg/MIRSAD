import type { VercelRequest, VercelResponse } from '@vercel/node'
import { handleOptions, safeServerError, setSecureCors } from './_security'

export default async function handler(req: VercelRequest, res: VercelResponse) {
  setSecureCors(req, res)
  if (handleOptions(req, res)) return
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' })
  try {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: 'production',
      services: { supabase: process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL ? 'configured' : 'not_configured', gemini: process.env.GEMINI_API_KEY ? 'configured' : 'not_configured' },
    })
  } catch {
    return safeServerError(res)
  }
}
