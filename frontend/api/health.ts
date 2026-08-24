import { VercelRequest, VercelResponse } from '@vercel/node'

/**
 * Health check endpoint
 * GET /api/health
 */

function setCors(res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,OPTIONS,PATCH,DELETE,POST,PUT'
  )
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  )
}

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  setCors(res)

  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  try {
    const supabaseUrl = process.env.VITE_SUPABASE_URL

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      services: {
        supabase: supabaseUrl ? '✅ configured' : '❌ not configured',
        gemini:
          process.env.GEMINI_API_KEY ? '✅ configured' : '❌ not configured',
      },
    }

    res.status(200).json(health)
  } catch (err: any) {
    res.status(500).json({
      status: 'unhealthy',
      error: err.message,
    })
  }
}
