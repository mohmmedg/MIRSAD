import type { VercelRequest, VercelResponse } from '@vercel/node'
import { handleOptions, setSecureCors } from './_security'

export default function handler(req: VercelRequest, res: VercelResponse) {
  setSecureCors(req, res)
  if (handleOptions(req, res)) return
  if (req.method === 'GET' && !req.query.endpoint) {
    return res.status(200).json({ status: 'ok', message: 'API is running', version: '1.0.0' })
  }
  return res.status(405).json({ error: 'Method not allowed' })
}
