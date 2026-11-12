import type { VercelRequest, VercelResponse } from '@vercel/node'

const DEFAULT_ALLOWED_ORIGINS = new Set([
  'http://localhost:5173',
  'http://127.0.0.1:5173',
])

export function setSecureCors(req: VercelRequest, res: VercelResponse): void {
  const configured = (process.env.FRONTEND_ORIGIN || '').split(',').map((v) => v.trim()).filter(Boolean)
  const allowed = new Set([...DEFAULT_ALLOWED_ORIGINS, ...configured])
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin : ''

  if (origin && allowed.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Vary', 'Origin')
    res.setHeader('Access-Control-Allow-Credentials', 'true')
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST,PUT,PATCH,DELETE')
  res.setHeader('Access-Control-Allow-Headers', 'Accept, Content-Type, Authorization, X-Requested-With, X-CSRF-Token, X-API-Key')
  res.setHeader('Access-Control-Max-Age', '600')
}

export function handleOptions(req: VercelRequest, res: VercelResponse): boolean {
  if (req.method !== 'OPTIONS') return false
  res.status(204).end()
  return true
}

export function safeServerError(res: VercelResponse, status = 500, message = 'The request could not be completed.'): void {
  res.status(status).json({ error: message })
}

export function isValidEmail(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
}

export function isValidPassword(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 12 && value.length <= 4096 && !/[\u0000-\u001F\u007F]/.test(value)
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}
