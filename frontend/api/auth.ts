import { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.VITE_SUPABASE_URL!
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY!

const supabase = createClient(supabaseUrl, supabaseKey)

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

  try {
    const { email, password, action } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }

    if (req.method === 'POST') {
      if (action === 'signup') {
        // إنشاء مستخدم جديد
        const { data, error } = await supabase.auth.admin.createUser({
          email,
          password,
          email_confirm: true,
        })

        if (error) {
          return res.status(400).json({ error: error.message })
        }

        return res.status(201).json({
          message: 'User created successfully',
          user: { id: data.user.id, email: data.user.email },
        })
      }

      if (action === 'login') {
        // تسجيل الدخول
        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        })

        if (error) {
          return res.status(401).json({ error: error.message })
        }

        return res.status(200).json({
          message: 'Login successful',
          session: {
            access_token: data.session?.access_token,
            refresh_token: data.session?.refresh_token,
            user: {
              id: data.user.id,
              email: data.user.email,
            },
          },
        })
      }

      if (action === 'logout') {
        // تسجيل الخروج
        const { error } = await supabase.auth.signOut()

        if (error) {
          return res.status(400).json({ error: error.message })
        }

        return res.status(200).json({ message: 'Logout successful' })
      }

      return res.status(400).json({ error: 'Invalid action' })
    }

    res.status(405).json({ error: 'Method not allowed' })
  } catch (err: any) {
    console.error('Auth error:', err)
    res.status(500).json({ error: err.message })
  }
}
