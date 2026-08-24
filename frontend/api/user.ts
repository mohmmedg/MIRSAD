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
    // استخراج الـ token من Authorization header
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid token' })
    }

    const token = authHeader.slice(7)

    // التحقق من الـ token من Supabase
    const { data, error } = await supabase.auth.getUser(token)

    if (error || !data.user) {
      return res.status(401).json({ error: 'Invalid token' })
    }

    const user = data.user

    if (req.method === 'GET') {
      // GET /api/user - استرجاع بيانات المستخدم
      return res.status(200).json({
        id: user.id,
        email: user.email,
        user_metadata: user.user_metadata,
      })
    }

    if (req.method === 'PUT') {
      // PUT /api/user - تحديث بيانات المستخدم
      const { email, metadata } = req.body

      if (email) {
        const { error: updateError } = await supabase.auth.admin.updateUserById(
          user.id,
          { email }
        )
        if (updateError) throw updateError
      }

      if (metadata) {
        const { error: metadataError } =
          await supabase.auth.admin.updateUserById(user.id, {
            user_metadata: metadata,
          })
        if (metadataError) throw metadataError
      }

      return res.status(200).json({
        message: 'User updated successfully',
        user: { id: user.id, email },
      })
    }

    res.status(405).json({ error: 'Method not allowed' })
  } catch (err: any) {
    console.error('Error:', err)
    res.status(500).json({ error: err.message })
  }
}
