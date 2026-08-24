# 🔗 كيف تربط Frontend مع Vercel API Routes

## المعمارية:

```
Frontend (React)
    ↓
Vercel API Routes (/api/*)
    ↓
Supabase (Database + Auth)
```

---

## الخطوة 1: تثبيت Dependencies

```bash
cd frontend

# Vercel serverless functions
npm install @vercel/node

# Supabase
npm install @supabase/supabase-js
```

---

## الخطوة 2: بنية المجلدات

```
frontend/
├── api/                      ← Vercel API routes
│   ├── _middleware.ts       ← CORS handling
│   ├── auth.ts              ← Authentication endpoints
│   ├── user.ts              ← User management
│   ├── health.ts            ← Health check
│   └── scans.ts             ← Scan management (TODO)
│
├── src/
│   ├── api/
│   │   └── client.ts        ← API client للـ frontend
│   ├── auth/
│   │   └── AuthGate.tsx
│   └── components/
│
├── vercel.json              ← Vercel configuration
├── package.json
└── vite.config.ts
```

---

## الخطوة 3: Frontend API Client

### `src/api/client.ts`

```typescript
// Base URL of your API (from environment)
const API_BASE_URL =
  process.env.VITE_API_BASE_URL || 'http://localhost:3000'

export const apiClient = {
  // Authentication
  signup: async (email: string, password: string) => {
    const response = await fetch(`${API_BASE_URL}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, action: 'signup' }),
    })
    return response.json()
  },

  login: async (email: string, password: string) => {
    const response = await fetch(`${API_BASE_URL}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, action: 'login' }),
    })
    return response.json()
  },

  logout: async () => {
    const token = localStorage.getItem('token')
    const response = await fetch(`${API_BASE_URL}/api/auth`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ action: 'logout' }),
    })
    return response.json()
  },

  // User
  getUser: async (token: string) => {
    const response = await fetch(`${API_BASE_URL}/api/user`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.json()
  },

  updateUser: async (token: string, data: any) => {
    const response = await fetch(`${API_BASE_URL}/api/user`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(data),
    })
    return response.json()
  },

  // Health check
  health: async () => {
    const response = await fetch(`${API_BASE_URL}/api/health`)
    return response.json()
  },
}
```

---

## الخطوة 4: استخدام API Client في Components

### `src/components/LoginForm.tsx`

```typescript
import { useState } from 'react'
import { apiClient } from '../api/client'

export function LoginForm() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const result = await apiClient.login(email, password)

      if (result.error) {
        setError(result.error)
        return
      }

      // حفظ الـ token
      localStorage.setItem('token', result.session.access_token)
      localStorage.setItem('refresh_token', result.session.refresh_token)

      // Redirect
      window.location.href = '/'
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleLogin}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button type="submit" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </form>
  )
}
```

---

## الخطوة 5: Environment Variables

### `frontend/.env`

```bash
# Local development
VITE_SUPABASE_URL=https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY=xxx
VITE_API_BASE_URL=http://localhost:3000
```

### في Vercel Dashboard:

```
Settings → Environment Variables

VITE_SUPABASE_URL = https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY = xxx (public)
VITE_API_BASE_URL = https://your-app.vercel.app
SUPABASE_SERVICE_ROLE_KEY = xxx (secret, server only)
```

---

## الخطوة 6: Deployment

### Local Testing:

```bash
# Terminal 1: Frontend dev server
cd frontend
npm run dev
# Open http://localhost:3000

# Terminal 2: Vercel dev environment
npx vercel dev
# API routes will be available at http://localhost:3000/api/*
```

### Deploy to Vercel:

```bash
# Option 1: Using Vercel CLI
vercel

# Option 2: GitHub integration
# 1. git push to GitHub
# 2. Vercel auto-deploys on every push
# 3. Add environment variables in Vercel dashboard
```

---

## الخطوة 7: Testing API Endpoints

### Health Check:

```bash
curl https://your-app.vercel.app/api/health
```

### Sign Up:

```bash
curl -X POST https://your-app.vercel.app/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "action": "signup"
  }'
```

### Login:

```bash
curl -X POST https://your-app.vercel.app/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "action": "login"
  }'
```

### Get User:

```bash
curl https://your-app.vercel.app/api/user \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## الخطوة 8: Handling Heavy Operations

**المشكلة:**
Vercel functions محدودة لـ 10-60 ثانية. إذا أردت nmap scanning أو heavy processing:

### الحل 1: External Webhook (GitHub Actions)

```typescript
// في api/scans.ts
if (req.method === 'POST') {
  const { target, scanId } = req.body

  // 1. حفظ الـ scan في Supabase
  await supabase.from('scans').insert({
    id: scanId,
    target,
    status: 'pending',
  })

  // 2. Trigger GitHub Action
  const response = await fetch(
    'https://api.github.com/repos/YOUR_USER/YOUR_REPO/dispatches',
    {
      method: 'POST',
      headers: {
        Authorization: `token ${process.env.GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event_type: 'start-scan',
        client_payload: { scan_id: scanId, target },
      }),
    }
  )

  // 3. Return immediately
  return res.status(202).json({ scanId, status: 'pending' })
}
```

### الحل 2: External API (Shodan, Burp, etc.)

```typescript
// في api/scans.ts
if (req.method === 'POST') {
  const { target } = req.body

  // Call external scanning service
  const scanResult = await fetch('https://api.shodan.io/shodan/host/search', {
    headers: {
      Authorization: `Bearer ${process.env.SHODAN_API_KEY}`,
    },
  })

  const data = await scanResult.json()

  // حفظ النتائج
  await supabase.from('scan_results').insert({
    target,
    results: data,
  })

  return res.status(200).json({ results: data })
}
```

---

## Checklist:

- [ ] تثبيت dependencies (@vercel/node, @supabase/supabase-js)
- [ ] إنشاء مجلد `/api`
- [ ] كتابة API routes (auth, user, health, etc.)
- [ ] إنشاء API client في Frontend
- [ ] استخدام API client في Components
- [ ] تعيين environment variables
- [ ] اختبار محلياً مع `vercel dev`
- [ ] Deploy على Vercel
- [ ] إضافة environment variables في dashboard
- [ ] اختبار API endpoints مع curl

---

## الخطوة التالية:

اختر واحد:

- [ ] هل تريد مثال كامل لـ `/api/scans`؟
- [ ] هل تحتاج توضيح حول Real-time updates؟
- [ ] كيف تتعامل مع الـ long-running tasks؟
- [ ] نعم، أنا جاهز للـ Deployment! 🚀
