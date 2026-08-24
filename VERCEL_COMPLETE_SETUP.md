# ⚡ Setup Vercel للمشروع

## مسار الحركة الموضحة:

```
1. نسخ Frontend فقط إلى Vercel
2. إنشاء Vercel API Routes (لـ lightweight endpoints)
3. ربط Supabase كـ Database
4. ربط Gemini API
5. متغيرات البيئة تُضاف من Vercel Dashboard
```

---

## المرحلة 1: إعداد الـ Frontend

### 1.1 تحديث `vercel.json`

```json
{
  "buildCommand": "npm ci && npm run build",
  "devCommand": "npm run dev",
  "installCommand": "npm ci",
  "outputDirectory": "./dist",
  "env": [
    "VITE_SUPABASE_URL",
    "VITE_SUPABASE_ANON_KEY",
    "VITE_API_BASE_URL"
  ]
}
```

### 1.2 تحديث `frontend/.env.example`

```bash
# Build-time variables (Vite)
VITE_SUPABASE_URL=https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY=xxx
VITE_API_BASE_URL=http://localhost:3000/api  # أو https://your-app.vercel.app/api
```

### 1.3 في `frontend/vite.config.ts`

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '/api'),
      }
    }
  }
})
```

---

## المرحلة 2: إنشاء API Routes

### 2.1 إنشاء مجلد `/api`

```
frontend/
├── api/
│   ├── auth.ts
│   ├── scans.ts
│   ├── findings.ts
│   ├── analysis.ts
│   └── _lib/
│       ├── supabase.ts
│       ├── auth.ts
│       └── cors.ts
```

### 2.2 `api/_lib/supabase.ts`

```typescript
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.VITE_SUPABASE_URL!
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!

export const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    persistSession: false,
  },
})
```

### 2.3 `api/_lib/cors.ts`

```typescript
import { VercelRequest, VercelResponse } from '@vercel/node'

export function corsHeaders(res: VercelResponse) {
  const origin = process.env.VITE_API_BASE_URL || 'http://localhost:3000'
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,OPTIONS,PATCH,DELETE,POST,PUT'
  )
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  )
}

export function handleCors(req: VercelRequest, res: VercelResponse) {
  corsHeaders(res)
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return true
  }
  return false
}
```

### 2.4 `api/auth.ts` - مثال

```typescript
import { VercelRequest, VercelResponse } from '@vercel/node'
import { handleCors } from './_lib/cors'
import { supabase } from './_lib/supabase'

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (handleCors(req, res)) return

  // POST /api/auth
  if (req.method === 'POST') {
    const { email, password, action } = req.body

    try {
      if (action === 'signup') {
        const { data, error } = await supabase.auth.admin.createUser({
          email,
          password,
          email_confirm: true,
        })
        if (error) throw error
        return res.status(200).json({ user: data.user })
      }

      if (action === 'login') {
        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        })
        if (error) throw error
        return res.status(200).json({ session: data.session })
      }

      return res.status(400).json({ error: 'Invalid action' })
    } catch (err: any) {
      return res.status(400).json({ error: err.message })
    }
  }

  return res.status(405).json({ error: 'Method not allowed' })
}
```

### 2.5 `api/scans.ts` - مثال

```typescript
import { VercelRequest, VercelResponse } from '@vercel/node'
import { handleCors } from './_lib/cors'
import { supabase } from './_lib/supabase'

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (handleCors(req, res)) return

  const authHeader = req.headers.authorization
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const token = authHeader.split(' ')[1]

  try {
    // التحقق من الـ token
    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser(token)
    if (authError) throw authError

    if (req.method === 'GET') {
      // استرجاع الـ scans من Supabase
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', user.id)

      if (error) throw error
      return res.status(200).json({ scans: data })
    }

    if (req.method === 'POST') {
      // بدء scan جديد
      const { target, scan_type } = req.body

      // ✅ الحل: استخدم external scanning service
      // مثل: Shodan API, HackerOne API, أو scheduled GitHub Action

      const { data, error } = await supabase.from('scans').insert({
        user_id: user.id,
        target,
        scan_type,
        status: 'pending',
        created_at: new Date(),
      })

      if (error) throw error

      // TODO: trigger GitHub Action أو external service
      // Webhook to GitHub Actions:
      // await fetch('https://api.github.com/repos/you/repo/dispatches', {
      //   method: 'POST',
      //   headers: {
      //     Authorization: `token ${process.env.GITHUB_TOKEN}`,
      //     'Content-Type': 'application/json',
      //   },
      //   body: JSON.stringify({
      //     event_type: 'start-scan',
      //     client_payload: { scan_id: data[0].id, target },
      //   }),
      // })

      return res.status(201).json({ scan: data[0] })
    }

    return res.status(405).json({ error: 'Method not allowed' })
  } catch (err: any) {
    return res.status(400).json({ error: err.message })
  }
}
```

---

## المرحلة 3: متغيرات البيئة في Vercel

### في Vercel Dashboard:

```
Settings → Environment Variables

VITE_SUPABASE_URL = https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY = xxx (public)
VITE_API_BASE_URL = https://your-app.vercel.app
SUPABASE_SERVICE_ROLE_KEY = xxx (secret - server only)
GEMINI_API_KEY = xxx (secret)
GITHUB_TOKEN = xxx (للـ GitHub Actions)
```

---

## المرحلة 4: Deployment

### في Terminal:

```bash
# 1. تثبيت Vercel CLI
npm i -g vercel

# 2. Login
vercel login

# 3. Deploy
cd frontend
vercel

# 4. أتبع التعليمات:
#    - Link to existing project؟ Yes/No
#    - Framework preset? Vite
#    - Root directory? . (current)
#    - Override build settings? No
#    - Deploy! ✅
```

### أو من GitHub:

```
1. https://vercel.com
2. "New Project"
3. Import from GitHub
4. Select repository
5. Root Directory: ./frontend
6. Environment Variables: (add من dashboard)
7. Deploy! ✅
```

---

## المرحلة 5: Heavy Operations (Scans)

### الخيارات للـ Scanning:

#### **Option A: GitHub Actions (مجاني)**

```yaml
# .github/workflows/run-scan.yml
name: Run Security Scan

on:
  workflow_dispatch:
    inputs:
      target:
        required: true
      scan_id:
        required: true

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run nmap
        run: |
          nmap -A ${{ github.event.inputs.target }} > results.txt
      
      - name: Upload results to Supabase
        run: |
          # Push results to Supabase via API
          curl -X POST https://xxx.supabase.co/rest/v1/scan_results \
            -H "Authorization: Bearer ${{ secrets.SUPABASE_KEY }}" \
            -d '{"scan_id": "${{ github.event.inputs.scan_id }}", ...}'
```

#### **Option B: External Services**

- Shodan API (IP scanning)
- HackerOne API (vulnerability scanning)
- Burp Suite API (web scanning)
- SecurityTrails API (DNS/certificate scanning)

#### **Option C: Scheduled Cloud Function**

- Google Cloud Functions (مع scheduler)
- AWS Lambda (مع EventBridge)
- Vercel Crons (إذا كنت على Pro)

---

## التحذيرات:

⚠️ **مشاكل:**
1. Vercel Functions محدودة لـ 10-60 ثانية
2. nmap لا يعمل على Vercel serverless
3. بدون persistent workers للـ queue
4. بدون Redis في Vercel

✅ **الحلول:**
1. استخدم external scanning APIs
2. GitHub Actions لـ heavy tasks
3. Supabase لتخزين النتائج
4. Polling أو WebSocket للـ real-time updates

---

## الخطوة التالية:

اختر:
- [ ] **Option A**: نعم، أنشر على Vercel فقط (بدون heavy scanning)
- [ ] **Option B**: أنشر Frontend على Vercel + Backend على Railway (أفضل)
- [ ] **Option C**: نعم، استخدم GitHub Actions للـ scans

أي خيار تفضل؟ 🚀
