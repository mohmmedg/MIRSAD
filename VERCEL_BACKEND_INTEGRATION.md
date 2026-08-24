# 🔀 ربط Vercel Frontend مع Backend الحالي

## المشكلة:

المشروع لديه Backend كامل (FastAPI, nmap, worker, Redis) لا يمكنه العمل على Vercel.

**الحلول:**

---

## ✅ الحل الأفضل: Vercel Frontend + Railway Backend

### المعمارية:

```
┌─────────────────────────────────────────┐
│      Vercel (Frontend)                 │
│  https://your-app.vercel.app          │
│                                         │
│  ├─ React UI                           │
│  ├─ Static assets                      │
│  └─ API calls to backend               │
└─────────────────────────────────────────┘
              ↓ (HTTP)
┌─────────────────────────────────────────┐
│      Railway (Backend)                  │
│  https://your-api.railway.app         │
│                                         │
│  ├─ FastAPI (Uvicorn)                 │
│  ├─ nmap scanner                       │
│  ├─ Worker process                     │
│  ├─ Redis queue                        │
│  ├─ PostgreSQL database                │
│  └─ Gemini integration                 │
└─────────────────────────────────────────┘
```

---

## الخطوات:

### 1️⃣ Deploy Frontend على Vercel

```bash
# من Vercel Dashboard:
# 1. New Project
# 2. Import from GitHub
# 3. Root Directory: ./frontend
# 4. Environment Variables:
#    - VITE_API_BASE_URL=https://your-api.railway.app
#    - VITE_SUPABASE_URL=xxx
#    - VITE_SUPABASE_ANON_KEY=xxx
```

### 2️⃣ Deploy Backend على Railway

```bash
# من Railway Dashboard:
# 1. New Project
# 2. Deploy from GitHub repo
# 3. Add services:
#    - PostgreSQL
#    - Redis
#    - Python runtime (Backend)
#    - Python runtime (Worker)

# Environment Variables:
DATABASE_URL=(من PostgreSQL)
REDIS_URL=(من Redis)
REDIS_PASSWORD=strong_password
SCHEDULER_DATABASE_URL=DATABASE_URL
GEMINI_API_KEY=xxx
AUTH_JWT_SECRET=xxx
ENFORCE_TARGET_SCOPE=true
ALLOWED_TARGETS=your-domain.com
CORS_ORIGINS=https://your-app.vercel.app
ENVIRONMENT=production
```

### 3️⃣ تحديث Frontend للـربط مع Backend

#### في `frontend/src/api/client.ts`:

```typescript
const API_BASE_URL = process.env.VITE_API_BASE_URL || 'http://localhost:8000'

export const apiClient = {
  // Scans
  startScan: async (token: string, target: string, scanType: string) => {
    const response = await fetch(`${API_BASE_URL}/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ target, scan_type: scanType }),
    })
    return response.json()
  },

  getScans: async (token: string) => {
    const response = await fetch(`${API_BASE_URL}/scans`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.json()
  },

  getScanResults: async (token: string, scanId: string) => {
    const response = await fetch(`${API_BASE_URL}/scans/${scanId}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.json()
  },

  // Findings
  getFindings: async (token: string) => {
    const response = await fetch(`${API_BASE_URL}/findings`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.json()
  },

  // Analysis
  analyzeFindings: async (token: string, findingIds: string[]) => {
    const response = await fetch(`${API_BASE_URL}/analysis`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ finding_ids: findingIds }),
    })
    return response.json()
  },
}
```

### 4️⃣ تحديث Frontend Environment

#### `frontend/.env` (local):

```bash
VITE_API_BASE_URL=http://localhost:8000
VITE_SUPABASE_URL=https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY=xxx
```

#### في Vercel Dashboard:

```
VITE_API_BASE_URL=https://your-api.railway.app
VITE_SUPABASE_URL=https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY=xxx
SUPABASE_SERVICE_ROLE_KEY=xxx (optional, only for API routes)
```

---

## 🔌 CORS Configuration

### في Backend (`backend/app/main.py`):

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')
    ],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)
```

### في Production (Railway):

```
CORS_ORIGINS=https://your-app.vercel.app,https://your-domain.com
```

---

## ✅ الفوائد:

| الميزة | التفصيل |
|--------|---------|
| **Frontend Hosting** | ✅ Vercel (Fast, Free) |
| **Backend Hosting** | ✅ Railway (Scalable) |
| **Database** | ✅ PostgreSQL على Railway |
| **Cache** | ✅ Redis على Railway |
| **nmap scanning** | ✅ يعمل على Railway |
| **Workers** | ✅ Long-running processes |
| **No Timeout** | ✅ طول ما تريد |
| **Cost** | ✅ ~$20-30/month |
| **Performance** | ✅ ممتاز |

---

## 🚀 Deployment Checklist:

- [ ] تأكد من بدون secrets في code
- [ ] Deploy Frontend على Vercel
- [ ] Deploy Backend على Railway
- [ ] اختبر CORS:
  ```bash
  curl -H "Origin: https://your-app.vercel.app" \
       -v https://your-api.railway.app/health
  ```
- [ ] اختبر API:
  ```bash
  curl https://your-api.railway.app/scans
  ```
- [ ] اختبر من Frontend
- [ ] Setup monitoring
- [ ] Enable backups

---

## 🔄 Continuous Updates:

### عندما تغيّر الـ code:

**Frontend:**
```bash
git push origin main
# Vercel auto-deploys
```

**Backend:**
```bash
git push origin main
# Railway auto-deploys (if configured)
```

---

## 📊 Monitoring & Logs:

### Vercel:
```
Dashboard → Deployments → Logs
```

### Railway:
```
Dashboard → Services → Logs
```

### Database:
```
Railway → PostgreSQL → Logs
```

---

## 🐛 Debugging:

### إذا اتصال Frontend بـ Backend فشل:

```bash
# 1. تأكد من Backend يعمل:
curl https://your-api.railway.app/health

# 2. تأكد من CORS:
curl -H "Origin: https://your-app.vercel.app" \
     -H "Access-Control-Request-Method: GET" \
     https://your-api.railway.app/health

# 3. تأكد من token صحيح:
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://your-api.railway.app/scans

# 4. شوف Frontend logs:
Browser DevTools → Console
```

---

## 💰 التكلفة:

| Service | Cost |
|---------|------|
| **Vercel** | Free (~$0) |
| **Railway** | ~$20/month (4GB RAM, 1 CPU) |
| **Supabase** | Free/~$25/month |
| **Total** | ~$20-50/month |

---

## ⚡ Performance Tips:

1. **استخدم CDN:**
   - Vercel يستخدم Cloudflare (مدمج)
   - Railway region يجب أن يكون قريب من users

2. **Caching:**
   - Frontend: Static assets على Vercel
   - Backend: Redis على Railway

3. **Database:**
   - أنشئ indexes على الجداول الكبيرة
   - استخدم connection pooling

4. **Monitoring:**
   - Setup alerts للـ errors
   - Track response times

---

## الخطوة التالية:

1. Deploy Frontend على Vercel ✅
2. Deploy Backend على Railway ✅
3. Test CORS ✅
4. Update Frontend API client ✅
5. Go live! 🚀

---

**تحتاج مساعدة في خطوة معينة؟** اسأل! 🎯
