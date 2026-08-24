# 🚀 خيارات النشر على السحابة

## المشكلة:
**Vercel لا يدعم:**
- ❌ Python Backend (Uvicorn)
- ❌ Long-running processes (Worker)
- ❌ Redis instances
- ❌ Database management

## ✅ الحل الموصى به:

### **Option A: Frontend على Vercel + Backend على Railway** (الأفضل)

#### الخطوات:

**1. Frontend on Vercel:**
```bash
cd frontend
# Create vercel.json (already exists)
```

**2. Backend on Railway:**

```bash
# 1. Go to railway.app
# 2. Create new project
# 3. Click "Deploy from GitHub"
# 4. Select your repo
# 5. Select "Backend" folder in "Monorepo Path"
# 6. Add these services:
#    - PostgreSQL (or link to Supabase)
#    - Redis
#    - Backend container (uvicorn)
#    - Worker container (python worker)
```

**Environment Variables for Railway:**
```
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
REDIS_PASSWORD=strong_password
SCHEDULER_DATABASE_URL=postgresql://...
GEMINI_API_KEY=xxx
AUTH_JWT_SECRET=xxx
ENFORCE_TARGET_SCOPE=true
ALLOWED_TARGETS=yourdomain.com
CORS_ORIGINS=https://your-frontend.vercel.app
ENVIRONMENT=production
```

**Vercel Environment Variables:**
```
VITE_API_BASE_URL=https://your-backend.railway.app
VITE_SUPABASE_URL=https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY=xxx (safe to expose)
```

---

### **Option B: كل شيء على Railway** (بديل)

```
railway.app setup:
├── PostgreSQL
├── Redis
├── Backend service (uvicorn:8000)
├── Worker service (python -m app.worker)
└── Frontend (static build + Nginx)
```

**الفوائد:**
- ✅ كل شيء في مكان واحد
- ✅ سهل الإدارة
- ✅ توصيل سلس بين الخدمات

**العيوب:**
- ❌ أغلى من Vercel للـ Frontend فقط
- ❌ عنوان واحد (API و Frontend معاً)

---

### **Option C: Render.com** (بديل آخر)

```
render.com setup:
├── PostgreSQL Database
├── Redis Cache
├── Web Service (Backend - Uvicorn)
├── Background Worker (Worker process)
└── Static Site (Frontend)
```

**الخطوات:**
1. Go to render.com
2. Create new Web Service
3. Connect GitHub
4. Environment: Python 3.12
5. Build command: `pip install -r backend/requirements.txt`
6. Start command: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
7. Add PostgreSQL and Redis add-ons

---

### **Option D: Replit** (للتطوير السريع)

```
replit.com setup:
- Good for testing
- Limited for production
- Free tier available
```

---

## 📋 خطوات الدرس على Railway (الموصى بها):

### 1. إنشاء مستودع GitHub (✅ تم)
```bash
git push origin main
```

### 2. إنشاء حساب Railway
```
https://railway.app
Sign up with GitHub
```

### 3. إنشاء مشروع جديد
```
1. Dashboard → New Project
2. "Deploy from GitHub repo"
3. Select your repo
```

### 4. إضافة PostgreSQL
```
1. Click "Add Service" → "Database" → PostgreSQL
2. Railway ينشئ DATABASE_URL تلقائياً
```

### 5. إضافة Redis
```
1. Click "Add Service" → "Database" → Redis
2. Railway ينشئ REDIS_URL تلقائياً
```

### 6. إضافة Backend Service
```
1. Click "Add Service" → "GitHub Repo"
2. Select your backend folder
3. Runtime: Python 3.12
4. Build command: pip install -r backend/requirements.txt
5. Start command: uvicorn app.main:app --host 0.0.0.0 --port 8000
6. Port: 8000
```

### 7. إضافة Worker Service
```
1. Click "Add Service" → "GitHub Repo"
2. Select your backend folder
3. Runtime: Python 3.12
4. Build command: pip install -r backend/requirements.txt
5. Start command: python -m app.worker
6. Environment: Worker only (لا يحتاج port)
```

### 8. تعيين متغيرات البيئة
```
في Railway dashboard لكل service:

Backend:
  DATABASE_URL → (من PostgreSQL)
  REDIS_URL → (من Redis)
  SCHEDULER_DATABASE_URL → DATABASE_URL
  REDIS_PASSWORD → (من Redis)
  GEMINI_API_KEY → (أنتجها أولاً)
  AUTH_JWT_SECRET → openssl rand -base64 32
  ENFORCE_TARGET_SCOPE=true
  ALLOWED_TARGETS=localhost,your-domain.com
  CORS_ORIGINS=https://your-vercel-app.vercel.app
  ENVIRONMENT=production

Worker:
  (نفس البيانات مثل Backend)
  WORKER_MODE=true
```

### 9. Deploy Frontend على Vercel
```
1. https://vercel.com → New Project
2. Import your GitHub repo
3. Framework: Vite (React)
4. Root Directory: ./frontend
5. Environment Variables:
   VITE_API_BASE_URL=https://your-backend.railway.app
   VITE_SUPABASE_URL=https://xxx.supabase.co
   VITE_SUPABASE_ANON_KEY=xxx
6. Deploy!
```

---

## 🔐 أمان الـ Secrets

**في Railway:**
- لا تضع secrets في code
- استخدم Railway "Environment" tab
- يتم التشفير تلقائياً

**في Vercel:**
- استخدم "Environment Variables" tab
- `VITE_*` متغيرات تُرى في Frontend (آمنة = public data فقط)
- لا تضع API keys سرية في `VITE_*`

**في GitHub:**
- لا تضع `.env` في المستودع
- استخدم `.env.example` بدون قيم
- استخدم GitHub Secrets للـ CI/CD

---

## ✅ Checklist قبل الإطلاق

- [ ] دوّر كل الـ API keys والـ passwords
- [ ] تأكد أن `.env` في `.gitignore`
- [ ] اختبر CORS مع domain الـ Frontend
- [ ] اختبر الـ authentication flow
- [ ] اختبر الـ Worker processing (continuous scans)
- [ ] Set up monitoring/logs
- [ ] اختبر backup strategy
- [ ] Enable HTTPS everywhere

---

## التكاليف المتوقعة:

**Vercel (Frontend):**
- Free tier: ≤50GB bandwidth/month ✅
- Pro: $20/month

**Railway (Backend):**
- Free tier: $5 credit/month (قد لا يكفي)
- Pay as you go: ~$10-50/month

**Supabase (Database):**
- Free tier: ≤500MB ✅
- Pro: $25/month

**Total: ~$10-50/month** (if using free tiers)

---

## الخطوة التالية:

```bash
# 1. Go to https://railway.app
# 2. Create account
# 3. Connect GitHub
# 4. Deploy!
```

Let me know if you need help with any specific step! 🚀
