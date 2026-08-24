# 🚀 Vercel Deployment Guide - Security Gemini Monster

## سريع وسهل: 3 خطوات للـ Deployment

### الخطوة 1️⃣: نشر على GitHub

```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

### الخطوة 2️⃣: Deploy Frontend على Vercel

```bash
# Option A: Using Vercel CLI
npm i -g vercel
cd frontend
vercel

# Option B: GitHub Integration
# 1. Go to https://vercel.com
# 2. Import from GitHub
# 3. Select your repo
# 4. Root directory: ./frontend
# 5. Deploy!
```

### الخطوة 3️⃣: Add Environment Variables

في **Vercel Dashboard → Settings → Environment Variables**:

```
VITE_SUPABASE_URL = https://xxx.supabase.co
VITE_SUPABASE_ANON_KEY = xxx (public, safe)
VITE_API_BASE_URL = https://your-app.vercel.app
SUPABASE_SERVICE_ROLE_KEY = xxx (secret)
GEMINI_API_KEY = xxx (secret)
```

**Done! ✅ Your app is live!**

---

## 📚 ملفات الدليل الكامل:

| الملف | الوصف |
|------|-------|
| **DEPLOYMENT_COMPARISON.md** | مقارنة بين 3 خيارات نشر |
| **VERCEL_SETUP_OPTIONS.md** | شرح مفصّل لخيارات Vercel |
| **VERCEL_COMPLETE_SETUP.md** | دليل كامل خطوة بخطوة |
| **VERCEL_API_INTEGRATION.md** | كيفية ربط Frontend مع API Routes |
| **SECURITY_SETUP.md** | إدارة الـ Secrets بأمان |
| **CLOUD_DEPLOYMENT_OPTIONS.md** | خيارات النشر على السحابة |

---

## 🔐 قبل الـ Deployment:

### ✅ تأكد من:

```bash
# 1. .env في .gitignore
git check-ignore -v .env
# Output: .env

# 2. بدون secrets في code
git status
# يجب ألا تظهر أي API keys أو passwords

# 3. Push بدون secrets
git push origin main
# تحقق من GitHub - لا secrets مرئية!
```

---

## ⚙️ البنية بعد الـ Deployment:

```
https://your-app.vercel.app/
├─ /                      ← React Frontend
├─ /dashboard
├─ /admin
└─ /api/
   ├─ /api/auth          ← Login/Signup
   ├─ /api/user          ← User profile
   ├─ /api/health        ← Health check
   └─ /api/scans         ← (TODO) Scan management
```

---

## 🔍 اختبر API Endpoints:

```bash
# Health check
curl https://your-app.vercel.app/api/health

# Sign up
curl -X POST https://your-app.vercel.app/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "test123",
    "action": "signup"
  }'

# Login
curl -X POST https://your-app.vercel.app/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "test123",
    "action": "login"
  }'
```

---

## 📊 ماذا يعمل وماذا لا:

### ✅ يعمل على Vercel:

- ✅ React Frontend
- ✅ Lightweight API routes
- ✅ User authentication (Supabase)
- ✅ Database queries
- ✅ Static assets
- ✅ Real-time updates (Supabase)

### ❌ لا يعمل على Vercel:

- ❌ nmap network scanning (binary محتاج)
- ❌ Long-running jobs (timeout: 10-60 ثانية)
- ❌ Redis caching
- ❌ Worker processes
- ❌ WebSocket connections (استخدم Supabase realtime بدلاً)

---

## 🔗 للـ Heavy Operations:

إذا أردت نmap scanning أو heavy processing:

### Option A: GitHub Actions (مجاني)

```yaml
# .github/workflows/scan.yml
- name: Run nmap
  run: nmap -A ${{ inputs.target }} > results.txt
- name: Upload to Supabase
  run: # push results
```

### Option B: External API

استخدم:
- **Shodan** (IP scanning)
- **Burp Suite Cloud** (web scanning)
- **SecurityTrails** (DNS/certs)

### Option C: Backend منفصل

Deploy Backend على **Railway** أو **Render**:

```
Vercel Frontend ↔ Railway Backend
    ↓                   ↓
Static assets      nmap, workers
UI components      Redis, DB
```

[شرح مفصّل في DEPLOYMENT_COMPARISON.md]

---

## 🚨 الأخطاء الشائعة:

### ❌ Error: "SUPABASE_SERVICE_ROLE_KEY is not set"

**الحل:**
```
في Vercel Dashboard:
Settings → Environment Variables
أضف: SUPABASE_SERVICE_ROLE_KEY = xxx
```

### ❌ Error: "CORS error"

**الحل:**
```
تأكد من VITE_API_BASE_URL مطابق لـ domain:
- Local: http://localhost:3000
- Vercel: https://your-app.vercel.app
```

### ❌ Error: "timeout 10s exceeded"

**الحل:**
```
API routes في Vercel محدودة لـ 10s (free) أو 60s (pro).
للـ heavy tasks، استخدم:
- GitHub Actions
- External services
- Separate backend
```

---

## 📈 الخطوات التالية:

### بعد الـ Deployment الأول:

1. **أضف أكثر API routes:**
   ```
   /api/scans
   /api/findings
   /api/analysis
   /api/reports
   ```

2. **أضف Database migrations:**
   ```
   Supabase Dashboard → SQL Editor
   تشغيل migrations من: /supabase/migrations/
   ```

3. **Setup automated backups:**
   ```
   Supabase Dashboard → Backups
   ```

4. **Enable monitoring:**
   ```
   Vercel Dashboard → Analytics
   Supabase Dashboard → Logs
   ```

---

## 💡 نصائح:

### Local Development:

```bash
# Start dev server
cd frontend
npm run dev

# Test API routes locally
npx vercel dev
```

### Monitoring:

```
https://vercel.com → Deployments
https://app.supabase.com → Logs
```

### Debugging:

```bash
# View Vercel logs
vercel logs

# View Supabase logs
Supabase Dashboard → Logs
```

---

## ❓ الأسئلة الشائعة:

**Q: كيف أحدّث الـ code؟**
A: 
```bash
git push origin main
# Vercel auto-deploys automatically
```

**Q: كيف أغيّر environment variables؟**
A:
```
Vercel Dashboard → Settings → Environment Variables
غيّر القيمة
Redeploy (click Deploy button)
```

**Q: هل يمكنني استخدام الـ Backend القديم؟**
A: نعم، اقرأ DEPLOYMENT_COMPARISON.md للـ Option B (Vercel Frontend + Railway Backend)

**Q: كيف أتعامل مع الـ database؟**
A:
```
Supabase Dashboard → SQL Editor
أو استخدم Vercel SQL (PostgreSQL managed)
```

**Q: هل بإمكاني نشر Backend أيضاً؟**
A: نعم:
- Option A: Vercel Edge Functions (محدود)
- Option B: Railway/Render backend
- Option C: GitHub Actions webhooks

---

## 🎉 تم!

مشروعك الآن **live على Vercel!** 🚀

**Next:** اقرأ الملفات الأخرى لـ:
- ✅ Scalability
- ✅ Security hardening
- ✅ Performance optimization
- ✅ Adding more features

---

**الدعم:**
- Vercel Docs: https://vercel.com/docs
- Supabase Docs: https://supabase.com/docs
- GitHub Actions: https://docs.github.com/actions
