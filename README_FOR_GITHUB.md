# 🔐 Security Gemini Monster - AI Security Scanner

**الوصف:** منصة أمان شاملة بقوة الذكاء الاصطناعي (Gemini) لفحص الثغرات الأمنية والتحليل الذكي.

---

## 📚 الوثائق السريعة:

### 🚀 للبدء الفوري:
- ⭐ **[QUICK_START_NOW.md](QUICK_START_NOW.md)** - ابدأ الآن! (الأسهل)
- ⭐ **[README_DEPLOYMENT.md](README_DEPLOYMENT.md)** - ملخص شامل

### 📖 للنشر على Vercel:
- **[DEPLOYMENT_INDEX.md](DEPLOYMENT_INDEX.md)** - جدول محتويات الدليل
- **[VERCEL_QUICK_START.md](VERCEL_QUICK_START.md)** - 3 خطوات للنشر
- **[VERCEL_COMPLETE_SETUP.md](VERCEL_COMPLETE_SETUP.md)** - دليل مفصّل
- **[VERCEL_API_INTEGRATION.md](VERCEL_API_INTEGRATION.md)** - ربط Frontend مع API

### 🔗 للربط مع Backend:
- **[VERCEL_BACKEND_INTEGRATION.md](VERCEL_BACKEND_INTEGRATION.md)** - الربط مع Railway

### 🔐 للأمان:
- **[SECURITY_SETUP.md](SECURITY_SETUP.md)** - إدارة الـ Secrets

---

## 🎯 الخيارات المتاحة:

### **Option A: Vercel فقط** ⚡
- **المدة:** ~1 ساعة
- **التكلفة:** مجاني (~$0-10/month)
- **المميزات:** سهل، سريع، auto-scaling
- **العيوب:** بدون nmap scanning، timeout 10-60s
- **اقرأ:** `VERCEL_QUICK_START.md`

### **Option B: Vercel + Railway** ⭐ الأفضل
- **المدة:** ~2-3 ساعات
- **التكلفة:** ~$20-30/month
- **المميزات:** كل الـ features، nmap، workers
- **العيوب:** أغلى، أكثر تعقيد
- **اقرأ:** `VERCEL_BACKEND_INTEGRATION.md`

---

## 🏗️ المعمارية:

```
Option A (Vercel):
┌──────────────────────┐
│  Vercel              │
│  ├─ React Frontend   │
│  ├─ API Routes       │
│  └─ Static assets    │
└──────────────────────┘
         ↓
    ┌─────────────┐
    │  Supabase   │
    │  Database   │
    └─────────────┘

Option B (Vercel + Railway):
┌──────────────────────┐         ┌──────────────────────┐
│  Vercel (Frontend)   │         │  Railway (Backend)   │
│  ├─ React UI         │────────→│  ├─ FastAPI         │
│  └─ Static assets    │         │  ├─ nmap scanner    │
└──────────────────────┘         │  ├─ Workers         │
                                 │  ├─ Redis           │
                                 │  └─ PostgreSQL      │
                                 └──────────────────────┘
```

---

## ✨ الميزات:

### 🔍 الفحص الأمني:
- Network scanning (nmap)
- Web vulnerability scanning
- API security testing
- Certificate validation
- DNS analysis

### 🤖 الذكاء الاصطناعي:
- Gemini AI analysis
- Intelligent findings correlation
- Remediation suggestions
- False positive filtering

### 🔐 الأمان:
- Multi-tenant isolation
- Role-based access control
- API key management
- Audit logging
- Session enforcement

### 📊 التقارير:
- HTML reports
- PDF exports
- CSV data export
- Risk scoring
- Compliance mapping

---

## 🚀 البدء السريع:

### الخطوة 1: Clone أو Download

```bash
git clone https://github.com/YOUR_USERNAME/security-gemini-monster.git
cd security-gemini-monster
```

### الخطوة 2: اختر مسارك

```bash
# اقرأ أحد الملفات:
cat DEPLOYMENT_INDEX.md    # اختر مسارك
cat QUICK_START_NOW.md     # أو ابدأ الآن!
```

### الخطوة 3: اتبع الدليل

**Option A (Vercel):**
```bash
cd frontend
npm install
vercel
```

**Option B (Vercel + Railway):**
```bash
# Frontend على Vercel
cd frontend && vercel

# Backend على Railway
# (راجع VERCEL_BACKEND_INTEGRATION.md)
```

---

## 📋 المتطلبات:

### Local Development:
- Node.js 18+
- npm/yarn/pnpm
- Python 3.12+ (للـ backend فقط)
- Docker (اختياري)

### Deployment:
- GitHub account
- Vercel account (مجاني)
- Supabase account (مجاني)
- Railway account (اختياري، للـ Option B)

---

## 📁 البنية:

```
.
├── frontend/                    ← React app + Vercel API routes
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── api/               ← Vercel serverless functions
│   ├── package.json
│   └── vercel.json
│
├── backend/                    ← FastAPI (Optional for Option B)
│   ├── app/
│   │   ├── api/
│   │   ├── modules/
│   │   ├── core/
│   │   └── main.py
│   └── requirements.txt
│
├── supabase/                   ← Database migrations
│   └── migrations/
│
└── Docs/                       ← Documentation
    ├── README_DEPLOYMENT.md
    ├── QUICK_START_NOW.md
    ├── VERCEL_QUICK_START.md
    └── ...
```

---

## 🔐 الأمان:

- ✅ لا API keys في الكود
- ✅ Secrets في environment variables
- ✅ تشفير الاتصالات (HTTPS)
- ✅ Authentication مع Supabase
- ✅ Audit logging شامل

**ملاحظة:** تأكد من تدوير كل الـ secrets قبل الـ production!

---

## 📈 الأداء:

- **Frontend:** Vercel CDN (ملي ثانية)
- **API:** Serverless functions (بدون cold starts طويلة)
- **Database:** Supabase managed PostgreSQL
- **Cache:** Redis (إذا Option B)

---

## 🔗 الروابط المهمة:

| الموضوع | الرابط |
|--------|--------|
| ابدأ الآن | [QUICK_START_NOW.md](QUICK_START_NOW.md) |
| دليل الـ Deployment | [DEPLOYMENT_INDEX.md](DEPLOYMENT_INDEX.md) |
| مقارنة الخيارات | [DEPLOYMENT_COMPARISON.md](DEPLOYMENT_COMPARISON.md) |
| أمان الـ Secrets | [SECURITY_SETUP.md](SECURITY_SETUP.md) |
| Vercel Setup | [VERCEL_QUICK_START.md](VERCEL_QUICK_START.md) |
| Backend Integration | [VERCEL_BACKEND_INTEGRATION.md](VERCEL_BACKEND_INTEGRATION.md) |

---

## 📊 الخطوات الموصى بها:

```
1. اقرأ: README.md (أنت هنا!)
2. اقرأ: QUICK_START_NOW.md
3. اختر: Option A أو B
4. اتبع: الدليل المناسب
5. Deploy: في البيئة المختارة
6. اختبر: من المتصفح
7. Go live! 🎉
```

---

## 🆘 الدعم:

### لو عندك مشكلة:

1. **اقرأ الـ FAQ:**
   - في كل ملف documentation
   - في الـ GitHub issues

2. **تأكد من:**
   - .env configuration صحيح
   - Environment variables في dashboard
   - Network connectivity

3. **اطلع على الـ Logs:**
   - Vercel: Dashboard → Deployments → Logs
   - Railway: Dashboard → Services → Logs
   - Supabase: Dashboard → Logs

---

## 📚 الموارد الإضافية:

- [Vercel Documentation](https://vercel.com/docs)
- [Supabase Documentation](https://supabase.com/docs)
- [Railway Documentation](https://docs.railway.app)
- [React Documentation](https://react.dev)
- [FastAPI Documentation](https://fastapi.tiangolo.com)

---

## 📝 الترخيص:

هذا المشروع مرخص تحت MIT License

---

## 🎯 الخطوة التالية:

```bash
# الآن:
cd QUICK_START_NOW.md
# أو
cat README_DEPLOYMENT.md
```

---

**جاهز للبدء؟ اقرأ [QUICK_START_NOW.md](QUICK_START_NOW.md) الآن! 🚀**

---

**Made with ❤️ by Security Team**

Last Updated: 2026-08-23
