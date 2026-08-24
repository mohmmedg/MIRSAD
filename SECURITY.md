# SECURITY.md

توثيق مركزي للقرارات الأمنية والقيود المعروفة بهذا المشروع. الهدف: أي حد
يقرأ هذا الملف قبل نشر المشروع (حتى داخلياً بفريق) يعرف بالضبط شو مغطى
وشو لأ، وليش.

---

## 1. طبقات الحماية المطبّقة

### Scope Guard (`backend/app/core/config.py`)
كل فحص (network أو web) يمر إجبارياً عبر `verify_target_in_scope()` قبل
التنفيذ. أي هدف غير موجود بـ `ALLOWED_TARGETS` (IP مفرد / hostname /
CIDR) يُرفض بـ HTTP 403 قبل حتى محاولة الاتصال بالهدف.

**لا تضف أي هدف لـ `ALLOWED_TARGETS` بدون تفويض قانوني صريح (scope
agreement) أو تأكيد إنه ضمن بيئة lab خاصة بك.**

### SSRF Protection (مستقلة عن Scope Guard)
`check_ssrf_risk()` تُستدعى دائماً قبل التنفيذ، حتى لو الهدف موجود
بـ `ALLOWED_TARGETS`. تمنع:
- عناوين cloud metadata (`169.254.169.254` وكامل `169.254.0.0/16`)
- link-local / multicast / reserved / `0.0.0.0`
- **hostname يُحلّ (DNS resolution) إلى أي عنوان بالقائمة أعلاه** — مو بس
  فحص النص الخام، عشان ما ينلف الحماية عبر DNS rebinding بسيط

تُعطَّل فقط عبر `ALLOW_SSRF_RISK_TARGETS=true` (استثناء موثّق، غير موصى
به إلا لسيناريو lab محدد).

### لا يوجد Command Injection
تنفيذ `nmap` عبر `asyncio.create_subprocess_exec(*command, ...)` بقائمة
argv صريحة — بدون `shell=True` ولا `os.system`. كل عنصر يُمرَّر كـ
argument مستقل للعملية مباشرة، بدون أي تفسير شل ممكن يُستغل.

### مصادقة API + Fail-Closed
- `X-API-Key` مطلوب على كل endpoints الفحص/التحليل (`verify_api_key`).
- المقارنة تستخدم `secrets.compare_digest` (زمن ثابت) — لا تكشف طول
  الجزء الصحيح من مفتاح مُخمَّن عبر فروقات التوقيت.
- بالإنتاج (`ENVIRONMENT=production`): `API_KEY` إجباري وإلا التطبيق
  يرفض الإقلاع أصلاً (`sys.exit` بـ `main.py`). نفس الشيء لو
  `CORS_ORIGINS` تحوي `*`.
- بالتطوير المحلي بدون `API_KEY`: الحماية معطّلة ضمنياً (تجربة تطوير
  أسرع) مع تحذير واضح بالـ logs عند الإقلاع.

### Rate Limiting + Audit Log
- `RATE_LIMIT_PER_MINUTE` لكل مفتاح API (أو IP كـ fallback).
- كل طلب فحص (مقبول أو مرفوض بسبب scope/SSRF) يُسجَّل بـ
  `data/audit.log.jsonl` — target, scan_type, نتيجة الفحص، الوقت.
  **مفتاح الـ API نفسه لا يُسجَّل أبداً.**

### Docker Hardening
- مستخدم non-root (`scanner`) بحاوية الـ backend.
- `setcap cap_net_raw,cap_net_admin+eip` على nmap بدل تشغيل الحاوية
  كـ root أو `--privileged`.
- `cap_add: [NET_RAW, NET_ADMIN]` محدد صراحة بـ docker-compose بدل
  صلاحيات واسعة غير ضرورية.

---

## 2. قيود معروفة — اقرأها قبل أي نشر

### 🔑 `VITE_API_KEY` ليس سراً حقيقياً
أي متغير يبدأ بـ `VITE_` يُخبز حرفياً داخل ملفات JavaScript المبنية
(`npm run build`) ويكون مرئياً لأي شخص يفتح DevTools أو يقرأ الشيفرة
المصدَّرة من المتصفح.

**الأثر العملي:** `X-API-Key` كما هو مطبّق هلق **لا يحمي من مستخدم
يملك وصول شرعي للواجهة (frontend) ويريد يتجاوزها** — هو فقط يمنع
استدعاء عشوائي للـ API من متصفح غير مرتبط بالواجهة. هذا نمط مقبول
لأداة داخلية يستخدمها فريق واحد موثوق فيه، **وليس** حماية كافية لو
المشروع صار متعدد المستخدمين (multi-tenant) أو يُنشر لجمهور غير موثوق.

لو احتجت لاحقاً عزل حقيقي بين مستخدمين: انتقل لمصادقة فعلية
(OAuth/JWT بجلسات مستخدم منفصلة) بدل مفتاح واحد مشترك.

### 🗄️ مخزن الفحوصات (`scan_store.py`) — in-memory وغير معزول
- كل الفحوصات تُخزَّن بذاكرة العملية (dict)، تُفقد عند إعادة تشغيل
  الـ backend.
- لا يعمل بين أكثر من instance (لا يدعم horizontal scaling).
- **كل حاملي نفس مفتاح API يشوفون كل الفحوصات** عبر
  `GET /scans/{scan_id}/status` لو خمّنوا/عرفوا الـ scan_id (UUID —
  صعب التخمين عملياً، لكن لا يوجد عزل صريح بين "مستخدمين" لأنو أصلاً
  ما في مفهوم مستخدم منفصل، مفتاح واحد للجميع).

لو المشروع تطوّر لخدمة بأكثر من مستخدم حقيقي: SQLite أو Redis بدل
in-memory، + مفهوم user/tenant فعلي.

### 🔒 TLS Verification أثناء فحص الويب — قابل للضبط الآن
`WebScanner` يفتح اتصال HTTP فعلي (GET) على الهدف لجلب headers/محتوى.
هذا الاتصال **لا يتحقق من صحة شهادة TLS افتراضياً**
(`WEB_SCAN_VERIFY_TLS=false` بشكل افتراضي)، لأن أهداف lab/pentest
كثيراً ما تحمل شهادات ذاتية التوقيع.

ملاحظة: هذا **منفصل** عن `_check_tls()` اللي يفحص صحة الشهادة بشكل
صريح ويُبلغ عن حالتها (`certificate_valid`) بغض النظر عن هذا الإعداد —
يعني نتيجة الفحص نفسها تعكس حالة الشهادة الحقيقية دائماً.

الأثر: بدون تفعيل `WEB_SCAN_VERIFY_TLS=true`، قناة الفحص نفسها (الطلب
اللي يجيب الـ headers/محتوى) غير محمية من MITM. فعّله لو الأهداف
بشهادات CA موثوقة فعلياً وتريد حماية إضافية.

### 🤖 بيانات الفحص تُرسل لـ Gemini API (طرف ثالث)
طبقة `AIAnalyzer` (`/api/v1/analysis/run`) ترسل بيانات الفحص الخام
(منافذ مفتوحة، خدمات، headers، نتائج فحوصات الثغرات) كنص JSON لـ
Gemini API (`api.google-genai.com`) لتحليلها وتوليد تقرير.

**اعتبار امتثال/خصوصية:** لو استخدمت هذا المشروع لفحص أهداف عملاء
حقيقيين، فبيانات البنية التحتية لهيك عملاء تُرسل لطرف ثالث (Google Gemini).
- راجع [سياسة الخصوصية وشروط الاستخدام الخاصة بـ Gemini API](https://ai.google.dev/gemini-api/docs)
  قبل الاعتماد على هذا بمشروع فيه بيانات عملاء حقيقية.
- استخدام محرك `rule_based_analysis` البديل (لا يحتاج API خارجي) هو
  الخيار المناسب لو البيانات حساسة ولا يمكن إرسالها لطرف ثالث.
- وثّق هذا التدفّق (data flow) بأي اتفاقية scope/عقد مع العميل قبل
  الفحص.

### 📦 تبعيات الحزم
لا يوجد فحص آلي دوري (CI) لثغرات معروفة بالتبعيات (`requirements.txt`،
`package-lock.json`). أضف هذا لسير عملك:

```bash
# backend
pip install pip-audit
pip-audit -r backend/requirements.txt

# frontend
cd frontend && npm audit
```

راجع `requirements-dev.txt` — `pip-audit` مضاف هناك الآن.

---

## 3. ملخص: مناسب لـ / غير مناسب لـ

| السيناريو | مناسب؟ |
|---|---|
| أداة داخلية لفريق pentest صغير موثوق، على lab خاص | ✅ نعم، بعد ضبط `.env` صح |
| فحص أهداف عملاء حقيقيين ضمن scope agreement موقّع | ✅ نعم، مع مراجعة قسم "بيانات الفحص تُرسل لـ Gemini API" أولاً |
| خدمة SaaS عامة متعددة المستخدمين (multi-tenant) | ❌ لا — يحتاج مصادقة مستخدمين حقيقية + عزل بيانات + قاعدة بيانات بدل in-memory |
| نشر بدون ضبط `API_KEY`/`ALLOWED_TARGETS`/`CORS_ORIGINS` بشكل صريح | ❌ لا أبداً |

## 4. Production architecture hardening (Phase 2 completion)

- PostgreSQL is the durable system of record for scan jobs and scan state. SQLite remains the local fallback only.
- Redis is used for durable background-job dispatch and distributed rate-limit storage when `REDIS_URL` is configured.
- `worker` is a separate non-HTTP process. The API never needs to execute long scans inside the request process when Redis is available.
- `/readiness` checks Nmap, the configured database, and Redis when queueing is enabled.
- Production startup fails closed when API authentication or target-scope enforcement is not configured.
- Async job state survives API process restarts because it is persisted in PostgreSQL.
- Job payloads contain scan configuration only. Credentials (`auth_header`, `cookie`, API keys) are not copied into audit logs or job logs.
- Do not place real secrets in `frontend/.env`, because Vite exposes `VITE_*` values to the browser bundle. The frontend may use a user-entered key for an internal deployment, but this is **not** multi-tenant authentication.

### Production boundary

This architecture is suitable for an authorized internal security-scanner deployment. It is **not** a public multi-tenant SaaS until a real user identity/session layer, tenant isolation/RLS, per-user authorization, secret management, and an authenticated frontend session flow are added. The existing API-key mode is intentionally retained so the current frontend remains visually unchanged.

### Secret rotation

If a real API key or Gemini key has ever been committed, pasted into a chat, stored in a ZIP, or exposed in a browser build, rotate/revoke it at the provider immediately. Removing it from the source tree does not invalidate the old credential.

## User authentication / RBAC / tenant isolation

Production API access uses short-lived Bearer access tokens plus rotating opaque refresh tokens. Passwords are stored only as scrypt hashes. Users belong to exactly one tenant and have one of `viewer`, `analyst`, or `admin` roles. Existing `X-API-Key` authentication is legacy-only and disabled by default in production.

PostgreSQL enables row-level security for durable job/scan rows using the transaction-local `app.tenant_id` setting. File-backed history and asset inventory are also partitioned by tenant ID. Worker processes restore the tenant context from the durable job before reading or writing tenant-scoped data.

Never place `GEMINI_API_KEY`, database passwords, JWT secrets, user credentials, cookies, or Authorization headers in frontend environment variables, source control, logs, job payloads, or AI prompts. Use `backend/.env` (or an external secret manager in production).
