"""
core/config.py

الإعدادات العامة للمشروع + طبقة التحكم بالنطاق (Scope Authorization Guard).

هذا الملف يطبّق الجانب الأخلاقي/القانوني المذكور بمقترح المشروع بشكل تقني وليس
مجرد نص: عند تفعيل النطاق الإلزامي فقط، يجب أن يكون الهدف ضمن ALLOWED_TARGETS قبل ما يُسمح
بفحصه فعلياً. يبقى SSRF protection فعالاً دائماً، بينما التطوير يسمح بإدخال أهداف جديدة من الواجهة بدون قائمة ثابتة.
lab)، وبيصير لاحقاً الأساس اللي تبني فوقه Scope Agreement الحقيقي مع العملاء.
"""

import ipaddress
import socket
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


import os as _os
# كان 7200 ثابتًا فتعلق أي أداة ساعتين؛ أصبح قابلاً للضبط (الافتراضي ساعة).
MIN_TOOL_TIMEOUT_SECONDS = int(_os.environ.get("MIN_TOOL_TIMEOUT_SECONDS", "3600"))
_TWO_HOUR_FLOOR_FIELDS = (
    "DEFAULT_SCAN_TIMEOUT_SECONDS", "EXTERNAL_DAST_TIMEOUT_SECONDS",
    "EXTERNAL_QUICK_TIMEOUT_SECONDS", "EXTERNAL_STANDARD_TIMEOUT_SECONDS",
    "EXTERNAL_DEEP_TIMEOUT_SECONDS", "EXTERNAL_MAXIMUM_TIMEOUT_SECONDS",
    "EXTERNAL_EVIDENCE_COLLECTION_TIMEOUT_SECONDS", "TESTSSL_TIMEOUT_SECONDS",
    "HTTPX_TIMEOUT_SECONDS", "TRIVY_TIMEOUT_SECONDS", "SOURCE_TOOL_TIMEOUT_SECONDS",
    "ADVANCED_SECURITY_TIMEOUT_SECONDS",
)


# seconds per external tool per scan profile; deep/maximum fall through to *_CAP_SECONDS
PROFILE_TOOL_CAPS_SECONDS: dict[str, dict[str, int]] = {
    "quick":    {"nuclei": 900,  "zap": 1200, "sqlmap": 300,  "ghauri": 300, "ffuf": 300, "testssl": 300},
    "standard": {"nuclei": 1800, "zap": 1800, "sqlmap": 900,  "ghauri": 900, "ffuf": 600, "testssl": 600},
}

class Settings(BaseSettings):
    APP_NAME: str = "AI-Powered Security Scanner"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"

    ENFORCE_TARGET_SCOPE: bool = Field(True, validation_alias="ENFORCE_TARGET_SCOPE")
    ALLOWED_TARGETS_RAW: str = Field("", validation_alias="ALLOWED_TARGETS")

    NMAP_BINARY_PATH: str = "nmap"
    DEFAULT_SCAN_TIMEOUT_SECONDS: int = 7200
    # Ports of MIRSAD's own stack published on the Docker host (backend, ZAP API,
    # frontend, DefectDojo...). Nmap must never probe them when the target is the
    # Docker host: NSE http scripts hitting ZAP's port made ZAP proxy requests to
    # itself in a loop (880k failed reads) and flooded DefectDojo/backend.
    NMAP_EXCLUDE_PORTS: str = "8000,8082,5173,8080,8081,8083,8443,5432,6379,6380,9000"
    # NSE scripts (-sC / --script) are dropped for loopback / Docker-host targets.
    NMAP_DISABLE_NSE_ON_LOCAL: bool = True
    # فحص على مرحلتين للبروفايلات الثقيلة: اكتشاف سريع للمنافذ ثم -sV/-sC/-O على المفتوح فقط
    NMAP_TWO_PHASE: bool = True
    NMAP_DISCOVERY_MIN_RATE: int = 500
    # UDP is ICMP rate-limited: a full 1-65535 UDP sweep takes hours. Cap it (2026-10-13).
    NMAP_UDP_TOP_PORTS: int = 200
    NMAP_UDP_MAX_RETRIES: int = 1
    NMAP_UDP_HOST_TIMEOUT_SECONDS: int = 300
    NMAP_UDP_TIMEOUT_SECONDS: int = 360
    # Circuit breaker: consecutive connect failures before a module stops hitting the target.
    TARGET_CONNECT_FAIL_LIMIT: int = 8
    # Consecutive 5xx responses before the transport pauses traffic (target health), and the pause length.
    TARGET_5XX_FAIL_LIMIT: int = 25
    TARGET_UNHEALTHY_COOLDOWN_SECONDS: float = 30.0

    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-3.7-flash"
    GEMINI_MAX_OUTPUT_TOKENS: int = 8192
    GEMINI_BASE_URL: str | None = None
    GEMINI_HTTP_PROXY: str | None = None
    AI_INPUT_COST_PER_1M_USD: float = 0.0
    AI_OUTPUT_COST_PER_1M_USD: float = 0.0

    DATA_DIR: Path = Path("./data")
    DATABASE_URL: str = "sqlite:///./data/security_scanner.db"
    DB_AUTO_CREATE_SCHEMA: bool = True
    # TLS mode for PostgreSQL. Supabase requires TLS (default). Use 'disable' ONLY for the local docker Postgres.
    DB_SSLMODE: str = "require"
    DB_CONNECT_TIMEOUT_SECONDS: int = 15
    # مهلة جلب JWKS من Supabase (app/core/auth.py::_get_jwks_client). بدونها
    # يستخدم PyJWKClient urllib بلا مهلة، فيُعلَّق التحقق من التوكن إلى ما
    # لا نهاية إذا تعذّر الوصول إلى مضيف Supabase.
    SUPABASE_JWKS_TIMEOUT_SECONDS: int = 15
    DB_POOL_RECYCLE_SECONDS: int = 180
    DB_POOL_TIMEOUT_SECONDS: int = 90
    DB_RETRY_ATTEMPTS: int = 5
    DB_RETRY_BASE_DELAY_SECONDS: float = 0.5
    # 2026-09-16: was 3/2, sized down defensively for a flaky VPN path. The
    # backend now connects to Supabase's Postgres directly (see database.py)
    # - Supabase project njnzfwiasslrcrhhlzqv (eu-central-1) reports
    # max_connections=60. With --workers 4 in production
    # (docker-compose.production.yml), 4 x (pool_size+max_overflow) must stay
    # safely under that with headroom for the dashboard/migrations/other
    # clients, hence 5+5=10 per worker, 40 total.
    # 2026-09-22 fix (توزيع ذكي للفحوصات المتزامنة):
    # القيم 15/10 كانت غير آمنة فعلياً. كل عملية (backend أو worker) تفتح
    # محرّكين منفصلين على نفس القاعدة — sync engine (SessionLocal) و async
    # engine (AsyncSessionLocal) — كل واحد بمجمّعه الخاص، يعني الاستهلاك
    # الفعلي لكل عملية هو (DB_POOL_SIZE+DB_MAX_OVERFLOW) × 2، وليس × 1 كما
    # افترض التعليق القديم. مع --workers 4 للـ backend فقط (بدون أي worker
    # فحص إضافي) هذا كان يعني حتى (15+10)×2×4 = 200 اتصال محتمل مقابل حد
    # Supabase البالغ 60 — أي زيادة حقيقية بالتوازي كانت ستُسقط الفحوصات
    # بأخطاء اتصال قاعدة بيانات بدل ما تسرّعها.
    #
    # الحل: الأرقام أدناه أصبحت الحد الأقصى المطلوب فقط؛ effective_db_pool_size
    # و effective_db_max_overflow (تحت) يحسبان القيمة الآمنة فعلياً حسب
    # EXPECTED_APP_PROCESSES و SUPABASE_MAX_CONNECTIONS، ويقلّصان تلقائياً
    # مع تحذير في اللوج بدل ما يفشلوا بصمت. database.py يستخدم هاتين
    # الخاصيتين المحسوبتين، وليس الحقلين الخام مباشرة.
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 5
    # عدد عمليات التطبيق الحية اللي كل وحدة منها تفتح Pool خاص بها:
    # 4 (uvicorn --workers 4 للـ backend) + عدد نسخ worker الفحص الشغالة
    # بنفس الوقت. لو زدت عدد worker containers لتسريع الفحص (التوزيع
    # الذكي)، لازم ترفع هذا الرقم بنفس القدر وإلا effective_db_pool_size
    # بينزل تلقائياً ليبقى آمن.
    EXPECTED_APP_PROCESSES: int = 5
    # 2026-09-22 (تحقّق فعلي عبر الاتصال بـ Supabase — مشروع
    # njnzfwiasslrcrhhlzqv، خطة free): `SELECT current_setting
    # ('max_connections')` رجّع 60 فعلياً (نفس رقم التعليق الأصلي أعلاه)،
    # وليس 15 كما خُمّن سابقاً بدون تحقق. عند القياس كان فيه أصلاً 12
    # اتصال مستخدم كخط أساس (dashboard/migrations) حتى بدون أي فحص شغال —
    # لذلك DB_POOL_RESERVE_CONNECTIONS تحته يأخذ هذا بالاعتبار. راجع هذا
    # الرقم من وقت لآخر (Settings → Database) لأنه يتغير لو غيّرت compute
    # tier مستقبلاً.
    SUPABASE_MAX_CONNECTIONS: int = 60
    # هامش أكبر من قبل عمداً: يغطي خط الأساس المُقاس فعلياً (12 اتصال) +
    # نمو معقول لاحقاً (migrations يدوية، جلسات dashboard إضافية).
    DB_POOL_RESERVE_CONNECTIONS: int = 20
    # 2026-10-05: كاش قصير لنتيجة مصادقة Supabase الناجحة (بالثواني، 0 = معطّل).
    # كل طلب محمي كان يفتح جلستين على DB، ومع polling الواجهة أثناء الفحص
    # كان الـ QueuePool الصغير (2+4) يُستنزف بالمصادقة وحدها فيعود 500.
    AUTH_PRINCIPAL_CACHE_SECONDS: int = 20
    # 2026-10-05: تجميع مخرجات أدوات الفحص قبل كتابتها في DB (بدل صف وجلسة لكل سطر).
    SCANNER_CHUNK_FLUSH_BYTES: int = 16384
    SCANNER_CHUNK_FLUSH_SECONDS: float = 2.0

    # سقف التزامن العالمي للمحركات الخارجية (nuclei/zap/sqlmap/ffuf/testssl).
    # 2026-09-22: كان Semaphore محلي داخل كل عملية worker فقط، فلو شغّلت N
    # نسخة worker بالتوازي (بالضبط الهدف من "التوزيع الذكي") كان السقف
    # الفعلي يتضاعف N مرة بدل ما يبقى ثابت. أصبح الآن يُنفَّذ كسقف موزّع عبر
    # Redis في core/distributed_semaphore.py — القيمة هنا هي السقف العالمي
    # الحقيقي مهما كان عدد الـ worker containers.
    # 2026-09-22: بعد التحقق الفعلي من حد Supabase (60، وليس 15 كما ظُن)
    # الميزانية أفضل من المتوقع — أعيد لـ 5 بدل 3. لسه محافظ عمداً: الخطة
    # المجانية محدودة أيضاً بـ CPU/RAM للـ compute instance نفسه (micro)،
    # مو بس عدد الاتصالات، فرفعه فوق هذا يخاطر بخنق المعالجة مو فقط القاعدة.
    MAX_CONCURRENT_ENGINES: int = 5
    # حد أقصى لعدد الفحوصات المتزامنة على نفس الهدف بالضبط (نفس الدومين/IP)
    # بغض النظر عن عدد الـ workers الكلي — يمنع تراكم الضغط على الموقع
    # المفحوص نفسه لو صار فيه أكثر من job على نفس الهدف بنفس اللحظة.
    MAX_CONCURRENT_ENGINES_PER_TARGET: int = 1
    REDIS_URL: str | None = None
    REDIS_PASSWORD: str | None = None
    # Dedicated at-rest key for credentials kept in durable scan job payloads.
    # When omitted, the crypto helper falls back to existing server secret
    # material for backwards-compatible local deployments.
    JOB_PAYLOAD_ENCRYPTION_KEY: str | None = None
    # Optional privileged DB URL used only by the durable scheduler to enumerate
    # schedules across tenants. In Supabase/Postgres, point this at a service DB
    # role with the minimum required scheduler privileges (never expose it to API clients).
    SCHEDULER_DATABASE_URL: str | None = None
    JOB_QUEUE_NAME: str = "security-scanner:jobs"
    JOB_QUEUE_ENABLED: bool = True
    # DefectDojo result-management integration is enabled by default.
    DEFECTDOJO_ENABLED: bool = True
    DEFECTDOJO_URL: str | None = "http://defectdojo-nginx:8080"
    DEFECTDOJO_API_URL: str | None = "http://defectdojo-nginx:8080"
    DEFECTDOJO_API_TOKEN: str | None = None
    DEFECTDOJO_TIMEOUT: int = 20
    DEFECTDOJO_IMPORT_WAIT_SECONDS: int = 900
    DEFECTDOJO_VERIFY_TLS: bool = True
    DEFECTDOJO_PRODUCT_PREFIX: str = "MIRSAD"
    DEFECTDOJO_ENGAGEMENT_MODE: str = "per_scan"
    DEFECTDOJO_IMPORT_MODE: str = "native"
    DEFECTDOJO_MAX_RETRIES: int = 5
    DEFECTDOJO_STALE_JOB_SECONDS: int = 1800
    WORKER_MODE: bool = False
    WORKER_MAX_CONCURRENT_JOBS: int = 2
    TRUST_PROXY_HEADERS: bool = False
    MAX_JOB_LOGS: int = 200

    API_KEY: str | None = None
    API_KEY_ROLES_RAW: str = Field("", validation_alias="API_KEY_ROLES")
    ENABLE_LEGACY_API_KEY: bool = False
    LEGACY_API_KEY_TENANT_ID: str | None = None
    # مصادقة محلية (password/JWT محلي) أُلغيت بالكامل من هذا المشروع.
    # Supabase Auth هو مزوّد المصادقة الوحيد المدعوم الآن.
    SUPABASE_URL: str | None = None
    SUPABASE_JWT_SECRET: str | None = None
    SUPABASE_JWT_AUDIENCE: str = "authenticated"
    SUPABASE_JWT_ISSUER: str | None = None
    # NOTE: must point at `app_metadata.tenant_id`, matching SUPABASE_ROLE_CLAIM
    # below and the payload written by _supabase_create_user(). app_metadata is
    # the only Supabase claim namespace that is server/trust-controlled; a bare
    # top-level "tenant_id" is never actually present in a Supabase JWT, so a
    # bare claim name here silently never matches and every new sign-in falls
    # back to the auto-provisioned per-user tenant.
    SUPABASE_TENANT_CLAIM: str = "app_metadata.tenant_id"
    SUPABASE_ROLE_CLAIM: str = "app_metadata.role"
    # Secure-by-default (2026-10-21): auto-provisioning is opt-in. It used to default to True,
    # which silently re-enabled account provisioning whenever the variable was omitted.
    SUPABASE_AUTO_PROVISION: bool = False
    # Joining an EXISTING organization by typing its name at signup is disabled by default:
    # user_metadata.tenant_name is user-controlled, so anyone could join a victim tenant.
    SUPABASE_ALLOW_JOIN_TENANT_BY_NAME: bool = False
    # False by default = secure-by-default. When True, any Supabase-authenticated
    # user whose JWT carries no trusted tenant_id claim is allowed to self-create
    # a brand-new tenant. Even when True, that self-created tenant NEVER grants
    # "owner"/"admin" — see _authenticate_supabase. Only the single, global,
    # very-first user of the whole deployment is ever auto-provisioned as owner
    # (one-time bootstrap). Everyone after that needs either a trusted tenant_id
    # claim (joining an existing tenant) or an explicit invite.
    SUPABASE_ALLOW_SELF_SERVICE_SIGNUP: bool = False
    SUPABASE_SERVICE_ROLE_KEY: str | None = None

    CORS_ORIGINS_RAW: str = Field(
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173,http://localhost:3000,http://127.0.0.1:3000",
        validation_alias="CORS_ORIGINS",
    )
    RATE_LIMIT_PER_MINUTE: int = 10
    WEB_SCAN_VERIFY_TLS: bool = True
    ALLOW_SSRF_RISK_TARGETS: bool = False
    # Opt-in hardening: also refuse loopback / RFC1918 / unique-local / docker-internal
    # addresses as scan targets. Off by default to support explicitly authorized local
    # test targets; turn ON for a shared/production deployment.
    # Interim DB copy of the live scan result while Redis is healthy. 0 = never (Redis only,
    # flushed to the row once at the terminal state). >0 = also write it every N seconds.
    LIVE_RESULT_DB_MIN_INTERVAL_SECONDS: int = 0
    BLOCK_PRIVATE_TARGETS: bool = False

    # Optional external threat-intel providers (app.modules.threat_intel).
    # Each is fully inert (never called) until its key is configured — see
    # that module's docstring. Bring your own key/quota for each provider.
    SHODAN_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    CENSYS_API_ID: str | None = None
    CENSYS_API_SECRET: str | None = None
    SECURITYTRAILS_API_KEY: str | None = None
    GENERIC_WEBHOOK_URL: str | None = None
    GENERIC_WEBHOOK_FORMAT: str = "json"  # "json" or "cef"
    # 3.2: optional shared community template directory (see
    # web_scan/scanner.py::_load_templates). Points at a local checkout of a
    # separate templates repo; not required, empty/unset = feature is a no-op.
    EXTERNAL_TEMPLATES_PATH: str | None = None
    # Optional external DAST engines. They are inert unless explicitly enabled
    # and the binary is present in the runtime image.
    ENABLE_NUCLEI: bool = True
    # كانت 5 req/s و concurrency=2 ثابتة في الكود (سبب رئيسي للبطء)
    REQUESTS_PER_SECOND: int = 50
    NUCLEI_CONCURRENCY: int = 15
    # sqlmap: 0 = بلا تأخير. كان --delay=1 ثابتًا مع STANDARD/AGGRESSIVE
    SQLMAP_DELAY_SECONDS: float = 0.0
    SQLMAP_MAX_TARGETS: int = 4
    PREFLIGHT_ATTEMPTS: int = 2
    # فحص فوري عند بدء الفحص: هل الهدف يعمل ويمكن الوصول إليه من حاويات الفحص؟
    PRECHECK_TARGET_REACHABLE: bool = True
    # إن كان الهدف غير قابل للوصول: أنهِ الفحص فورًا (بلا إعادة محاولة) بدل تشغيل الأدوات عبثًا
    FAIL_FAST_ON_UNREACHABLE: bool = True
    # سقوف زمن واقعية لكل محرك (النتائج الجزئية تُحفظ عند بلوغ السقف)
    NUCLEI_CAP_SECONDS: int = 3600
    ZAP_CAP_SECONDS: int = 3600
    SQLMAP_CAP_SECONDS: int = 1800
    GHAURI_CAP_SECONDS: int = 1800
    FFUF_CAP_SECONDS: int = 3600
    TESTSSL_CAP_SECONDS: int = 900
    # Per-profile wall-clock caps per external tool (2026-10-13). quick/standard finish in
    # minutes; only deep/maximum keep the long budgets above. Set to False to restore the old
    # behaviour (every profile uses the *_CAP_SECONDS values).
    ENABLE_PROFILE_TOOL_CAPS: bool = True
    NETWORK_STEP_TIMEOUT_SECONDS: int = 1800
    NETWORK_LONG_PROFILE_TIMEOUT_SECONDS: int = 3600  # was 7200; UDP is capped separately (NMAP_UDP_TIMEOUT_SECONDS)
    NUCLEI_BINARY_PATH: str = "nuclei"
    NUCLEI_ALLOWED_TAGS: str = "cve,misconfig,exposure,config,ssl,headers,technologies,default-login,panel,unauth,token,file,xss,sqli,lfi,rce,ssrf,redirect,takeover,wordpress,wp-plugin,dast,fuzz"
    ENABLE_ZAP: bool = True
    ZAP_ENABLE_AJAX_SPIDER: bool = True
    ZAP_AJAX_SPIDER_MAX_SECONDS: int = 1800
    ZAP_ASCAN_THREADS_PER_HOST: int = 8   # ZAP default is 2
    ZAP_ASCAN_MAX_RULE_MINUTES: int = 5   # one slow rule can no longer hold the scan
    ZAP_MAX_SEED_URLS: int = 1500
    ZAP_BINARY_PATH: str = "zap-full-scan.py"
    EXTERNAL_DAST_TIMEOUT_SECONDS: int = 7200
    # External engines are independently bounded by the scan profile so one
    # hung DAST engine cannot monopolize a full assessment for 90 minutes.
    # The overall scan may still run longer when native crawl/analysis work is
    # progressing; these values only bound one external detector invocation.
    # External scanner processes issue their own HTTP traffic; RequestBudget
    # reserves one slot per process but does not throttle each tool's internal
    # requests. Keep fan-out conservative so a single scan cannot overwhelm a
    # small/local target (especially while ZAP, SQLMap and ffuf are active).
    EXTERNAL_ENGINE_PARALLELISM: int = 2
    # How many discovered subdomains get their DNS/network/web/API assessment
    # run concurrently. This used to be a hard-coded sequential `for` loop (one
    # subdomain fully finished, including its own nuclei/zap/sqlmap/ffuf/testssl
    # pass, before the next one started) — the dominant reason a "full" scan
    # with 10-15 discovered hosts took 15-20+ hours. Keep this modest: each
    # concurrent subdomain scan launches its own external-tool fan-out, so this
    # multiplies total concurrent outbound load against the target almost as
    # much as EXTERNAL_ENGINE_PARALLELISM does.
    SUBDOMAIN_SCAN_CONCURRENCY: int = 4
    # testssl.sh gives up on the whole TLS assessment after this many failed
    # TCP connect attempts (its own internal default is 2). See run_testssl()
    # in external_scanners/engines.py for why this is raised.
    TESTSSL_MAX_SOCKET_FAIL: int = 8
    # Evidence collection (ZAP alert/message pagination, raw artifact persistence)
    # has its OWN 2h budget, independent of the scan phase, so a scan that used
    # its whole window can still collect everything it found.
    EXTERNAL_EVIDENCE_COLLECTION_TIMEOUT_SECONDS: int = 7200
    EXTERNAL_QUICK_TIMEOUT_SECONDS: int = 7200
    EXTERNAL_STANDARD_TIMEOUT_SECONDS: int = 7200
    EXTERNAL_DEEP_TIMEOUT_SECONDS: int = 7200
    EXTERNAL_MAXIMUM_TIMEOUT_SECONDS: int = 7200
    ENABLE_SQLMAP: bool = True
    SQLMAP_BINARY_PATH: str = "sqlmap"
    # 2026-11-02: a 6.5h scan against a target under heavy ffuf/ZAP load died with sqlmap's own
    # "[CRITICAL] unable to connect to the target URL ('Network is unreachable')" on every target -
    # a transient connectivity drop, not a time-budget timeout. sqlmap's own log explicitly suggested
    # raising --time-sec; these flags make sqlmap itself more tolerant of a lagging/flaky target
    # instead of giving up after its stock defaults (--timeout=30, --retries=3, --time-sec=5).
    SQLMAP_REQUEST_TIMEOUT_SECONDS: int = 45
    SQLMAP_RETRIES: int = 5
    SQLMAP_TIME_SEC: int = 8
    # How many times run_sqlmap_multi retries a single target after a dropped-connection failure
    # (previously hard-coded to exactly one retry with a fixed 30s pause, which did not recover in
    # the 2026-11-02 incident). Pauses back off linearly: 20s, 40s, 60s, ... capped by the remaining
    # per-tool time budget.
    SQLMAP_CONNECT_RETRY_ATTEMPTS: int = 3
    SQLMAP_CONNECT_RETRY_BASE_SECONDS: int = 20
    # Before spending a full per-target time slice on a crawler-guessed GET target, confirm it
    # actually exists. select_sqlmap_targets() can propose a GET URL reconstructed from a <form>
    # whose action never 404s in practice but whose exact query shape was guessed; against a real
    # site (portal.cpu.edu.sy, 2026-11-01) 2 of 4 sqlmap targets turned out to be 404s, each
    # consuming its whole budget slice with "[CRITICAL] page not found (404)" and nothing else.
    SQLMAP_PRECHECK_GET_TARGETS: bool = True
    SQLMAP_PRECHECK_TIMEOUT_SECONDS: float = 8.0
    # Second SQL-injection engine (cross-checks sqlmap; runs after it, never beside it).
    ENABLE_GHAURI: bool = True
    GHAURI_BINARY_PATH: str = "ghauri"
    ENABLE_FFUF: bool = True
    FFUF_BINARY_PATH: str = "ffuf"
    # Quick/deep content-discovery wordlists are baked into the image.
    FFUF_WORDLIST_QUICK_PATH: str = "/app/wordlists/mirsad-ffuf-wordlist-quick.txt"
    FFUF_WORDLIST_DEEP_PATH: str = "/app/wordlists/mirsad-ffuf-wordlist-deep.txt"

    # Additional external/passive engines. Enabled by default; deployment
    # operators may disable them explicitly through environment/config.
    ENABLE_TESTSSL: bool = True
    TESTSSL_BINARY_PATH: str = "testssl.sh"
    TESTSSL_TIMEOUT_SECONDS: int = 7200
    ENABLE_SUBFINDER: bool = True
    SUBFINDER_BINARY_PATH: str = "subfinder"
    SUBFINDER_MAX_TIME_MINUTES: int = 3
    SUBFINDER_TIMEOUT_SECONDS: int = 30
    ENABLE_HTTPX_PROBE: bool = True
    HTTPX_BINARY_PATH: str = "pd-httpx"
    HTTPX_TIMEOUT_SECONDS: int = 7200
    HTTPX_MAX_HOSTS: int = 100
    ENABLE_TRIVY: bool = True
    TRIVY_BINARY_PATH: str = "trivy"
    TRIVY_TIMEOUT_SECONDS: int = 7200
    TRIVY_CACHE_DIR: str = "/opt/trivy-cache"
    # Trivy DB availability is a detector capability, not worker liveness.
    # The worker starts even when the registry is unreachable unless the
    # operator explicitly chooses fail-closed startup.
    TRIVY_DB_REQUIRED: bool = True
    TRIVY_DB_BOOTSTRAP_RETRIES: int = 3
    TRIVY_DB_BOOTSTRAP_TIMEOUT_SECONDS: int = 120

    # Native Source Intelligence / optional source-analysis detectors.
    ENABLE_SOURCE_INTELLIGENCE: bool = True
    ENABLE_SOURCE_MAP_ANALYSIS: bool = True
    ENABLE_PLAYWRIGHT: bool = True
    ENABLE_SEMGREP: bool = True
    SEMGREP_BINARY_PATH: str = "semgrep"
    ENABLE_GITLEAKS: bool = True
    GITLEAKS_BINARY_PATH: str = "gitleaks"
    ENABLE_TRUFFLEHOG: bool = True
    TRUFFLEHOG_BINARY_PATH: str = "trufflehog"
    SOURCE_INTELLIGENCE_MAX_SOURCE_SIZE: int = 5_000_000
    SOURCE_INTELLIGENCE_MAX_JS_ASSETS: int = 500
    SOURCE_INTELLIGENCE_MAX_SOURCE_MAPS: int = 100
    SOURCE_INTELLIGENCE_MAX_MAP_SIZE: int = 10_000_000
    SOURCE_INTELLIGENCE_MAX_REPO_FILES: int = 2000
    SOURCE_TOOL_TIMEOUT_SECONDS: int = 7200
    ZAP_SERVICE_URL: str = ""
    ZAP_API_KEY: str = ""
    # Path to a file holding the ZAP API key (generated by the zap-key-init compose service),
    # so the key never has to live in .env. Used only when ZAP_API_KEY itself is empty.
    ZAP_API_KEY_FILE: str = ""
    # Max concurrent scans on the single shared ZAP daemon (1 = fully isolated, see engines.py).
    ZAP_MAX_CONCURRENT_SCANS: int = 1
    ENABLE_ADVANCED_SECURITY: bool = True
    ADVANCED_SECURITY_TIMEOUT_SECONDS: int = 7200
    # Every advanced family has a separate hard wall clock and request allowance.
    # The overall assessment timeout remains the outer bound.
    ADVANCED_SECURITY_PHASE_TIMEOUT_SECONDS: float = Field(180.0, gt=0)
    ADVANCED_SECURITY_PHASE_MAX_REQUESTS: int = Field(2000, ge=1)
    ADVANCED_SECURITY_PHASE_MAX_ENDPOINTS: int = Field(200, ge=1)
    # Deep-assessment ceilings are intentionally high and configurable. They are
    # operational safeguards (not vulnerability-coverage caps): scope, budget and
    # operator policy remain authoritative while large applications can be scanned
    # far beyond the old 500-page/8-depth defaults.
    MAX_ASSESSMENT_PAGES: int = 10000
    MAX_ASSESSMENT_DEPTH: int = 32
    MAX_ASSESSMENT_REQUESTS: int = 1000000
    # When False (default) the worker NEVER resumes scans that were running or
    # queued before it started: on startup they are finalized as CANCELLED and
    # any orphaned RUNNING job found later is cancelled instead of re-queued.
    # Set True only for a multi-worker production deployment that wants
    # crash-recovery (it re-runs interrupted scans from scratch).
    WORKER_RESUME_INTERRUPTED_JOBS: bool = False
    # Stall watchdog (app/core/stall_watchdog.py): flag a running job that has
    # written no progress/log/stage/tool output for this many seconds. Report-only.
    WORKER_STALL_SECONDS: int = 180
    WORKER_STALL_CHECK_SECONDS: int = 15
    # Cancel a job that wrote nothing at all for this long (zombie holding a slot). 0 = report only.
    # A long-running, quiet scanner is not a dead worker. Escalation must be
    # an explicit deployment choice; otherwise it can silently terminate a
    # valid maximum assessment before its own per-tool timeout is reached.
    WORKER_STALL_CANCEL_SECONDS: int = 0
    MAX_ASSESSMENT_CONCURRENCY: int = 64
    MAX_ASSESSMENT_RPS: int = 100
    OOB_CALLBACK_BASE_URL: str | None = None
    OOB_CALLBACK_TOKEN_TTL_SECONDS: int = 3600
    STRICT_EXTERNAL_ENGINE_FAILURES: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @model_validator(mode="after")
    def _load_zap_key_from_file(self):
        if not (self.ZAP_API_KEY or "").strip() and (self.ZAP_API_KEY_FILE or "").strip():
            try:
                with open(self.ZAP_API_KEY_FILE, encoding="utf-8") as fh:
                    key = fh.read().strip()
                if key:
                    object.__setattr__(self, "ZAP_API_KEY", key)
            except OSError:
                # Missing file: ZAP calls will simply be rejected (fail closed) until it exists.
                pass
        return self

    @model_validator(mode="after")
    def _enforce_two_hour_tool_floor(self):
        """Every scan/tool/evidence budget is at least MIN_TOOL_TIMEOUT_SECONDS (2h).

        Older .env / .env.production files still carry 900/1800/5400 values.
        Rather than editing those files (they are in active use), the floor is
        applied here so stale lower values can never cut a scan or evidence
        collection short. Higher values are respected.
        """
        floor = MIN_TOOL_TIMEOUT_SECONDS
        for name in _TWO_HOUR_FLOOR_FIELDS:
            if int(getattr(self, name)) < floor:
                object.__setattr__(self, name, floor)
        return self

    @property
    def _safe_db_pool_budget(self) -> int:
        """أقصى (pool_size+max_overflow) آمن لكل محرك DB واحد، محسوب من حد
        Supabase الفعلي مقسوم على عدد العمليات × 2 محرك (sync+async) لكل عملية.
        2026-09-22 fix: كان فيه أرضية max(2,...) تكسر الضمان على ميزانيات
        ضيقة جداً (خطة Supabase مجانية) — لو الحساب الحقيقي أقل من 2، لازم
        نرجّع 1 لا 2، وإلا نبيع اتصالات أكثر من المتاح فعلياً."""
        processes = max(1, int(getattr(self, "EXPECTED_APP_PROCESSES", 5)))
        available = max(1, int(getattr(self, "SUPABASE_MAX_CONNECTIONS", 15))
                         - int(getattr(self, "DB_POOL_RESERVE_CONNECTIONS", 2)))
        return max(1, available // (processes * 2))

    @property
    def effective_db_pool_size(self) -> int:
        requested = int(getattr(self, "DB_POOL_SIZE", 15))
        requested_overflow = int(getattr(self, "DB_MAX_OVERFLOW", 10))
        budget = self._safe_db_pool_budget
        if requested + requested_overflow <= budget:
            return requested
        # وزّع الميزانية الآمنة بنفس نسبة pool_size:overflow المطلوبة تقريباً.
        # pool_size الأساسي يحصل على الأولوية (يبقى 1 على الأقل)؛ overflow
        # يمكن أن ينزل لـ 0 لو الميزانية ضيقة جداً (خطة مجانية) بدل ما
        # نكسر الميزانية بفرض حد أدنى وهمي عليه.
        ratio = requested / max(1, requested + requested_overflow)
        return max(1, min(budget, round(budget * ratio)))

    @property
    def effective_db_max_overflow(self) -> int:
        requested = int(getattr(self, "DB_POOL_SIZE", 15))
        requested_overflow = int(getattr(self, "DB_MAX_OVERFLOW", 10))
        budget = self._safe_db_pool_budget
        if requested + requested_overflow <= budget:
            return requested_overflow
        return max(0, budget - self.effective_db_pool_size)

    @property
    def api_key_roles(self) -> dict[str, str]:
        out = {}
        for item in self.API_KEY_ROLES_RAW.split(","):
            if ":" in item:
                key, role = item.split(":", 1)
                key, role = key.strip(), role.strip().lower()
                if key and role in {"admin", "analyst", "viewer"}:
                    out[key] = role
        return out

    @property
    def allowed_targets(self) -> list[str]:
        return [t.strip() for t in self.ALLOWED_TARGETS_RAW.split(",") if t.strip()]

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS_RAW.split(",") if o.strip()]


settings = Settings()
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)


# --- SSRF Protection ---
# نطاقات خطرة لا يوجد لها أي استخدام مشروع بأداة فحص شبكات، حتى لو أُدرجت
# غلطاً بـ ALLOWED_TARGETS (مثلاً CIDR واسع بالغلط). هذا خط دفاع إضافي مستقل
# عن Scope Guard، وليس بديلاً عنه.
#   - 169.254.0.0/16: link-local، يشمل عنوان metadata الخاص بمزوّدي cloud
#     (169.254.169.254) اللي منه ممكن تُسرق IAM credentials حساسة
#   - 0.0.0.0/8: "هذه الشبكة" — غير موجّه، سلوك غير معرّف بأغلب الأنظمة
#   - 224.0.0.0/4: multicast — لا معنى لفحصه كهدف فردي
#   - 240.0.0.0/4: محجوز (reserved/future use)
#   - fe80::/10: النظير الـ IPv6 لـ link-local (يشمل metadata عبر IPv6 أيضاً)
#   - ff00::/8: multicast IPv6
SSRF_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

# عناوين مفردة إضافية نمنعها صراحة حتى لو نظرياً تقع خارج الشبكات فوق على
# بعض التفسيرات (دفاع مضاعف/defense-in-depth)
SSRF_BLOCKED_EXACT: set[str] = {
    "169.254.169.254",  # AWS/GCP/Azure metadata endpoint
    "0.0.0.0",
    "::",
}


class SSRFRiskError(Exception):
    """يُرفع عندما يقع الهدف (أو أحد العناوين اللي يُحلّ لها hostname) ضمن
    نطاق SSRF خطر، بغض النظر عن وجوده بـ ALLOWED_TARGETS."""

    def __init__(self, target: str, resolved_ip: str | None = None):
        self.target = target
        self.resolved_ip = resolved_ip
        detail = f"'{target}'"
        if resolved_ip and resolved_ip != target:
            detail += f" (يُحلّ إلى {resolved_ip})"
        super().__init__(
            f"الهدف {detail} يقع ضمن نطاق SSRF محظور (مثل عنوان cloud metadata "
            f"أو multicast/reserved) — مرفوض حتى لو موجود بـ ALLOWED_TARGETS. "
            f"لو هذا فعلاً جزء موثّق من بيئة lab خاصة بك، فعّل "
            f"ALLOW_SSRF_RISK_TARGETS=true بوعي تام بالمخاطر."
        )


def _ip_in_blocked_ssrf_ranges(ip_str: str) -> bool:
    if ip_str in SSRF_BLOCKED_EXACT:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if any(addr in network for network in SSRF_BLOCKED_NETWORKS):
        return True
    # Opt-in: protect the internal stack (redis, zap, defectdojo, DB, docker host).
    if settings.BLOCK_PRIVATE_TARGETS and (addr.is_private or addr.is_loopback):
        return True
    return False


def resolve_safe_target(target: str) -> list[str]:
    """Resolve a hostname and return only IPs that pass the SSRF policy.

    Callers that can pin the connection target (for example nmap) should use
    the returned IPs rather than resolving the hostname again. HTTP callers
    must re-run this check immediately before every request and after redirects.
    """
    try:
        addr = ipaddress.ip_address(target)
        if _ip_in_blocked_ssrf_ranges(str(addr)) and not settings.ALLOW_SSRF_RISK_TARGETS:
            raise SSRFRiskError(target, str(addr))
        return [str(addr)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if settings.ENVIRONMENT == "production":
            raise ValueError(f"Unable to resolve target '{target}'") from exc
        # Development/test environments may mock HTTP/DNS. The actual HTTP
        # request still fails naturally if the host is unresolved; production
        # remains fail-closed.
        return []
    ips = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not ips:
        raise ValueError(f"Unable to resolve target '{target}'")
    if not settings.ALLOW_SSRF_RISK_TARGETS:
        for ip in ips:
            if _ip_in_blocked_ssrf_ranges(ip):
                raise SSRFRiskError(target, resolved_ip=ip)
    return ips


def check_ssrf_risk(target: str) -> None:
    """
    يتحقق أن الهدف (IP مباشر أو hostname يُحلّ إلى IP) لا يقع ضمن نطاق SSRF
    خطر. يُستدعى بالإضافة إلى verify_target_in_scope، مو بدلاً عنها.

    لو ALLOW_SSRF_RISK_TARGETS=true، يتم تجاوز الفحص (استخدام متعمّد فقط،
    موثّق بالـ README تحت Security Considerations).
    """
    if settings.ALLOW_SSRF_RISK_TARGETS:
        return

    # الحالة 1: target نفسه IP
    try:
        ipaddress.ip_address(target)
        if _ip_in_blocked_ssrf_ranges(target):
            raise SSRFRiskError(target)
        return
    except ValueError:
        pass  # مو IP مباشر، جرّب hostname resolution تحت

    # الحالة 2: target هو hostname — لازم نحلّه لعنوان IP فعلي ونفحص هذاك،
    # وإلا ممكن حد يلف الحماية عبر DNS يشاور على 169.254.169.254
    try:
        addr_infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        # فشل الـ resolution هون مش مشكلتنا — الفحص الفعلي (nmap/httpx) رح
        # يتعامل مع الفشل هذا لاحقاً بشكل طبيعي
        return

    for family, _, _, _, sockaddr in addr_infos:
        # sockaddr هو tuple بطول 2 لـ IPv4 أو 4 لـ IPv6؛ العنصر الأول
        # دائماً هو عنوان IP كنص بكلا الحالتين
        resolved_ip = str(sockaddr[0])
        if _ip_in_blocked_ssrf_ranges(resolved_ip):
            raise SSRFRiskError(target, resolved_ip=resolved_ip)


class ScopeViolationError(Exception):
    """يُرفع عندما يكون الهدف المطلوب خارج نطاق الأهداف المصرّح بها.

    ملاحظة أمنية: رسالة الخطأ المرئية للمستخدم/الـ API يجب أن تبقى عامة —
    لا تذكر أسماء متغيرات البيئة (ENFORCE_TARGET_SCOPE / ALLOWED_TARGETS) ولا
    خطوات "كيف تتجاوز الفحص"، لأن هذا يكشف تفاصيل بنية الحماية لأي شخص (بما
    فيهم مهاجم) يجرّب فحص هدف غير مصرّح له. التفاصيل الكاملة تُسجَّل في
    اللوجّات الخادمية فقط عبر detail، وليس في الرسالة المعروضة للعميل.
    """

    def __init__(self, target: str):
        self.target = target
        self.detail = (
            f"scope violation: target '{target}' is not in ALLOWED_TARGETS "
            f"while ENFORCE_TARGET_SCOPE is enabled"
        )
        super().__init__("هذا الهدف غير مصرّح بفحصه ضمن هذه البيئة.")


def _is_ip_in_allowed_network(target_ip: str, allowed_entries: list[str]) -> bool:
    try:
        target_addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return False

    for entry in allowed_entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if target_addr in network:
                return True
        except ValueError:
            continue
    return False


def verify_target_in_scope(target: str) -> None:
    """
    يتحقق أن الهدف ضمن النطاق المصرّح به قبل تنفيذ أي فحص.
    يقبل: عنوان IP مفرد، أو اسم مضيف مطابق، أو wildcard مثل *.example.com،
    أو IP يقع ضمن CIDR range مُدرج بالقائمة.

    يرفع ScopeViolationError إذا كان الهدف خارج النطاق.
    يرفع SSRFRiskError إذا كان الهدف (أو ما يُحلّ له) ضمن نطاق SSRF خطر،
    حتى لو تقنياً موجود بـ ALLOWED_TARGETS — هذا الفحص مستقل ولا يمكن
    تجاوزه إلا صراحة عبر ALLOW_SSRF_RISK_TARGETS.
    """
    # عند تفعيل النطاق الإلزامي، ارفض hostname خارج النطاق قبل DNS resolution.
    # هذا يمنع اختبار/طلب هدف غير مصرّح به من إجبار الـ scanner على انتظار DNS،
    # بينما تبقى SSRF resolution فعّالة للهدف الذي اجتاز scope authorization.
    if settings.ENFORCE_TARGET_SCOPE:
        allowed = settings.allowed_targets
        exact_or_cidr = target in allowed or _is_ip_in_allowed_network(target, allowed)
        wildcard_match = any(
            entry.startswith("*.") and target.lower().endswith(entry[1:].lower())
            and target.lower() != entry[2:].lower()
            for entry in allowed
        )
        if not exact_or_cidr and not wildcard_match:
            # IPs المحظورة SSRF يجب أن تبقى SSRF errors حتى لو لم تُدرج بالنطاق،
            # لذلك نفحصها مباشرة قبل ScopeViolationError.
            try:
                ipaddress.ip_address(target)
            except ValueError:
                raise ScopeViolationError(target)
            check_ssrf_risk(target)
            raise ScopeViolationError(target)

    # SSRF check مستقل عن scope: حتى الهدف المصرّح به يجب ألا يُحلّ إلى
    # cloud metadata/link-local أو نطاق محظور.
    check_ssrf_risk(target)
