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

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "AI-Powered Security Scanner"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"

    ENFORCE_TARGET_SCOPE: bool = Field(False, validation_alias="ENFORCE_TARGET_SCOPE")
    ALLOWED_TARGETS_RAW: str = Field("", validation_alias="ALLOWED_TARGETS")

    NMAP_BINARY_PATH: str = "nmap"
    DEFAULT_SCAN_TIMEOUT_SECONDS: int = 1800

    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-3.7-flash"
    GEMINI_MAX_OUTPUT_TOKENS: int = 8192
    AI_INPUT_COST_PER_1M_USD: float = 0.0
    AI_OUTPUT_COST_PER_1M_USD: float = 0.0

    DATA_DIR: Path = Path("./data")
    DATABASE_URL: str = "sqlite:///./data/security_scanner.db"
    DB_AUTO_CREATE_SCHEMA: bool = True
    DB_CONNECT_TIMEOUT_SECONDS: int = 15
    DB_POOL_RECYCLE_SECONDS: int = 180
    DB_POOL_SIZE: int = 3
    DB_MAX_OVERFLOW: int = 2
    REDIS_URL: str | None = None
    # Optional privileged DB URL used only by the durable scheduler to enumerate
    # schedules across tenants. In Supabase/Postgres, point this at a service DB
    # role with the minimum required scheduler privileges (never expose it to API clients).
    SCHEDULER_DATABASE_URL: str | None = None
    JOB_QUEUE_NAME: str = "security-scanner:jobs"
    JOB_QUEUE_ENABLED: bool = True
    WORKER_MODE: bool = False
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
    SUPABASE_TENANT_CLAIM: str = "tenant_id"
    SUPABASE_ROLE_CLAIM: str = "app_metadata.role"
    SUPABASE_AUTO_PROVISION: bool = True
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
    WEB_SCAN_VERIFY_TLS: bool = False
    ALLOW_SSRF_RISK_TARGETS: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

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
    return any(addr in network for network in SSRF_BLOCKED_NETWORKS)


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
    يقبل: عنوان IP مفرد، أو اسم مضيف (hostname) مطابق تماماً لعنصر بالقائمة،
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
        if target not in allowed and not _is_ip_in_allowed_network(target, allowed):
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
