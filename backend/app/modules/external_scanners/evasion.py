"""
evasion.py — طبقة التخفي المركزية لمرصاد
==========================================
تقنيات معيارية في اختبار الاختراق المرخص للحد من قابلية الكشف
بواسطة WAF / IDS / IPS. استخدمها فقط على أهداف لديك تصريح كتابي بفحصها.

الاستخدام:
    from app.modules.external_scanners.evasion import EvasionProfile, apply_evasion_to_args

المستويات:
    - NONE    : بلا تخفٍّ (للبيئات الداخلية أو عند الإيقاف الصريح)
    - PASSIVE : UA + ترويسات فقط — لا يُغيّر معدل الإرسال
    - STANDARD: UA + ترويسات + jitter + تأخير عشوائي (افتراضي)
    - AGGRESSIVE: كل ما سبق + fragmentation hints + decoy-like timing
"""
from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.core.config import settings


class EvasionLevel(str, Enum):
    NONE       = "none"
    PASSIVE    = "passive"
    STANDARD   = "standard"     # الافتراضي
    AGGRESSIVE = "aggressive"


# ── User-Agents ─────────────────────────────────────────────────────────────
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,en-US;q=0.7",
    "ar,en;q=0.7,fr;q=0.5",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

_REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "",  # بلا Referer — أحياناً أكثر طبيعية
]


@dataclass
class EvasionProfile:
    """إعدادات التخفي القابلة للتكوين لكل جلسة فحص."""

    level: EvasionLevel = EvasionLevel.STANDARD

    # User-Agent — None = عشوائي من القائمة في كل طلب
    user_agent: str | None = None

    # تأخير جيتر بالثانية (min, max)
    jitter_range: tuple[float, float] = (0.05, 0.35)

    # تأخير إضافي لـ AGGRESSIVE
    aggressive_delay: tuple[float, float] = (0.1, 0.8)

    # proxy اختياري (http://host:port)
    proxy: str | None = field(default_factory=lambda: getattr(settings, "EVASION_HTTP_PROXY", "") or None)

    # ─────────────────────────────────────────────────────────────────────
    def random_ua(self) -> str:
        return self.user_agent or random.choice(_UA_POOL)

    def http_headers(self) -> dict[str, str]:
        """مجموعة ترويسات تجعل الطلب يبدو كمتصفح حقيقي."""
        if self.level == EvasionLevel.NONE:
            return {}
        h: dict[str, str] = {
            "User-Agent": self.random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": random.choice(_ACCEPT_LANGS),
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            ref = random.choice(_REFERERS)
            if ref:
                h["Referer"] = ref
        return h

    def jitter_seconds(self) -> float:
        """تأخير عشوائي ناعم بين الطلبات."""
        if self.level == EvasionLevel.NONE:
            return 0.0
        lo, hi = self.jitter_range
        delay = random.uniform(lo, hi)
        if self.level == EvasionLevel.AGGRESSIVE:
            lo2, hi2 = self.aggressive_delay
            delay += random.uniform(lo2, hi2)
        return delay

    def env(self) -> dict[str, str]:
        """متغيرات البيئة للأدوات الخارجية (proxy، إلخ)."""
        e = os.environ.copy()
        if self.proxy:
            for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                e[k] = self.proxy
        return e

    def nuclei_flags(self) -> list[str]:
        """أعلام إضافية لـ nuclei تدعم الـ evasion."""
        if self.level == EvasionLevel.NONE:
            return []
        flags = ["-H", f"User-Agent: {self.random_ua()}"]
        if self.level == EvasionLevel.AGGRESSIVE:
            # تأخير 100-300ms بين كل قالب
            flags += ["-timeout", "10"]
        return flags

    def ffuf_flags(self) -> list[str]:
        """أعلام إضافية لـ ffuf."""
        if self.level == EvasionLevel.NONE:
            return []
        ua = self.random_ua()
        lang = random.choice(_ACCEPT_LANGS)
        flags = [
            "-H", f"User-Agent: {ua}",
            "-H", f"Accept-Language: {lang}",
            "-H", "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
            "-H", "Cache-Control: no-cache",
        ]
        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            # تأخير عشوائي بين الطلبات
            p = round(random.uniform(0.01, 0.08), 3)
            flags += ["-p", str(p)]
        return flags

    def sqlmap_flags(self) -> list[str]:
        """أعلام إضافية لـ sqlmap."""
        if self.level == EvasionLevel.NONE:
            return []
        ua = self.random_ua()
        flags = [
            f"--user-agent={ua}",
            "--random-agent",  # sqlmap يُقنّع بـ UA عشوائي من قاعدة بياناته الداخلية أيضاً
        ]
        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            _d = float(getattr(settings, "SQLMAP_DELAY_SECONDS", 0.0) or 0.0)
            if _d > 0:
                flags += [f"--delay={_d}"]
        if self.level == EvasionLevel.AGGRESSIVE:
            flags += [
                "--tamper=space2comment,between,randomcase",  # tamper scripts لتشويش الـ payload
            ]
        return flags


# ── خريطة القيم الفعلية من الـ Frontend ──────────────────────────────────────
#
# scan_profile (الـ dropdown الثاني في الصورة):
#   "passive"  → Passive Recon
#   "quick"    → Quick
#   "standard" → Standard
#   "deep"     → Deep
#   "maximum"  → Maximum
#   "custom"   → Custom (يحتاج تقييم يدوي)
#
# safe_mode (الـ dropdown الأول):
#   "safe"        → Safe — read-only
#   "caution"     → Caution — schema-backed mutations only
#   "destructive" → Destructive — bounded write/delete tests
# ─────────────────────────────────────────────────────────────────────────────

_PROFILE_LEVEL: dict[str, EvasionLevel] = {
    "passive":     EvasionLevel.PASSIVE,    # قراءة فقط، حركة خفيفة جداً
    "quick":       EvasionLevel.PASSIVE,    # سريع ومحدود — UA فقط كافٍ
    "standard":    EvasionLevel.STANDARD,   # UA + jitter متوسط
    "deep":        EvasionLevel.AGGRESSIVE, # UA + jitter + tamper + proxy
    "maximum":     EvasionLevel.AGGRESSIVE, # أقصى تخفٍّ
    "custom":      EvasionLevel.STANDARD,   # افتراضي للـ custom
}

_SAFEMODE_LEVEL: dict[str, EvasionLevel] = {
    "safe":        EvasionLevel.PASSIVE,    # قراءة فقط — حركة طبيعية جداً
    "caution":     EvasionLevel.STANDARD,   # تعديلات محدودة — تخفٍّ متوسط
    "destructive": EvasionLevel.AGGRESSIVE, # اختبارات destructive — أقصى تخفٍّ
}


def default_profile(
    safe_mode: str = "safe",
    scan_profile: str = "standard",
) -> EvasionProfile:
    """
    أنشئ EvasionProfile بناءً على القيم الفعلية من الـ Frontend.

    المنطق: نأخذ الأعلى (الأكثر حماية) بين مستوى safe_mode ومستوى scan_profile.
    مثال:
      safe + maximum   → AGGRESSIVE (maximum يرفع المستوى)
      destructive + quick → AGGRESSIVE (destructive يرفع المستوى)
      safe + standard  → STANDARD
      safe + passive   → PASSIVE
    """
    _rank = {
        EvasionLevel.NONE:       0,
        EvasionLevel.PASSIVE:    1,
        EvasionLevel.STANDARD:   2,
        EvasionLevel.AGGRESSIVE: 3,
    }
    lvl_profile  = _PROFILE_LEVEL.get(scan_profile,  EvasionLevel.STANDARD)
    lvl_safemode = _SAFEMODE_LEVEL.get(safe_mode,     EvasionLevel.STANDARD)
    # نختار الأعلى بين الاثنين
    lvl = lvl_profile if _rank[lvl_profile] >= _rank[lvl_safemode] else lvl_safemode
    return EvasionProfile(level=lvl)
