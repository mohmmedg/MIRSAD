"""
modules/rule_based_analysis/nvd_client.py

عميل NVD (National Vulnerability Database — قاعدة بيانات الثغرات الأمريكية
الرسمية، مجانية) لجلب CVEs حقيقية حسب اسم المنتج والإصدار، عبر REST API:
https://nvd.nist.gov/developers/vulnerabilities

هذا **منفصل عمداً** عن KNOWN_VULNERABLE_VERSIONS بـ rules.py (الجدول
اليدوي المُستخدم بمحرك rule-based الحتمي والمتزامن). السبب: NVD API عبر
الشبكة، بطيء نسبياً (ثواني)، وعرضة لتحديد معدّل الطلبات (rate limiting) —
دمجه مباشرة بمسار analyze() المتزامن كان يبطّئ كل تحليل rule-based حتى لو
المستخدم ما يحتاج CVE lookup حي. لذلك هو مكشوف كـ endpoint منفصل
(POST /api/v1/analysis/cve-lookup) يستخدمه المستخدم صراحة عند الحاجة.

Caching محلي بملف JSON تحت DATA_DIR، TTL أسبوع — NVD نفسها توصي بعدم
تكرار الاستعلامات المتطابقة بكثرة (rate limit: 5 طلبات/30 ثانية بدون
مفتاح API، أعلى بمفتاح مجاني).
"""

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

from app.core.config import settings

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # أسبوع
REQUEST_TIMEOUT_SECONDS = 8.0


class NVDLookupError(Exception):
    """يُرفع عند فشل الاتصال بـ NVD أو استجابة غير متوقعة — الـ caller
    (endpoint الـ API) يقرر كيف يتعامل معه (503 مع رسالة واضحة عادة)."""


def _cache_path() -> Path:
    return settings.DATA_DIR / "nvd_cache.json"


def _cache_key(product: str, version: str) -> str:
    return f"{product.strip().lower()}::{version.strip()}"


def _load_cache() -> dict[str, dict]:
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict[str, dict]) -> None:
    try:
        settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except OSError:
        logger.debug("Failed to write NVD lookup cache to %s", _cache_path(), exc_info=True)  # فشل الكتابة بالكاش مش سبب كافٍ لفشل الطلب نفسه


def _parse_nvd_response(data: dict) -> list[dict[str, Any]]:
    """يحوّل استجابة NVD الخام (بنية متداخلة كبيرة) لصيغة مبسّطة نستخدمها
    بالتطبيق: cve_id, description, severity, cvss_score, published."""
    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "unknown")

        descriptions = cve.get("descriptions", [])
        english_desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS v3.1 أولوية، ثم v3.0، ثم v2 كـ fallback (بعض CVEs القديمة بس فيها v2)
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity_label = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity_label = cvss_data.get("baseSeverity") or metrics[key][0].get(
                    "baseSeverity"
                )
                break

        results.append(
            {
                "cve_id": cve_id,
                "description": english_desc[:500],  # نقصّ الوصف عشان ما يطول كثير بالاستجابة
                "cvss_score": cvss_score,
                "severity": severity_label,
                "published": cve.get("published"),
            }
        )
    return results


async def lookup_cves(product: str, version: str) -> list[dict[str, Any]]:
    """
    يبحث عن CVEs معروفة لمنتج+إصدار معيّن عبر NVD API، مع كاش محلي (TTL أسبوع).

    يرفع NVDLookupError لو فشل الاتصال بالكامل (شبكة، timeout، استجابة
    غير متوقعة) — الـ caller يقرر كيف يعرض الخطأ للمستخدم.
    """
    if not product or not version:
        raise ValueError("product وversion مطلوبين لبحث CVE.")

    key = _cache_key(product, version)
    cache = _load_cache()
    cached_entry = cache.get(key)
    if cached_entry and (time.time() - cached_entry["cached_at"]) < CACHE_TTL_SECONDS:
        return cached_entry["results"]

    query = f"{product} {version}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(NVD_API_BASE, params={"keywordSearch": query})
    except httpx.HTTPError as exc:
        raise NVDLookupError(f"فشل الاتصال بـ NVD API: {exc}") from exc

    if response.status_code == 429:
        raise NVDLookupError(
            "NVD API رفض الطلب بسبب تجاوز حد المعدل (rate limit). حاول لاحقاً."
        )
    if response.status_code != 200:
        raise NVDLookupError(f"NVD API رجع حالة غير متوقعة: {response.status_code}")

    try:
        data = response.json()
        results = _parse_nvd_response(data)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise NVDLookupError(f"استجابة NVD بصيغة غير متوقعة: {exc}") from exc

    cache[key] = {"cached_at": time.time(), "results": results}
    _save_cache(cache)
    return results
