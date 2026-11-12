"""Authentication protection discovery and safe verification.

This module intentionally avoids credential spraying, CAPTCHA bypass, and lockout
triggering. It discovers authentication surfaces and reports evidence needed for
an operator to verify CAPTCHA/rate limiting/lockout controls safely.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Any

AUTH_PATH_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|auth|authenticate|oauth|token|session|"
    r"password|account|sso|saml|oidc)(?:/|$|\?|#|-|_)",
    re.I,
)
CAPTCHA_RE = re.compile(
    r"(?:captcha|recaptcha|g-recaptcha|grecaptcha|hcaptcha|turnstile|"
    r"cf-turnstile|challenge-platform|arkose|funcaptcha|datadome)",
    re.I,
)
RATE_HEADER_NAMES = {
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
    "ratelimit-reset",
}


def _same_origin(url: str, origin: tuple[str, str | None, int]) -> bool:
    p = urlparse(url)
    return (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) == origin


def _auth_candidate(url: str) -> bool:
    return bool(AUTH_PATH_RE.search(urlparse(url).path or ""))


def analyze_auth_protection(
    *,
    page_urls: list[str] | None = None,
    forms: list[Any] | None = None,
    rendered_html: list[dict] | None = None,
    xhr_requests: list[dict] | None = None,
    responses: list[dict] | None = None,
    origin_url: str | None = None,
) -> dict[str, Any]:
    """Build a bounded authentication-protection inventory from observed traffic.

    No credentials are accepted and no authentication request is generated.
    """
    page_urls = page_urls or []
    forms = forms or []
    rendered_html = rendered_html or []
    xhr_requests = xhr_requests or []
    responses = responses or []

    origin = None
    if origin_url:
        p = urlparse(origin_url)
        origin = (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80))

    endpoints: dict[str, dict[str, Any]] = {}

    def add(url: str, method: str = "GET", source: str = "observed", status: int | None = None):
        if not url or (origin and not _same_origin(url, origin)):
            return
        if not _auth_candidate(url):
            return
        e = endpoints.setdefault(url, {"url": url, "methods": set(), "sources": set(), "statuses": set()})
        e["methods"].add(method.upper())
        e["sources"].add(source)
        if status is not None:
            e["statuses"].add(int(status))

    for f in forms:
        action = getattr(f, "action", None) or (f.get("action") if isinstance(f, dict) else None)
        method = getattr(f, "method", "GET") or (f.get("method") if isinstance(f, dict) else "GET")
        if action:
            add(str(action), str(method), "html-form")

    for req in xhr_requests:
        add(str(req.get("url", "")), str(req.get("method", "GET")), "browser-xhr")

    for resp in responses:
        add(str(resp.get("url", "")), str(resp.get("method", "GET")), "browser-response", resp.get("status"))

    captcha_evidence: list[dict[str, str]] = []
    for item in rendered_html:
        url = str(item.get("url", ""))
        html = str(item.get("html", ""))
        if CAPTCHA_RE.search(html):
            match = CAPTCHA_RE.search(html)
            captcha_evidence.append({
                "url": url,
                "indicator": match.group(0)[:80] if match else "captcha",
                "source": "rendered-dom",
            })
    captcha_evidence = captcha_evidence[:50]

    rate_observations = []
    for resp in responses:
        headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
        status = int(resp.get("status") or 0)
        observed = {k: headers[k] for k in RATE_HEADER_NAMES if k in headers}
        if status == 429 or observed:
            rate_observations.append({
                "url": str(resp.get("url", ""))[:1000],
                "status": status,
                "headers": observed,
            })
    rate_observations = rate_observations[:100]

    lockout_signals = []
    for resp in responses:
        status = int(resp.get("status") or 0)
        if status in {423, 429}:
            lockout_signals.append({"url": str(resp.get("url", ""))[:1000], "status": status})
    lockout_signals = lockout_signals[:50]

    findings = []
    if endpoints:
        findings.append({
            "check": "authentication_surface_discovery",
            "status": "OBSERVED",
            "detail": f"Discovered {len(endpoints)} same-origin authentication-related endpoint(s).",
        })
    else:
        findings.append({
            "check": "authentication_surface_discovery",
            "status": "NOT_OBSERVED",
            "detail": "No authentication endpoint was observed during the bounded crawl/browser pass.",
        })

    findings.append({
        "check": "captcha_presence",
        "status": "PRESENT" if captcha_evidence else "NOT_OBSERVED",
        "detail": (
            "CAPTCHA/challenge indicators were found in rendered DOM."
            if captcha_evidence else
            "No CAPTCHA/challenge indicator was observed in rendered DOM. "
            "This does not prove CAPTCHA is absent from server-side authentication."
        ),
    })
    findings.append({
        "check": "rate_limiting",
        "status": "EVIDENCE_OBSERVED" if rate_observations else "NOT_VERIFIED",
        "detail": (
            "The scan observed HTTP 429 and/or standard rate-limit headers."
            if rate_observations else
            "No rate-limit response/header was observed during normal discovery traffic; "
            "credential spraying was not performed."
        ),
    })
    findings.append({
        "check": "account_lockout_backoff",
        "status": "EVIDENCE_OBSERVED" if lockout_signals else "NOT_VERIFIED",
        "detail": (
            "The scan observed 423/429 responses on an authentication-related request."
            if lockout_signals else
            "Lockout/backoff was not actively triggered; safe discovery alone cannot prove its absence."
        ),
    })
    findings.append({
        "check": "server_side_captcha_enforcement",
        "status": "NOT_VERIFIED",
        "detail": "Server-side CAPTCHA enforcement requires a controlled invalid/missing-token authentication test; this engine does not bypass or spray credentials.",
    })

    normalized = []
    for e in endpoints.values():
        normalized.append({
            "url": e["url"],
            "methods": sorted(e["methods"]),
            "sources": sorted(e["sources"]),
            "statuses": sorted(e["statuses"]),
        })

    return {
        "version": 1,
        "authentication_endpoints": sorted(normalized, key=lambda x: x["url"])[:100],
        "captcha_evidence": captcha_evidence,
        "rate_limit_observations": rate_observations,
        "lockout_signals": lockout_signals,
        "findings": findings,
        "active_credential_attack": False,
    }
