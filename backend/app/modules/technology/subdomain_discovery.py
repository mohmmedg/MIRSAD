"""Passive + low-noise DNS subdomain discovery.

Sources (each a `source_x(base_domain) -> dict[str, dict]` async function with
the same {hostname, method, source, evidence} output shape, registered in
plugin_registry.py under kind="subdomain_source"):
- Certificate Transparency via crt.sh (passive; no requests to discovered hosts).
- Certificate SANs supplied by the caller.
- DNSDumpster (passive, no key).
- Wayback Machine CDX API (passive, no key; historical URLs reveal hostnames).
- Censys certificate search (optional, requires CENSYS_API_ID/SECRET).
- SecurityTrails passive-DNS history (optional, requires SECURITYTRAILS_API_KEY).
- Bounded DNS resolution of common names, with wildcard detection.

This is discovery only. It never scans a discovered hostname automatically.
"""
import asyncio
import logging
import socket
import sys
import ipaddress
import re
from urllib.parse import urlparse

import httpx
import tldextract

from app.modules.plugin_registry import Plugin, registry
from app.modules.external_scanners.engines import run_subfinder_source
from app.modules.threat_intel.external_clients import censys_client, securitytrails_client, virustotal_client

logger = logging.getLogger(__name__)

# Offline PSL snapshot only (suffix_list_urls=()): a security scanner must
# not depend on an outbound fetch to publicsuffix.org at scan time, and must
# not silently fall back to naive last-two-labels parsing if that fetch
# fails or is blocked by network policy.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Multi-tenant hosting suffixes where a naive "last two labels" split is
# wrong even as a fallback: <tenant>.herokuapp.com is not "in scope" of
# herokuapp.com, it IS the tenant's own registrable domain. tldextract's
# bundled Public Suffix List already encodes these (and many more), this
# set is only a defense-in-depth backstop in case that data is ever stale
# or the extractor still returns a bare suffix for some other reason.
KNOWN_SHARED_HOSTING_SUFFIXES = {
    "herokuapp.com", "github.io", "gitlab.io", "vercel.app", "netlify.app",
    "pages.dev", "workers.dev", "azurewebsites.net", "azurestaticapps.net",
    "cloudfront.net", "firebaseapp.com", "web.app", "surge.sh",
    "onrender.com", "render.com", "repl.co", "glitch.me",
    "ngrok.io", "ngrok-free.app", "s3.amazonaws.com",
}

# Hard safety cap: subdomain discovery is passive and cheap, but each
# discovered host feeds an *active* per-host assessment loop (DNS, network,
# web, API). Never let a base-domain misclassification (or a genuinely huge
# but legitimate target) silently balloon into thousands of active scans
# against hosts an operator never explicitly reviewed. See MIRSAD-AUDIT:
# a mis-scoped target on a shared PaaS suffix returned 4,529 unrelated
# third-party hosts and the assessment loop began scanning all of them.
MAX_SUBDOMAINS_TO_ASSESS = 50

COMMON_NAMES = [
    "www", "api", "app", "admin", "portal", "dev", "staging", "test", "qa",
    "uat", "beta", "demo", "mail", "smtp", "imap", "vpn", "remote", "auth",
    "login", "sso", "cdn", "static", "assets", "media", "files", "download",
    "docs", "blog", "shop", "store", "support", "status", "monitor", "grafana",
    "git", "gitlab", "jenkins", "ci", "docker", "registry", "m", "mobile",
]


def _base_domain(host: str) -> str:
    """Return the target's registrable domain, Public-Suffix-List aware.

    A naive "last two labels" split (the previous implementation) is wrong
    for any target hosted on a multi-tenant platform: for
    "juice-shop.herokuapp.com" it would return "herokuapp.com" — the shared
    hosting provider's own domain, not the target's. Discovery would then
    enumerate *every* customer on that platform (thousands of unrelated,
    unauthorized hosts) instead of just the target's own subdomain tree.

    tldextract knows "herokuapp.com" (and github.io, vercel.app, etc.) is
    itself a public suffix, so it correctly returns
    "juice-shop.herokuapp.com" as the registrable domain here.
    """
    host = (host or "").lower().rstrip(".")
    ext = _tld_extractor(host)
    if ext.domain and ext.suffix:
        base = f"{ext.domain}.{ext.suffix}"
    else:
        # No recognized public suffix (e.g. a bare internal/lab hostname).
        # Fall back to the previous heuristic rather than failing closed.
        parts = host.split(".")
        base = ".".join(parts[-2:]) if len(parts) >= 2 and all(parts) else host
    if base in KNOWN_SHARED_HOSTING_SUFFIXES:
        # Defense in depth: never treat a bare shared-hosting suffix itself
        # as an enumerable "base domain", even if the PSL data used above
        # were ever stale or unavailable.
        print(
            f"[subdomain_discovery] refusing to use shared-hosting suffix "
            f"'{base}' as an enumeration scope for host '{host}'",
            file=sys.stderr, flush=True,
        )
        return host
    return base


def _valid_hostname(name: str) -> bool:
    name = str(name or "").lower().rstrip(".")
    if not name or len(name) > 253 or name.isdigit() or all(part.isdigit() for part in name.split(".")):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        pass
    return all(len(part) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in name.split("."))

def _in_scope(name: str, base: str) -> bool:
    name = name.lower().rstrip(".")
    return _valid_hostname(name) and bool(name and base and name.endswith("." + base) and name != base)


def _resolve(name: str) -> list[str]:
    try:
        return sorted({str(x[4][0]) for x in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)})
    except Exception:
        return []

async def source_dnsdumpster(base_domain: str) -> dict[str, dict]:
    """DNSDumpster (https://dnsdumpster.com) — free, no API key, passive
    aggregator of DNS records including subdomains. Fails safe to {} on any
    error (layout change, rate limit, network) since it's a best-effort extra
    source, not a required one."""
    try:
        async with httpx.AsyncClient(
            timeout=8, follow_redirects=True,
            headers={"User-Agent": "MIRSAD-Scanner/1.0 (authorized-security-testing)"},
        ) as client:
            r = await client.get("https://api.dnsdumpster.com/domain/" + base_domain)
            if r.status_code != 200:
                return {}
            data = r.json()
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for row in (data.get("a", []) or []) + (data.get("cname", []) or []):
        name = str(row.get("host", "")).strip().lower().rstrip(".")
        if _in_scope(name, base_domain):
            out[name] = {"hostname": name, "method": "DNS aggregation", "source": "DNSDumpster",
                         "evidence": f"DNSDumpster record for {name}"}
    return out


async def source_wayback(base_domain: str) -> dict[str, dict]:
    """Wayback Machine CDX API (https://web.archive.org/cdx) — free, no key.
    Historical crawled URLs often reference subdomains never seen in CT logs
    (e.g. deprecated staging hosts). Passive: only queries the archive, never
    the discovered hosts themselves."""
    try:
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=True,
            headers={"User-Agent": "MIRSAD-Scanner/1.0 (authorized-security-testing)"},
        ) as client:
            r = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": f"*.{base_domain}/*", "output": "json", "fl": "original",
                        "collapse": "urlkey", "limit": "2000"},
            )
            if r.status_code != 200:
                return {}
            rows = r.json()
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for row in rows[1:] if isinstance(rows, list) and len(rows) > 1 else []:
        try:
            host = urlparse(row[0]).hostname or ""
        except Exception:
            continue
        name = host.strip().lower().rstrip(".")
        if _in_scope(name, base_domain):
            out.setdefault(name, {"hostname": name, "method": "Historical crawl", "source": "Wayback CDX",
                                   "evidence": f"Archived URL referenced host: {name}"})
    return out


async def source_censys(base_domain: str) -> dict[str, dict]:
    """Optional (CENSYS_API_ID/CENSYS_API_SECRET). No-op when not configured."""
    names = await censys_client.enum_subdomains(base_domain)
    out: dict[str, dict] = {}
    for name in names:
        if _in_scope(name, base_domain):
            out[name] = {"hostname": name, "method": "Certificate search", "source": "Censys",
                         "evidence": f"Censys certificate search matched: {name}"}
    return out


async def source_securitytrails(base_domain: str) -> dict[str, dict]:
    """Optional (SECURITYTRAILS_API_KEY). No-op when not configured."""
    names = await securitytrails_client.enum_subdomains(base_domain)
    out: dict[str, dict] = {}
    for name in names:
        if _in_scope(name, base_domain):
            out[name] = {"hostname": name, "method": "Passive DNS history", "source": "SecurityTrails",
                         "evidence": f"SecurityTrails passive DNS record: {name}"}
    return out


async def source_virustotal(base_domain: str) -> dict[str, dict]:
    """Optional (VIRUSTOTAL_API_KEY). No-op when not configured."""
    names = await virustotal_client.enum_subdomains(base_domain)
    out: dict[str, dict] = {}
    for name in names:
        if _in_scope(name, base_domain):
            out[name] = {"hostname": name, "method": "Certificate/DNS relationship", "source": "VirusTotal",
                         "evidence": f"VirusTotal subdomain relationship: {name}"}
    return out


_PLUGIN_SOURCES = {
    "subdomain_source.dnsdumpster": source_dnsdumpster,
    "subdomain_source.wayback": source_wayback,
    "subdomain_source.censys": source_censys,
    "subdomain_source.securitytrails": source_securitytrails,
    "subdomain_source.virustotal": source_virustotal,
    "subdomain_source.subfinder": run_subfinder_source,
}
for _name, _runner in _PLUGIN_SOURCES.items():
    try:
        registry.register(Plugin(name=_name, version="1.0", kind="subdomain_source", runner=_runner))
    except ValueError:
        pass  # already registered (e.g. module reloaded under a test runner)


async def discover_subdomains(target_url: str, certificate_names: list[str] | None = None, max_results: int = MAX_SUBDOMAINS_TO_ASSESS) -> list[dict]:
    host = urlparse(target_url if "://" in target_url else "https://" + target_url).hostname or ""
    try:
        if ipaddress.ip_address(host):
            logger.info("Skipping subdomain discovery for IP literal target %s", host)
            return []
    except ValueError:
        pass
    base = _base_domain(host)
    if not base or "." not in base or base in {"localhost", "local"}:
        return []

    found: dict[str, dict] = {}

    # Certificate SANs are the fastest passive source and remain useful even
    # when CT is unavailable.
    for raw in certificate_names or []:
        name = str(raw).strip().lower().lstrip("*.").rstrip(".")
        if _in_scope(name, base):
            found[name] = {"hostname": name, "method": "TLS certificate SAN", "source": "TLS certificate", "evidence": f"Certificate SAN entry: {name}"}

    # CT lookup is passive. Failure is intentionally non-fatal.
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, headers={"User-Agent": "MIRSAD-Scanner/1.0 (authorized-security-testing)"}) as client:
            r = await client.get("https://crt.sh/", params={"q": f"%.{base}", "output": "json"})
            if r.status_code == 200:
                rows = r.json()
                for row in rows if isinstance(rows, list) else []:
                    for raw in str(row.get("name_value", "")).splitlines():
                        name = raw.strip().lower().lstrip("*.").rstrip(".")
                        if _in_scope(name, base):
                            found[name] = {"hostname": name, "method": "Certificate Transparency", "source": "crt.sh", "evidence": f"Certificate Transparency certificate name: {name}"}
    except Exception:
        logger.debug("Certificate Transparency (crt.sh) subdomain lookup failed for %s", base, exc_info=True)

    # Every registered subdomain_source plugin runs concurrently and best-effort.
    # A failing/unconfigured source contributes nothing (already fails safe
    # internally) rather than aborting discovery for the others.
    plugin_runners = [p for p in registry.list() if p["kind"] == "subdomain_source"]
    if plugin_runners:
        results = await asyncio.gather(
            *(_PLUGIN_SOURCES[p["name"]](base) for p in plugin_runners if p["name"] in _PLUGIN_SOURCES),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, dict):
                for name, entry in result.items():
                    found.setdefault(name, entry)

    # Detect wildcard DNS once. If wildcard exists, do not report every random
    # common name as a real subdomain merely because it resolves.
    wildcard_ips = set(_resolve("mirsad-wildcard-check-9f3a7b." + base))
    sem = asyncio.Semaphore(8)
    async def check(label: str):
        name = f"{label}.{base}"
        async with sem:
            ips = await asyncio.to_thread(_resolve, name)
        if ips and not wildcard_ips.intersection(ips):
            return name, ips
        return None
    results = await asyncio.gather(*(check(x) for x in COMMON_NAMES))
    for item in results:
        if item:
            name, ips = item
            found.setdefault(name, {"hostname": name, "method": "DNS resolution", "source": "DNS", "evidence": f"A/AAAA resolution returned: {', '.join(ips)}"})

    result = sorted(found.values(), key=lambda x: x["hostname"])

    max_results = max(1, min(int(max_results), 500))
    if len(result) > max_results:
        # Never let discovery silently hand an unbounded host list to the
        # active per-host assessment loop. Cap it and log loudly — an
        # operator who genuinely needs the full set should re-run with an
        # explicit, reviewed scope rather than have it happen implicitly.
        print(
            f"[subdomain_discovery] {len(result)} candidate host(s) found "
            f"for '{base}', exceeding the safety cap of "
            f"{MAX_SUBDOMAINS_TO_ASSESS}. Truncating to the first "
            f"{max_results}; re-scope explicitly to assess the "
            f"full set.",
            file=sys.stderr, flush=True,
        )
        result = result[:max_results]

    return result