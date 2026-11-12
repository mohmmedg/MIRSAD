"""
Optional external threat-intelligence enrichment clients.

Each client wraps a well-known public/commercial threat-intel API (Shodan,
VirusTotal, AbuseIPDB). None of them is ever called unless the operator has
configured the matching API key via environment variable / .env — with no
key, ``.enabled`` is False and the scan simply skips that source. This is
deliberate: these services are third-party reputation/exposure databases,
not something this project can bundle credentials for, and a missing key
must never break or slow down a scan.

Every network call here is:
- Short-timeout (few seconds) so a slow/unreachable provider cannot stall a
  scan.
- Wrapped in a broad ``except Exception`` that degrades to ``None`` — a
  malformed response, expired key, or rate limit must never raise into the
  scan pipeline.
- Read-only (GET requests against the provider's lookup endpoints only).

These results are *context*, not verified facts about the scanned target —
they reflect what a third party has observed about that IP/domain
elsewhere on the internet, which is why they are surfaced separately as
``threat_intel`` rather than folded into deterministic findings.
"""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.request_budget import RequestBudget

DEFAULT_TIMEOUT = 6.0


class ShodanClient:
    """https://developer.shodan.io/api — known exposed services/banners for an IP."""

    BASE = "https://api.shodan.io"

    @property
    def enabled(self) -> bool:
        return bool(settings.SHODAN_API_KEY)

    async def host_info(self, ip: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                r = await client.get(f"{self.BASE}/shodan/host/{ip}", params={"key": settings.SHODAN_API_KEY})
            if r.status_code != 200:
                return None
            data = r.json()
            return {
                "source": "shodan",
                "ip": ip,
                "org": data.get("org"),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "known_vulns": sorted((data.get("vulns") or [])),
            }
        except Exception:
            return None


class VirusTotalClient:
    """https://developer.virustotal.com/reference — domain reputation/malware associations."""

    BASE = "https://www.virustotal.com/api/v3"

    @property
    def enabled(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY)

    async def domain_reputation(self, domain: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                r = await client.get(
                    f"{self.BASE}/domains/{domain}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
            if r.status_code != 200:
                return None
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": attrs.get("reputation"),
            }
        except Exception:
            return None

    async def enum_subdomains(self, base_domain: str) -> list[str]:
        """VirusTotal's /domains/{domain}/subdomains — passive, certificate-
        and-DNS-derived subdomain relationships. Same output-shape contract
        as CensysClient.enum_subdomains/SecurityTrailsClient.enum_subdomains
        (a flat list of candidate hostnames); scope/DNS validation happens
        in technology/subdomain_discovery.py, not here."""
        if not self.enabled:
            return []
        try:
            names: set[str] = set()
            url = f"{self.BASE}/domains/{base_domain}/subdomains?limit=40"
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                for _ in range(3):  # follow pagination up to a bounded number of pages
                    if not url:
                        break
                    r = await client.get(url, headers={"x-apikey": settings.VIRUSTOTAL_API_KEY})
                    if r.status_code != 200:
                        break
                    body = r.json()
                    for item in body.get("data", []) or []:
                        name = str(item.get("id", "")).strip().lower()
                        if name:
                            names.add(name)
                    url = (body.get("links") or {}).get("next")
            return sorted(names)
        except Exception:
            return []


class AbuseIPDBClient:
    """https://docs.abuseipdb.com/ — IP abuse-confidence score from community reports."""

    BASE = "https://api.abuseipdb.com/api/v2"

    @property
    def enabled(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)

    async def check_ip(self, ip: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                r = await client.get(
                    f"{self.BASE}/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                )
            if r.status_code != 200:
                return None
            data = r.json().get("data", {})
            return {
                "source": "abuseipdb",
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "is_tor": data.get("isTor"),
            }
        except Exception:
            return None


class CensysClient:
    """https://search.censys.io/api — internet-wide host/service exposure search.
    Same optional-key / fail-safe pattern as ShodanClient above."""

    BASE = "https://search.censys.io/api/v2"

    @property
    def enabled(self) -> bool:
        return bool(settings.CENSYS_API_ID and settings.CENSYS_API_SECRET)

    async def host_info(self, ip: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                auth=(settings.CENSYS_API_ID, settings.CENSYS_API_SECRET),
            ) as client:
                r = await client.get(f"{self.BASE}/hosts/{ip}")
            if r.status_code != 200:
                return None
            result = r.json().get("result", {})
            services = result.get("services", []) or []
            return {
                "source": "censys",
                "ip": ip,
                "autonomous_system": (result.get("autonomous_system") or {}).get("name"),
                "services": [
                    {"port": s.get("port"), "service_name": s.get("service_name")} for s in services
                ],
                "location": (result.get("location") or {}).get("country"),
            }
        except Exception:
            return None

    async def enum_subdomains(self, base_domain: str) -> list[str]:
        """Certificate-search based subdomain enumeration — same output shape
        contract as the other subdomain sources in technology/subdomain_discovery.py
        (a flat list of candidate hostnames; scope/DNS validation happens there)."""
        if not self.enabled:
            return []
        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT,
                auth=(settings.CENSYS_API_ID, settings.CENSYS_API_SECRET),
            ) as client:
                r = await client.post(
                    f"{self.BASE}/certificates/search",
                    json={"q": f"names: {base_domain}", "per_page": 100},
                )
            if r.status_code != 200:
                return []
            hits = r.json().get("result", {}).get("hits", [])
            names: set[str] = set()
            for hit in hits:
                for n in hit.get("names", []) or []:
                    names.add(str(n).lower().lstrip("*."))
            return sorted(names)
        except Exception:
            return []


class SecurityTrailsClient:
    """https://docs.securitytrails.com/reference — passive DNS / subdomain history."""

    BASE = "https://api.securitytrails.com/v1"

    @property
    def enabled(self) -> bool:
        return bool(settings.SECURITYTRAILS_API_KEY)

    async def enum_subdomains(self, base_domain: str) -> list[str]:
        if not self.enabled:
            return []
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                r = await client.get(
                    f"{self.BASE}/domain/{base_domain}/subdomains",
                    headers={"APIKEY": settings.SECURITYTRAILS_API_KEY},
                )
            if r.status_code != 200:
                return []
            subs = r.json().get("subdomains", []) or []
            return sorted({f"{s}.{base_domain}".lower() for s in subs if s})
        except Exception:
            return []


class CISAKEVClient:
    """https://www.cisa.gov/known-exploited-vulnerabilities-catalog — free, no API
    key, public JSON feed of CVEs with confirmed active exploitation. Used by the
    risk engine (2.3) to sharply raise priority for findings tied to a KEV CVE,
    since "known exploited in the wild" is a stronger signal than EPSS alone."""

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self) -> None:
        self._cache: set[str] | None = None

    @property
    def enabled(self) -> bool:
        return True  # no key required; still fails gracefully on network errors

    async def _load(self) -> set[str]:
        if self._cache is not None:
            return self._cache
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(self.FEED_URL)
            if r.status_code != 200:
                return set()
            data = r.json()
            self._cache = {str(v.get("cveID", "")).upper() for v in data.get("vulnerabilities", [])}
        except Exception:
            return set()
        return self._cache

    async def is_known_exploited(self, cve_id: str | None) -> bool:
        if not cve_id:
            return False
        catalog = await self._load()
        return cve_id.strip().upper() in catalog


shodan_client = ShodanClient()
virustotal_client = VirusTotalClient()
abuseipdb_client = AbuseIPDBClient()
censys_client = CensysClient()
securitytrails_client = SecurityTrailsClient()
cisa_kev_client = CISAKEVClient()


async def gather_threat_intel(domain: str | None, ip_addresses: list[str], budget: RequestBudget | None = None) -> dict:
    """Best-effort aggregate across every configured provider. Returns an
    empty dict (not an error) when no provider is configured."""
    out: dict = {}
    async def _call(kind: str, fn, *args):
        if budget:
            await budget.acquire_external(kind)
            try:
                return await fn(*args)
            finally:
                budget.release_external()
        return await fn(*args)
    if virustotal_client.enabled and domain:
        vt = await _call("virustotal", virustotal_client.domain_reputation, domain)
        if vt:
            out["virustotal"] = vt
    if shodan_client.enabled and ip_addresses:
        shodan_results = []
        for ip in ip_addresses[:3]:  # cap: avoid burning API quota on large DNS answer sets
            info = await _call("shodan", shodan_client.host_info, ip)
            if info:
                shodan_results.append(info)
        if shodan_results:
            out["shodan"] = shodan_results
    if abuseipdb_client.enabled and ip_addresses:
        abuse_results = []
        for ip in ip_addresses[:3]:
            info = await _call("abuseipdb", abuseipdb_client.check_ip, ip)
            if info:
                abuse_results.append(info)
        if abuse_results:
            out["abuseipdb"] = abuse_results
    if censys_client.enabled and ip_addresses:
        censys_results = []
        for ip in ip_addresses[:3]:
            info = await _call("censys", censys_client.host_info, ip)
            if info:
                censys_results.append(info)
        if censys_results:
            out["censys"] = censys_results
    return out
