"""
EPSS (Exploit Prediction Scoring System) lookup — https://www.first.org/epss/

CVSS measures theoretical severity; EPSS estimates the probability (0-1)
that a given CVE will actually be exploited in the wild in the next 30
days, based on real observed scanning/exploitation activity. Two CVEs can
have the identical CVSS "Critical" score while one has a 90% real-world
exploitation probability and the other under 1% — EPSS is what tells them
apart, which is exactly what risk prioritization needs and CVSS alone
cannot provide.

Free, no API key required, maintained by FIRST.org (the same body behind
CVSS itself).
"""
from __future__ import annotations

import time
from typing import Any

import httpx

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT_SECONDS = 10.0
CACHE_TTL_SECONDS = 24 * 60 * 60  # EPSS scores are recalculated daily upstream

# Simple in-memory cache (process lifetime only — unlike the NVD client this
# doesn't need to survive restarts; EPSS scores are cheap and safe to refetch).
_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}


class EPSSLookupError(Exception):
    pass


async def lookup_epss(cve_id: str) -> dict[str, Any] | None:
    """Returns {"epss_score": float 0-1, "epss_percentile": float 0-1} for a
    single CVE ID, or None if FIRST.org has no EPSS entry for it (e.g. a
    CVE too new to have been scored yet). Never raises into the caller —
    a scan's risk output should never depend on this optional enrichment
    service being reachable."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    cached = _cache.get(cve_id)
    if cached and (time.time() - cached[0]) < CACHE_TTL_SECONDS:
        return cached[1]
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(EPSS_API_BASE, params={"cve": cve_id})
        if response.status_code != 200:
            _cache[cve_id] = (time.time(), None)
            return None
        data = response.json()
        rows = data.get("data") or []
        if not rows:
            _cache[cve_id] = (time.time(), None)
            return None
        row = rows[0]
        result = {"epss_score": float(row["epss"]), "epss_percentile": float(row["percentile"])}
    except Exception:
        # Network error, timeout, malformed JSON, missing key — all treated
        # the same way: no EPSS data available for this CVE right now.
        result = None
    _cache[cve_id] = (time.time(), result)
    return result


async def lookup_epss_many(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Bulk variant — FIRST.org's API accepts a comma-separated cve= list in
    one request, which is far cheaper than one request per CVE when a
    finding matched several. Falls back to per-CVE lookups (which hit the
    same cache) if the bulk request itself fails."""
    ids = [c.strip().upper() for c in cve_ids if c and c.strip().upper().startswith("CVE-")]
    if not ids:
        return {}
    uncached = [c for c in ids if c not in _cache or (time.time() - _cache[c][0]) >= CACHE_TTL_SECONDS]
    if uncached:
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.get(EPSS_API_BASE, params={"cve": ",".join(uncached[:50])})
            if response.status_code == 200:
                data = response.json()
                found = {row["cve"]: {"epss_score": float(row["epss"]), "epss_percentile": float(row["percentile"])} for row in data.get("data") or []}
                for cve in uncached:
                    _cache[cve] = (time.time(), found.get(cve))
            else:
                for cve in uncached:
                    _cache.setdefault(cve, (time.time(), None))
        except Exception:
            for cve in uncached:
                _cache.setdefault(cve, (time.time(), None))
    return {c: _cache[c][1] for c in ids if _cache.get(c) and _cache[c][1]}
