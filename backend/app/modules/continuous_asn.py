"""3.1 - organization-wide expanded discovery ("ASN discovery").

Wired into continuous.py as a distinct schedule kind (see
ContinuousScanner.create_asn_discovery / _execute_asn_discovery in
continuous.py) rather than a separate scheduler: it reuses the exact same
Postgres-leased, Redis-deduplicated due-work loop as ordinary re-scan
schedules, just with a different row.request["__kind__"].

Unlike a normal continuous re-scan (which re-scans one already-known
target), this periodically asks "what NEW hosts exist under this
domain/organization that we haven't scanned before?" and only surfaces the
delta - re-running full discovery every cycle but diffing against
`known_assets` (persisted in the schedule row's JSON `request` column, so no
DB migration is required for this to work end-to-end).
"""
from __future__ import annotations

from app.modules.technology.subdomain_discovery import discover_subdomains  # 1.1 - reuses every registered source
from app.modules.threat_intel.external_clients import censys_client, securitytrails_client


async def discover_new_assets_for_asn(asn_or_org: str, already_scanned: set[str] | None = None) -> list[str]:
    """Best-effort full-scope discovery for one root domain/organization,
    returning only hosts not already present in `already_scanned`.

    Reuses 1.1's multi-source subdomain discovery (crt.sh, DNSDumpster,
    Wayback CDX, plus Censys/SecurityTrails when configured) - this
    orchestrates existing sources at the same scope discover_subdomains()
    already supports; it does not add a new discovery mechanism of its own.
    """
    already_scanned = {h.lower().rstrip(".") for h in (already_scanned or set())}
    discovered: set[str] = set()

    for hit in await discover_subdomains(asn_or_org):
        host = hit.get("hostname") if isinstance(hit, dict) else getattr(hit, "hostname", None)
        if host:
            discovered.add(str(host).lower().rstrip("."))

    # discover_subdomains() already calls the registered Censys/SecurityTrails
    # subdomain_source plugins internally (see 1.1), so nothing further is
    # needed here for those two - they're listed for clarity of what backs
    # this function, not because this function calls them a second time.
    _ = (censys_client, securitytrails_client)

    return sorted(discovered - already_scanned)
