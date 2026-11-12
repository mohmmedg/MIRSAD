"""
Automatic CVE attachment for network findings.

Previously CVE lookup was a fully manual, separate step (`/analysis/cve-lookup`)
that required the operator to already know which product+version to ask
about. This module closes that gap: every network finding whose underlying
open port has a fingerprinted product+version is automatically checked
against the real NIST NVD database (via the existing, already-cached
``app.modules.rule_based_analysis.nvd_client.lookup_cves``) and, if any CVEs
are found, they are attached to that finding's ``cve_matches`` field.

Design constraints:
- Never raises into the scan pipeline. NVD being down, rate-limited, or
  returning malformed data must not fail a scan — it just means no CVE data
  gets attached for that finding.
- Deduplicates identical (product, version) pairs within one scan so a host
  with many ports running the same service only triggers one NVD call.
- Only attaches *real* NVD results — nothing is fabricated when NVD has no
  match or is unreachable.
"""
from __future__ import annotations

from typing import Any

from app.modules.rule_based_analysis.nvd_client import lookup_cves, NVDLookupError
from app.modules.threat_intel.epss_client import lookup_epss_many
from app.modules.threat_intel.external_clients import cisa_kev_client


async def _lookup_cached(cache: dict[tuple[str, str], list[dict[str, Any]]], product: str, version: str) -> list[dict[str, Any]]:
    key = (product.strip().lower(), version.strip())
    if key in cache:
        return cache[key]
    try:
        results = await lookup_cves(product, version)
    except (NVDLookupError, ValueError):
        results = []
    cache[key] = results
    return results


async def _attach_epss(results: list[dict[str, Any]]) -> tuple[float, bool]:
    """Enrich each CVE match dict in place with epss_score/epss_percentile
    and in_kev, and return (exploitability, in_kev) — this becomes the
    finding's risk exploitability factor, so a CVE with real observed
    exploitation activity outranks one that's merely theoretically severe.

    1.4/2.3: CISA KEV (confirmed active exploitation in the wild) is a
    stronger, more concrete signal than EPSS (a predicted probability), so a
    KEV hit floors exploitability at 1.0 regardless of what EPSS alone says -
    it never lets a KEV-listed CVE be treated as low-priority just because
    its EPSS score happens to be moderate.
    """
    if not results:
        return 0.0, False
    epss_by_cve = await lookup_epss_many([r.get("cve_id", "") for r in results])
    max_score = 0.0
    any_kev = False
    for r in results:
        cve_id = (r.get("cve_id") or "").upper()
        epss = epss_by_cve.get(cve_id)
        if epss:
            r["epss_score"] = epss["epss_score"]
            r["epss_percentile"] = epss["epss_percentile"]
            max_score = max(max_score, epss["epss_score"])
        in_kev = await cisa_kev_client.is_known_exploited(cve_id)
        r["in_kev"] = in_kev
        any_kev = any_kev or in_kev
    exploitability = 1.0 if any_kev else max_score
    return exploitability, any_kev


async def attach_cve_matches_normalized(findings: list[Any], network: Any) -> None:
    """Full-assessment path: ``findings`` are ``NormalizedFinding`` objects,
    ``network`` is the ``NetworkScanResult`` already produced by this scan."""
    if not network or not getattr(network, "open_ports", None):
        return
    cache: dict[tuple[str, str], list[dict[str, Any]]] = {}
    port_by_asset = {
        f"{network.target}:{p.port}/{p.protocol}": p
        for p in network.open_ports
    }
    for finding in findings:
        if finding.source_module != "network" or not finding.affected_asset:
            continue
        port = port_by_asset.get(finding.affected_asset)
        if not port or not port.product or not port.version:
            continue
        results = await _lookup_cached(cache, port.product, port.version)
        if results:
            finding.cve_matches = results[:5]
            # This runs before risk_engine.assess() (in correlator.correlate,
            # later in the pipeline), which reads risk_context["exploitability"]
            # when present instead of its severity-based default — so this is
            # what actually makes EPSS influence the final risk score, not
            # just decorate the finding with an extra number nobody reads.
            max_epss = await _attach_epss(finding.cve_matches)
            exploitability, in_kev = max_epss
            if exploitability > 0:
                finding.risk_context["exploitability"] = exploitability
            if in_kev:
                finding.risk_context["in_kev"] = True


async def attach_cve_matches_dicts(findings: list[dict[str, Any]], network_ports: list[dict[str, Any]]) -> None:
    """Async single-module scan path (``finding_pipeline``): ``findings`` are
    plain dicts, ``network_ports`` is the raw ``open_ports`` list of dicts
    from the network scan result (``{"port", "protocol", "product", "version", ...}``)."""
    if not network_ports:
        return
    cache: dict[tuple[str, str], list[dict[str, Any]]] = {}
    port_by_key = {
        f"{p.get('port')}/{p.get('protocol', 'tcp')}": p
        for p in network_ports
    }
    for finding in findings:
        if finding.get("source_module") != "network":
            continue
        port = port_by_key.get(finding.get("affected_asset"))
        if not port or not port.get("product") or not port.get("version"):
            continue
        results = await _lookup_cached(cache, port["product"], port["version"])
        if results:
            finding["cve_matches"] = results[:5]
            exploitability, in_kev = await _attach_epss(finding["cve_matches"])
            risk_context = finding.setdefault("risk_context", {})
            if exploitability > 0:
                risk_context["exploitability"] = exploitability
            if in_kev:
                risk_context["in_kev"] = True
