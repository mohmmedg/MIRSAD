"""Scan profiles and safety/budget normalization for MIRSAD.

Profiles are intentionally conservative. They tune the existing engines rather than
inventing a second scanner pipeline, and all limits remain bounded server-side.
"""
from copy import deepcopy

PROFILES = {
    "passive": {"network_profile":"quick","web_profile":"balanced","max_pages":1,"max_depth":0,"network_ports":"top100","safe_mode":"safe","max_requests":250,"requests_per_second":2,"max_concurrency":1,"network":False,"web":False,"api":False,"subdomain_discovery":True,"subdomain_dns_verification":True,"subdomain_network_scan":False,"subdomain_web_scan":False,"subdomain_api_security":False,"subdomain_max_hosts":25},
    "quick": {"network_profile":"quick","web_profile":"balanced","max_pages":25,"max_depth":2,"network_ports":"top100","safe_mode":"safe","max_requests":750,"requests_per_second":3,"max_concurrency":2,"subdomain_discovery":True,"subdomain_dns_verification":True,"subdomain_network_scan":True,"subdomain_web_scan":True,"subdomain_api_security":True,"subdomain_max_hosts":50},
    "standard": {"network_profile":"balanced","web_profile":"deep","max_pages":80,"max_depth":4,"network_ports":None,"safe_mode":"safe","max_requests":5000,"requests_per_second":5,"max_concurrency":4,"subdomain_discovery":True,"subdomain_dns_verification":True,"subdomain_network_scan":True,"subdomain_web_scan":True,"subdomain_api_security":True,"subdomain_max_hosts":100},
    "deep": {"network_profile":"deep","web_profile":"deep","max_pages":250,"max_depth":6,"network_ports":"1-65535","safe_mode":"safe","max_requests":15000,"requests_per_second":8,"max_concurrency":6,"subdomain_discovery":True,"subdomain_dns_verification":True,"subdomain_network_scan":True,"subdomain_web_scan":True,"subdomain_api_security":True,"subdomain_max_hosts":250},
    "maximum": {"network_profile":"maximum","web_profile":"maximum","max_pages":500,"max_depth":8,"network_ports":"1-65535","safe_mode":"safe","max_requests":30000,"requests_per_second":10,"max_concurrency":8,"subdomain_discovery":True,"subdomain_dns_verification":True,"subdomain_network_scan":True,"subdomain_web_scan":True,"subdomain_api_security":True,"subdomain_max_hosts":500},
}

SAFE_MODES = {"safe", "caution", "destructive"}


def resolve_profile(name: str | None, current: dict) -> dict:
    key = (name or "standard").strip().lower()
    if key == "custom":
        out = deepcopy(current)
    else:
        if key not in PROFILES:
            raise ValueError(f"Unknown scan profile: {key}")
        out = {**PROFILES[key], **current}
        # Only explicit custom tuning values should override a profile. Pydantic
        # defaults are indistinguishable from explicit values, so profile values
        # are authoritative for the primary engine knobs unless custom is used.
        for k in ("network_profile","web_profile","max_pages","max_depth","network_ports","max_requests","requests_per_second","max_concurrency","network","web","api","subdomain_discovery","subdomain_dns_verification","subdomain_network_scan","subdomain_web_scan","subdomain_api_security","subdomain_max_hosts"):
            if k in PROFILES[key]: out[k] = PROFILES[key][k]
    mode = str(out.get("safe_mode", "safe")).lower()
    if mode not in SAFE_MODES: raise ValueError("safe_mode must be safe, caution, or destructive")
    # Safety is server-authoritative.  The legacy probe_write_methods field is
    # accepted for compatibility, but cannot upgrade a safe request.
    # Caution allows schema-backed POST/PUT/PATCH probes; destructive additionally
    # allows DELETE/default-credential probes and other explicitly unsafe checks.
    out["probe_write_methods"] = mode in {"caution", "destructive"}
    out["destructive_confirmation"] = bool(out.get("destructive_confirmation", False))
    if mode == "destructive" and not out["destructive_confirmation"]:
        raise ValueError("destructive mode requires destructive_confirmation=true")
    out["scan_profile"] = key
    out["max_requests"] = max(100, min(int(out.get("max_requests", 30000)), 1000000))
    out["requests_per_second"] = max(1, min(int(out.get("requests_per_second", 5)), 20))
    out["max_concurrency"] = max(1, min(int(out.get("max_concurrency", 4)), 16))
    out["max_pages"] = max(1, min(int(out.get("max_pages", 500)), 10000, out["max_requests"]))
    return out
