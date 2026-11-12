"""Conservative endpoint-level coverage: discovery is not a security test."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, urljoin


def _field(obj: Any, name: str, default=None):
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def _key(url: str, method: str = "GET") -> tuple[str, str]:
    p = urlsplit(str(url))
    # Query *names* are useful to compare probe coverage; values can contain
    # credentials, and must never enter the coverage report or fingerprints.
    q = urlencode([(key, "*") for key in sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})])
    safe = urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", q, ""))
    return safe, str(method or "GET").upper()


def build_endpoint_matrix(web: Any | None, api: Any | None) -> list[dict]:
    records: dict[tuple[str, str], dict] = {}
    root = _field(web, "target") or _field(api, "target") or ""
    for source, owner in ((web, "web"), (api, "api")):
        for endpoint in _field(source, "endpoints", []) or []:
            raw = _field(endpoint, "url") or _field(endpoint, "path")
            if not raw:
                continue
            url = urljoin(root, str(raw))
            key = _key(url, _field(endpoint, "method", "GET"))
            rec = records.setdefault(key, {"url": key[0], "method": key[1], "discovered": True,
                                            "http_observed": False, "security_state": "NOT_TESTED",
                                            "reason": "no recorded security probe for this endpoint/method",
                                            "sources": []})
            if owner not in rec["sources"]:
                rec["sources"].append(owner)
            rec["http_observed"] |= _field(endpoint, "status_code") is not None

    for check in _field(web, "vulnerability_checks", []) or []:
        check_url = _field(check, "url")
        if not check_url:
            continue
        key = _key(urljoin(root, check_url), _field(check, "method", "GET"))
        if key in records:
            records[key]["security_state"] = "TESTED"
            records[key]["reason"] = "web vulnerability check recorded for matching URL and method"
            records[key]["test_source"] = "web.vulnerability_checks"

    return sorted(records.values(), key=lambda item: (item["url"], item["method"]))
