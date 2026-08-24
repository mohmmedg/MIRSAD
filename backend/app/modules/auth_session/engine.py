"""Explicit authentication comparison engine.

Credentials are accepted for the duration of a request only and are never
returned, persisted, logged, or sent to AI analysis.
"""
from dataclasses import dataclass
from typing import Any
import httpx
from app.core.config import verify_target_in_scope
from urllib.parse import urljoin, urlparse

@dataclass(frozen=True)
class AuthProfile:
    name: str
    headers: dict[str, str]

    @classmethod
    def from_input(cls, name: str, auth_type: str, value: str | None = None, headers: dict[str, str] | None = None):
        h = dict(headers or {})
        t = auth_type.lower().strip()
        if t == "bearer" and value: h["Authorization"] = f"Bearer {value}"
        elif t == "basic" and value: h["Authorization"] = f"Basic {value}"
        elif t == "cookie" and value: h["Cookie"] = value
        elif t == "custom": pass
        elif t == "none": pass
        elif t not in {"bearer", "basic", "cookie", "custom", "none"}: raise ValueError("unsupported auth_type")
        return cls(name=name, headers=h)

@dataclass
class AuthComparison:
    endpoint: str
    unauthenticated: dict[str, Any]
    profiles: list[dict[str, Any]]
    differences: list[str]

async def compare_endpoint(endpoint: str, profiles: list[AuthProfile], timeout: float = 15.0) -> AuthComparison:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("endpoint must be a valid http/https URL")
    verify_target_in_scope(parsed.hostname)
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        async def fetch(headers: dict[str,str]):
            current = endpoint
            response = None
            for _ in range(6):
                p = urlparse(current)
                if p.scheme not in {"http", "https"} or not p.hostname:
                    raise ValueError("redirect target is not a valid http/https URL")
                verify_target_in_scope(p.hostname)
                response = await client.get(current, headers=headers)
                if not response.has_redirect_location:
                    break
                current = urljoin(current, response.headers["location"])
            if response is None:
                raise ValueError("endpoint request failed")
            return {"status": response.status_code, "content_type": response.headers.get("content-type", ""), "length": len(response.content)}
        unauth = await fetch({})
        results=[]
        for p in profiles:
            obs=await fetch(p.headers)
            results.append({"name":p.name, **obs})
    diffs=[]
    for p in results:
        if p["status"] != unauth["status"] or p["length"] != unauth["length"]:
            diffs.append(f"{p['name']}: unauth={unauth['status']}/{unauth['length']} auth={p['status']}/{p['length']}")
    return AuthComparison(endpoint, unauth, results, diffs)
