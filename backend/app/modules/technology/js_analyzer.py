import re
from urllib.parse import urljoin

ENDPOINT_PATTERNS = [
    re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|\.request)\s*\(\s*[`\"']([^`\"']+)", re.I),
    re.compile(r"[\"'`]((?:/|https?://)[^\"'`\s]{1,450}(?:api|graphql|swagger|openapi)[^\"'`]*)[\"'`]", re.I),
    re.compile(r"[\"'`]((?:/|https?://)[^\"'`\s]{1,450})[\"'`]", re.I),
]
WS_PATTERN = re.compile(r"\b(wss?://[^\"'`\s]+)", re.I)
SOURCEMAP_PATTERN = re.compile(r"sourceMappingURL=([^\s*]+)")
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"'][^\"']{12,}[\"']")),
]

def analyze_js(urls: list[str], bodies: list[str] | None = None):
    endpoints=set(); websockets=set(); secrets=[]; sourcemaps=[]; external=[]
    for url, body in zip(urls or [], bodies or []):
        text=body or ""
        for pat in ENDPOINT_PATTERNS:
            for match in pat.findall(text):
                value=match.strip()
                if len(value)<500:
                    endpoints.add(urljoin(url, value) if value.startswith("/") else value)
        websockets.update(WS_PATTERN.findall(text))
        for m in SOURCEMAP_PATTERN.findall(text): sourcemaps.append(urljoin(url,m))
        for label, pat in SECRET_PATTERNS:
            if pat.search(text): secrets.append({"type":label,"value":"<redacted>","source":url,"confidence":0.9 if label!="Generic secret assignment" else 0.72})
        for value in re.findall(r"https?://[^\"'`\s)]+", text, re.I):
            if urlparse_host(value) and urlparse_host(value) != urlparse_host(url): external.append(value[:500])
    return {
        "endpoints":sorted(endpoints)[:1000],
        "secret_indicators":secrets[:100],
        "websocket_candidates":sorted(websockets)[:200],
        "sourcemaps":sorted(set(sourcemaps))[:200],
        "external_urls":sorted(set(external))[:200],
        "assets_analyzed":len(bodies or []),
    }

def urlparse_host(value: str):
    try:
        from urllib.parse import urlparse
        return urlparse(value).hostname
    except Exception:
        return None
