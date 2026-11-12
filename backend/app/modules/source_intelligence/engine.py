from __future__ import annotations

import hashlib
from functools import lru_cache
import html
import ipaddress
import json
import os
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlparse

from app.core.request_budget import RequestBudget, RequestBudgetExceeded
from app.core.config import settings, verify_target_in_scope, resolve_safe_target
from app.modules.external_scanners.engines import run_source_detectors

import logging as _logging
logger = _logging.getLogger(__name__)


_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Generic secret assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"secret|password|passwd|private[_-]?key|webhook[_-]?secret)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
    )),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]
_COMMENT_INDICATORS = {
    "TODO", "FIXME", "DEBUG", "TEMP", "TEST", "INTERNAL", "STAGING", "DEV",
    "DEVELOPMENT", "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
    "PRIVATE", "ADMIN", "BACKUP", "REMOVE BEFORE PRODUCTION", "LOCALHOST",
    "INTERNAL URL", "HACK", "XXX",
}

@lru_cache(maxsize=8)
def _load_terms(filename: str, defaults_key: tuple[str, ...] = ()) -> set[str]:
    terms=set(defaults_key)
    candidates=[
        Path("/app/wordlists") / filename,
        Path(__file__).resolve().parents[3] / "wordlists" / filename,
    ]
    for path in candidates:
        try:
            if path.exists():
                for line in path.read_text(encoding="utf-8",errors="ignore").splitlines():
                    line=line.strip()
                    if line and not line.startswith("#"):
                        terms.add(line.upper()[:120])
                break
        except Exception:
            continue
    custom_root=Path("/app/wordlists/custom_user_wordlists")
    if custom_root.exists():
        try:
            for path in sorted(custom_root.glob("*.txt"))[:20]:
                for line in path.read_text(encoding="utf-8",errors="ignore").splitlines()[:10000]:
                    line=line.strip()
                    if line and not line.startswith("#"):
                        terms.add(line.upper()[:120])
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
    return terms


_DANGEROUS_SINKS = [
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("document.write", re.compile(r"\bdocument\.write\s*\(")),
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*=")),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*['\"`]")),
    ("setInterval(string)", re.compile(r"\bsetInterval\s*\(\s*['\"`]")),
]
_TECH_SIGNATURES = [
    ("Next.js", [r"/_next/", r"__NEXT_DATA__", r"next/static"]),
    ("Nuxt", [r"/_nuxt/", r"__NUXT__"]),
    ("React", [r"react(?:\.production|\.development)?(?:\.min)?\.js", r"data-reactroot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"]),
    ("Vue", [r"vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js", r"data-v-[a-f0-9]+", r"__VUE__"]),
    ("Angular", [r"ng-version=", r"angular(?:\.min)?\.js", r"__ngContext__"]),
    ("Svelte", [r"svelte", r"__svelte"]),
    ("Vite", [r"/@vite/client", r"vite/client", r"vite\.svg"]),
    ("Webpack", [r"webpackJsonp", r"webpackChunk", r"__webpack_require__"]),
    ("WordPress", [r"/wp-content/", r"/wp-includes/", r"wp-json"]),
    ("Drupal", [r"drupalSettings", r"/sites/default/files/"]),
    ("Laravel", [r"laravel_session", r"laravel_mix"]),
    ("Django", [r"csrfmiddlewaretoken", r"django"]),
    ("Rails", [r"actioncable", r"rails-ujs", r"_rails_session"]),
    ("Express", [r"x-powered-by:\s*express"]),
    ("nginx", [r"server:\s*nginx"]),
    ("Apache", [r"server:\s*apache"]),
    ("Cloudflare", [r"cf-ray", r"__cf_bm", r"cloudflare"]),
    ("Bootstrap", [r"bootstrap(?:\.bundle)?(?:\.min)?\.js", r"bootstrap(?:\.min)?\.css"]),
    ("jQuery", [r"jquery(?:\.min)?\.js", r"\bjQuery\b"]),
    ("GraphQL", [r"\bgraphql\b", r"/graphql(?:/|$)"]),
    ("REST", [r"\b(?:fetch|axios|XMLHttpRequest)\b", r"/api/(?:v\d+/)?"]),
    ("WebSocket", [r"\bWebSocket\s*\(", r"\bwss?://"]),
    ("Supabase", [r"supabase\.co", r"createClient\s*\("]),
    ("Firebase", [r"firebase(?:app|auth|firestore)", r"firebaseio\.com"]),
    ("AWS", [r"\bamazonaws\.com\b", r"\bAWS_(?:REGION|ACCESS|SECRET)\b"]),
    ("Azure", [r"\bazure(?:websites|staticapps|edge)\.net\b", r"AZURE_"]),
    ("GCP", [r"\bgoogleapis\.com\b", r"\bGCP_[A-Z_]"]),
]


def _docker_aware_request_url(url: str, hostname: str | None) -> str:
    """Rewrite a loopback hostname to host.docker.internal ONLY when actually running
    inside a container - the same /.dockerenv check external_scanners/engines.py already
    uses for this exact reason (engines.py:238). Without this guard, every 127.0.0.1/
    localhost fetch in this module (source maps, CSS/manifest/service-worker assets)
    unconditionally tried to resolve host.docker.internal even on bare-metal/non-Docker
    runs (e.g. plain pytest, or a non-containerized backend deployment), where that
    hostname does not exist - the request failed outright and was silently swallowed by
    the surrounding try/except, so this layer looked like it found nothing at all.
    """
    if hostname in {"127.0.0.1", "localhost"} and os.path.exists("/.dockerenv"):
        return url.replace(hostname, "host.docker.internal", 1)
    return url


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()


def _maybe_json(value: str):
    # Dedup round-trips dicts through json.dumps()/json.loads() to hash them
    # by content. A plain string that merely *starts* with "{" (a JS object
    # literal fragment, a path template, etc.) is not guaranteed to be valid
    # JSON, so json.loads() must never be allowed to raise here - one bad
    # element would otherwise abort the whole source-intelligence pass.
    if not (isinstance(value, str) and value.startswith("{")):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _redact(value: str, limit: int = 300) -> str:
    value = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(cookie\s*[:=]\s*)[^;\n]+(?:;[^\n]*)?", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*([:=])\s*(['\"]?)[^'\"\s,;]{6,}\3", r"\1\2[REDACTED]", value)
    return value[:limit]


def _safe_secret(text: str, match: re.Match[str]) -> dict:
    raw = match.group(0)
    label = "Secret"
    for name, pattern in _SECRET_PATTERNS:
        if pattern is pattern:
            label = name
    # Prefer the named detector based on the pattern that matched.
    label = next((name for name, pattern in _SECRET_PATTERNS if pattern.search(raw)), "Secret")
    return {
        "type": label,
        "fingerprint": _sha(raw),
        "evidence": _redact(raw, 180),
        "classification": "secret_candidate",
    }


class _HTMLIntelligenceParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.comments: list[dict] = []
        self.meta: list[dict] = []
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.iframes: list[str] = []
        self.objects: list[str] = []
        self.embeds: list[str] = []
        self.bases: list[str] = []
        self.hidden_inputs: list[dict] = []
        self.forms: list[dict] = []
        self.inline_handlers: list[dict] = []
        self.structured_data: list[dict] = []
        self._form: dict | None = None
        self._script_type: str | None = None
        self._script_buf: list[str] = []
        self._style_buf: list[str] = []
        self._in_style = False
        self.inline_scripts: list[str] = []
        self.inline_styles: list[str] = []

    def _abs(self, value: str) -> str:
        try:
            return urljoin(self.base_url, html.unescape(value.strip()))
        except Exception:
            return value.strip()

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        for key, value in d.items():
            if key.lower().startswith("on") and value:
                self.inline_handlers.append({"event": key.lower(), "evidence": _redact(value, 240)})
        if tag == "script":
            src = d.get("src")
            self._script_type = d.get("type", "").lower()
            self._script_buf = []
            if src:
                self.scripts.append(self._abs(src))
        elif tag == "style":
            self._style_buf = []
            self._in_style = True
        elif tag == "meta":
            if d.get("name") or d.get("property") or d.get("http-equiv") or d.get("content"):
                self.meta.append({"name": d.get("name"), "property": d.get("property"), "http_equiv": d.get("http-equiv"), "content": _redact(d.get("content",""), 300)})
        elif tag == "link" and d.get("href"):
            self.links.append(self._abs(d["href"]))
        elif tag == "iframe" and d.get("src"):
            self.iframes.append(self._abs(d["src"]))
        elif tag == "object" and d.get("data"):
            self.objects.append(self._abs(d["data"]))
        elif tag == "embed" and d.get("src"):
            self.embeds.append(self._abs(d["src"]))
        elif tag == "base" and d.get("href"):
            self.bases.append(self._abs(d["href"]))
        elif tag == "input":
            typ = d.get("type", "text").lower()
            if typ == "hidden":
                self.hidden_inputs.append({"name": d.get("name"), "value": _redact(d.get("value",""), 160)})
        elif tag == "form":
            self._form = {"action": self._abs(d.get("action", self.base_url)), "method": d.get("method","GET").upper(), "inputs": []}
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            self._form["inputs"].append({"name": d.get("name"), "type": d.get("type", tag), "value": _redact(d.get("value",""), 160)})
        elif tag == "script" and "ld+json" in d.get("type",""):
            self._script_type = "ld+json"
        elif tag == "link" and d.get("rel"):
            rel = d.get("rel","").lower()
            if "manifest" in rel:
                self.links.append(self._abs(d.get("href","")))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "script":
            text = "".join(self._script_buf)
            if text.strip():
                if self._script_type == "ld+json":
                    try:
                        self.structured_data.append(_redact_json_value(json.loads(text)))
                    except Exception:
                        self.structured_data.append({"_parse_error": True, "snippet": _redact(text, 300)})
                else:
                    self.inline_scripts.append(text[:2_000_000])
            self._script_buf = []
            self._script_type = None
        elif tag == "style":
            text = "".join(self._style_buf)
            if text.strip():
                self.inline_styles.append(text[:2_000_000])
            self._style_buf = []
            self._in_style = False
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data):
        if self._script_type is not None:
            self._script_buf.append(data)
        elif self._in_style:
            self._style_buf.append(data)

    def handle_comment(self, data):
        clean = " ".join(data.split())
        if clean:
            indicators = sorted({token for token in _load_terms("comments.txt", tuple(sorted(_COMMENT_INDICATORS))) if token in clean.upper()})[:30]
            self.comments.append({
                "text": _redact(clean, 500),
                "fingerprint": _sha(clean),
                "indicators": indicators,
                "classification": "suspicious" if indicators else "informational",
            })


def _redact_json_value(value, depth: int = 0):
    if depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if re.search(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|cookie|credential|private[_-]?key)", str(k)) else _redact_json_value(v, depth+1)) for k,v in list(value.items())[:1000]}
    if isinstance(value, list):
        return [_redact_json_value(v, depth+1) for v in value[:1000]]
    if isinstance(value, str):
        return _redact(value, 1000)
    return value


def _extract_urls(text: str, base_url: str) -> set[str]:
    out: set[str] = set()
    for raw in re.findall(r"""(?:(?:https?|wss?)://|/)[^\s"'`<>\\]{1,1000}""", text, re.I):
        raw = raw.rstrip(").,;]}\"'")
        if raw.startswith("/"):
            raw = urljoin(base_url, raw)
        if urlparse(raw).scheme in {"http","https","ws","wss"}:
            out.add(raw[:1000])
    return out


def _extract_api_paths(text: str, base_url: str) -> set[str]:
    out = set()
    patterns = [
        r"""(?i)(?:fetch|axios\.(?:get|post|put|patch|delete)|\.request|url|endpoint)\s*\(\s*['"`]([^'"`]+)""",
        r"""(?i)['"`]((?:/|https?://)[^'"`\s]{1,500}(?:api|graphql|swagger|openapi|rest|v\d+)[^'"`]*)['"`]""",
    ]
    for pattern in patterns:
        for raw in re.findall(pattern, text):
            if raw.startswith(("/", "http://", "https://")):
                out.add(urljoin(base_url, raw))
    for raw in re.findall(r"""['"`]((?:/|https?://)[^'"`\s]{1,500})['"`]""", text):
        if re.search(r"/(?:api|graphql|swagger|openapi|rest|v\d+)(?:/|$)", raw, re.I):
            out.add(urljoin(base_url, raw))
    return out


def _extract_comments(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"//[^\n\r]{0,500}|/\*[\s\S]{0,2000}?\*/", text):
        clean = re.sub(r"^\s*(?://|/\*|\*/)", "", m.group(0)).strip()
        indicators = sorted({token for token in _load_terms("comments.txt", tuple(sorted(_COMMENT_INDICATORS))) if token in clean.upper()})[:30]
        if clean:
            out.append({"text": _redact(clean,500), "fingerprint":_sha(clean), "indicators":indicators,
                        "classification":"suspicious" if indicators else "informational"})
    return out[:1000]


def _secret_candidates(text: str) -> list[dict]:
    found = []
    seen = set()
    for label, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0)
            fp = _sha(raw)
            if fp in seen:
                continue
            seen.add(fp)
            found.append({"type":label, "fingerprint":fp, "evidence":_redact(raw,180), "classification":"secret_candidate"})
            if len(found) >= 200:
                return found
    return found


def _technology_hits(text: str, headers: dict | None = None) -> list[dict]:
    corpus = text[:5_000_000]
    if headers:
        corpus += "\n" + "\n".join(f"{k}: {v}" for k,v in headers.items())
    hits=[]
    for name, patterns in _TECH_SIGNATURES:
        evidence=[]
        for pattern in patterns:
            m=re.search(pattern, corpus, re.I)
            if m:
                evidence.append(_redact(m.group(0),120))
        if evidence:
            confidence=min(0.98, 0.55+0.1*len(evidence))
            hits.append({"name":name,"confidence":round(confidence,2),"evidence":list(dict.fromkeys(evidence))[:5]})
    return hits


def _line_location(text: str, needle: str) -> int | None:
    pos=text.find(needle)
    return None if pos < 0 else text.count("\n",0,pos)+1


def _js_analysis(url: str, text: str) -> dict:
    endpoints=sorted(_extract_api_paths(text,url))[:2000]
    urls=sorted(_extract_urls(text,url))[:3000]
    websockets=sorted({x for x in urls if x.lower().startswith(("ws://","wss://"))})[:500]
    sinks=[]
    for name, pattern in _DANGEROUS_SINKS:
        for m in pattern.finditer(text):
            sinks.append({"sink":name,"line":text.count("\n",0,m.start())+1,"evidence":_redact(text[max(0,m.start()-100):m.end()+140],300)})
            if len(sinks)>=500: break
    storage=sorted(set(re.findall(r"\b(?:localStorage|sessionStorage|indexedDB|document\.cookie)\b",text,re.I)))
    env_refs=sorted(set(re.findall(r"\b(?:import\.meta\.env|process\.env|window\.__[A-Z0-9_]+__)\b",text,re.I)))[:300]
    cloud=sorted({name for name,_ in _TECH_SIGNATURES if name in {"Firebase","Supabase","AWS","Azure","GCP"} and any(re.search(p,text,re.I) for p in dict(_TECH_SIGNATURES)[name])})
    return {
        "url":url,"sha256":_sha(text),"bytes":len(text.encode("utf-8","ignore")),
        "endpoints":endpoints,"urls":urls,"websockets":websockets,
        "comments":_extract_comments(text),"secret_candidates":_secret_candidates(text),
        "dangerous_sinks":sinks,"storage_usage":storage,"environment_references":env_refs,
        "cloud_indicators":cloud,"source_map_urls":sorted(set(urljoin(url,x) for x in re.findall(r"sourceMappingURL\s*=\s*([^\s*]+)",text,re.I)))[:200],
    }


async def analyze_web_source(
    *,
    client,
    base_url: str,
    html_pages: list[tuple[str,str]],
    js_bodies: list[tuple[str,str]],
    headers: dict[str,str] | None = None,
    budget: RequestBudget | None = None,
    run_detectors: bool = False,
) -> dict:
    """Deep, bounded, passive source intelligence.

    The engine is enrichment-first: it records observations/assets and only
    emits security findings for contextual signals. Secrets are fingerprinted
    and redacted before persistence. Source maps are fetched only when the
    referenced map is same-origin and within the shared request/size budget.
    """
    budget = budget or RequestBudget()
    max_source = int(getattr(settings,"SOURCE_INTELLIGENCE_MAX_SOURCE_SIZE",5_000_000))
    max_map = int(getattr(settings,"SOURCE_INTELLIGENCE_MAX_MAP_SIZE",10_000_000))
    max_maps = int(getattr(settings,"SOURCE_INTELLIGENCE_MAX_SOURCE_MAPS",100))
    result={
        "enabled":bool(getattr(settings,"ENABLE_SOURCE_INTELLIGENCE",True)),
        "version":"1.0",
        "html":{"pages":0,"comments":[],"meta":[],"hidden_inputs":[],"forms":[],"scripts":[],"links":[],"iframes":[],"objects":[],"embeds":[],"bases":[],"inline_handlers":[],"structured_data":[]},
        "javascript":{"assets":[],"endpoints":[],"websockets":[],"secret_candidates":[],"dangerous_sinks":[],"comments":[],"storage_usage":[],"environment_references":[],"cloud_indicators":[],"source_maps":[]},
        "source_maps":{"maps_analyzed":[],"sources":[],"exposures":[],"secret_candidates":[],"endpoints":[]},
        "css":{"assets":[],"comments":[],"urls":[]},
        "manifests":{"assets":[],"entries":[]},
        "service_workers":{"assets":[],"registrations":[]},
        "json":{"documents":[],"keys":[],"endpoint_candidates":[]},
        "technologies":[],"assets":[],"findings":[],"warnings":[],"coverage":{},
    }
    detector_sources: list[tuple[str, str]] = []
    if not result["enabled"]:
        result["status"]="DISABLED"; return result

    try:
        # HTML/DOM intelligence.
        all_corpus=[]
        for page_url, body in html_pages[:1000]:
            text=(body or "")[:max_source]
            result["html"]["pages"]+=1
            all_corpus.append(text)
            # Equivalent of "View page source": the full served HTML is always available
            # for the Gitleaks/TruffleHog/Trivy snapshot, so source detectors never depend on
            # finding a public repository (e.g. on GitHub) for the target.
            if text.strip():
                detector_sources.append((page_url.split("#")[0]+"#page-source.html", text))
            stripped=text.lstrip()
            if stripped.startswith(("{","[")):
                try:
                    obj=json.loads(stripped)
                    result["json"]["documents"].append({"url":page_url,"sha256":_sha(text),"bytes":len(text.encode())})
                    if isinstance(obj,dict):
                        result["json"]["keys"].extend(list(obj.keys())[:1000])
                        result["json"]["endpoint_candidates"].extend(_extract_api_paths(json.dumps(obj),page_url))
                except Exception:
                    logger.debug("suppressed non-fatal error", exc_info=True)
            parser=_HTMLIntelligenceParser(page_url)
            try: parser.feed(text)
            except Exception as exc: result["warnings"].append(f"HTML parser warning: {type(exc).__name__}")
            for key, value in [
                ("comments",parser.comments),("meta",parser.meta),("hidden_inputs",parser.hidden_inputs),
                ("forms",parser.forms),("scripts",parser.scripts),("links",parser.links),
                ("iframes",parser.iframes),("objects",parser.objects),("embeds",parser.embeds),
                ("bases",parser.bases),("inline_handlers",parser.inline_handlers),
                ("structured_data",parser.structured_data),
            ]:
                result["html"][key].extend(value)
            for script in parser.inline_scripts:
                result["javascript"]["assets"].append({"url":page_url+"#inline-script","sha256":_sha(script),"bytes":len(script.encode()),"inline":True})
                detector_sources.append((page_url+"#inline.js", script))
                result["javascript"]["endpoints"].extend(_extract_api_paths(script,page_url))
                result["javascript"]["secret_candidates"].extend(_secret_candidates(script))
                result["javascript"]["comments"].extend(_extract_comments(script))
                result["javascript"]["dangerous_sinks"].extend(_js_analysis(page_url,script)["dangerous_sinks"])
                result["javascript"]["source_maps"].extend(_js_analysis(page_url,script)["source_map_urls"])
            for style in parser.inline_styles:
                result["assets"].append({"type":"css","url":page_url+"#inline-style","sha256":_sha(style),"bytes":len(style.encode())})
        parsed_base=urlparse(base_url)
        origin=(parsed_base.scheme,parsed_base.hostname,parsed_base.port or (443 if parsed_base.scheme=="https" else 80))
        # Fetch bounded same-origin passive assets referenced by HTML/JS:
        # CSS, web manifests, JSON documents and service workers. These requests
        # use the same httpx client/budget and never execute the downloaded code.
        passive_asset_urls=set()
        for page_url, body in html_pages[:1000]:
            parser=_HTMLIntelligenceParser(page_url)
            try: parser.feed((body or "")[:max_source])
            except Exception: continue
            for link in parser.links:
                if re.search(r"\.(?:css|json)(?:\?|$)", link, re.I) or "manifest" in link.lower():
                    passive_asset_urls.add(link)
            for inline in parser.inline_scripts:
                for raw in re.findall(r"""(?i)(?:serviceWorker\.register|importScripts)\s*\(\s*['"`]([^'"`]+)""", inline):
                    passive_asset_urls.add(urljoin(page_url, raw))
        for _, text in js_bodies[: int(getattr(settings,"SOURCE_INTELLIGENCE_MAX_JS_ASSETS",500))]:
            for raw in re.findall(r"""(?i)(?:serviceWorker\.register|importScripts)\s*\(\s*['"`]([^'"`]+)""", text or ""):
                passive_asset_urls.add(urljoin(base_url, raw))
            for raw in re.findall(r"""(?i)['"`]((?:/|https?://)[^'"`]{1,500}\.json(?:\?[^'"`]*)?)['"`]""", text or ""):
                passive_asset_urls.add(urljoin(base_url, raw))
        for asset_url in sorted(passive_asset_urls)[:200]:
            try:
                p=urlparse(asset_url)
                if (p.scheme,p.hostname,p.port or (443 if p.scheme=="https" else 80))!=origin:
                    continue
                verify_target_in_scope(p.hostname or ""); resolve_safe_target(p.hostname or "")
                request_url=_docker_aware_request_url(asset_url,p.hostname)
                r=await client.get(request_url,follow_redirects=False)
                if r.status_code>=400: continue
                data=r.content[:max_source].decode("utf-8","ignore")
                if data.strip():
                    detector_sources.append((asset_url, data))  # CSS/JSON/manifest/service-worker source
                if re.search(r"\.css(?:\?|$)",p.path,re.I):
                    result["css"]["assets"].append({"url":asset_url,"sha256":_sha(data),"bytes":len(data.encode())})
                    result["css"]["comments"].extend(_extract_comments(data)[:500])
                    result["css"]["urls"].extend(sorted(_extract_urls(data,asset_url))[:1000])
                elif "manifest" in p.path.lower():
                    result["manifests"]["assets"].append({"url":asset_url,"sha256":_sha(data),"bytes":len(data.encode())})
                    try:
                        obj=json.loads(data); result["manifests"]["entries"].append(_redact_json_value(obj) if isinstance(obj,dict) else {"value":_redact_json_value(obj)})
                    except Exception:
                        logger.debug("suppressed non-fatal error", exc_info=True)
                elif re.search(r"\.json(?:\?|$)",p.path,re.I):
                    result["json"]["documents"].append({"url":asset_url,"sha256":_sha(data),"bytes":len(data.encode())})
                    try:
                        obj=json.loads(data)
                        if isinstance(obj,dict):
                            result["json"]["keys"].extend(list(obj.keys())[:1000])
                            result["json"]["endpoint_candidates"].extend(_extract_api_paths(json.dumps(obj),asset_url))
                    except Exception:
                        logger.debug("suppressed non-fatal error", exc_info=True)
                if re.search(r"(?:service|sw)\.js(?:\?|$)",p.path,re.I) or "serviceworker" in data.lower():
                    result["service_workers"]["assets"].append({"url":asset_url,"sha256":_sha(data),"bytes":len(data.encode())})
                    result["service_workers"]["registrations"].extend(sorted(_extract_api_paths(data,asset_url))[:500])
            except RequestBudgetExceeded:
                result["warnings"].append("Passive asset analysis stopped by shared request budget"); break
            except Exception:
                continue

        # External JS intelligence.
        for url,text in js_bodies[: int(getattr(settings,"SOURCE_INTELLIGENCE_MAX_JS_ASSETS",500))]:
            text=(text or "")[:max_source]
            a=_js_analysis(url,text)
            detector_sources.append((url, text))
            result["javascript"]["assets"].append({"url":url,"sha256":a["sha256"],"bytes":a["bytes"],"inline":False})
            for k in ("endpoints","websockets","secret_candidates","dangerous_sinks","comments"):
                result["javascript"][k].extend(a[k] if isinstance(a[k],list) else [])
            result["javascript"]["source_maps"].extend(a.get("source_map_urls", []))
            all_corpus.append(text)

        # Source maps. Same-origin only; every request passes through the existing
        # target policy and the shared budget.
        map_urls=sorted(set(result["javascript"]["source_maps"]))
        for map_url in map_urls[:max_maps]:
            try:
                p=urlparse(map_url)
                if (p.scheme,p.hostname,p.port or (443 if p.scheme=="https" else 80))!=origin:
                    result["warnings"].append(f"Skipped cross-origin source map: {p.hostname or 'unknown'}"); continue
                verify_target_in_scope(p.hostname or "")
                resolve_safe_target(p.hostname or "")
                request_url = _docker_aware_request_url(map_url, p.hostname)
                r=await client.get(request_url, follow_redirects=False)
                raw=r.content[:max_map]
                if r.status_code>=400 or not raw: continue
                data=json.loads(raw.decode("utf-8","replace"))
                if not isinstance(data,dict): continue
                sources=data.get("sources") or []
                names=data.get("names") or []
                contents=data.get("sourcesContent") or []
                entry={"url":map_url,"sha256":hashlib.sha256(raw).hexdigest(),"sources_count":len(sources),"names_count":len(names),"has_sources_content":bool(contents)}
                result["source_maps"]["maps_analyzed"].append(entry)
                for src in sources[:5000]:
                    result["source_maps"]["sources"].append(_redact(str(src),500))
                if contents:
                    for idx,src_text in enumerate(contents[:500]):
                        src_text=(src_text or "")[:max_source]
                        src_name=str(sources[idx]) if idx < len(sources) else f"source-{idx}"
                        detector_sources.append((src_name, src_text))
                        result["source_maps"]["sources"].append(_redact(src_name,500))
                        result["source_maps"]["endpoints"].extend(_extract_api_paths(src_text,map_url))
                        result["source_maps"]["secret_candidates"].extend(_secret_candidates(src_text))
                        result["source_maps"]["exposures"].append({
                            "source":_redact(src_name,500),"sha256":_sha(src_text),"bytes":len(src_text.encode("utf-8","ignore")),
                            "classification":"original_source_exposed",
                            "evidence":_redact(src_text[:600],600),
                        })
                        all_corpus.append(src_text)
            except RequestBudgetExceeded:
                result["warnings"].append("Source-map analysis stopped by shared request budget"); break
            except Exception as exc:
                result["warnings"].append(f"Source-map analysis skipped: {type(exc).__name__}")

        # Deduplicate and technology correlation.
        corpus="\n".join(all_corpus)
        result["technologies"]=_technology_hits(corpus,headers)
        for key in ("comments","scripts","links","iframes","objects","embeds","bases"):
            result["html"][key]=list(dict.fromkeys(
                (json.dumps(x,sort_keys=True) if isinstance(x,dict) else str(x)) for x in result["html"][key]
            ))
            result["html"][key]=[_maybe_json(x) for x in result["html"][key]]
        for key in ("endpoints","websockets","storage_usage","environment_references","cloud_indicators","source_maps"):
            vals=result["javascript"].get(key,[])
            result["javascript"][key]=sorted(set(json.dumps(x,sort_keys=True) if isinstance(x,dict) else str(x) for x in vals))
            result["javascript"][key]=[_maybe_json(x) for x in result["javascript"][key]]
        for key in ("secret_candidates","dangerous_sinks","comments"):
            vals=result["javascript"][key]
            result["javascript"][key]=list({json.dumps(x,sort_keys=True):x for x in vals}.values())[:2000]
        for key in ("secret_candidates","endpoints","exposures","sources"):
            vals=result["source_maps"][key]
            result["source_maps"][key]=list(dict.fromkeys(json.dumps(x,sort_keys=True) if isinstance(x,dict) else str(x) for x in vals))
            result["source_maps"][key]=[_maybe_json(x) for x in result["source_maps"][key]][:5000]

        # Context-aware findings: observation first, vulnerability only when the
        # context supports it. A keyword alone is never promoted to High/Critical.
        for c in result["html"]["comments"]:
            if c.get("classification")=="suspicious":
                sev="Medium" if any(x in c.get("indicators",[]) for x in ("PASSWORD","SECRET","TOKEN","PRIVATE","INTERNAL URL")) else "Low"
                result["findings"].append({"source":"mirsad-source","category":"source_comment","title":"Suspicious Source Comment",
                    "severity":sev,"confidence":0.9 if c.get("indicators") else 0.6,"asset":base_url,
                    "evidence_redacted":c.get("text"),"context":c.get("indicators",[]),
                    "remediation":"Remove internal/debug comments and references that should not ship to production."})
        secrets=result["javascript"]["secret_candidates"]+result["source_maps"]["secret_candidates"]
        for s in list({json.dumps(x,sort_keys=True):x for x in secrets}.values())[:200]:
            result["findings"].append({"source":"mirsad-source","category":"secret_exposure","title":"Potential Secret Exposure",
                "severity":"High","confidence":0.82,"asset":base_url,"evidence_redacted":s.get("evidence"),
                "fingerprint":s.get("fingerprint"),"detectors":["native-source"],"remediation":"Revoke/rotate the credential if valid, remove it from client-delivered source, and move secret material server-side."})
        for sink in result["javascript"]["dangerous_sinks"][:500]:
            result["findings"].append({"source":"mirsad-source","category":"dangerous_dom_sink","title":f"Potential dangerous JavaScript sink: {sink['sink']}",
                "severity":"Info","confidence":0.55,"asset":base_url,"location":sink.get("line"),
                "evidence_redacted":sink.get("evidence"),"context":["requires-source-and-dataflow-validation"],
                "remediation":"Review the dataflow into this sink; use safe DOM APIs and contextual output encoding."})
        if result["source_maps"]["exposures"]:
            result["findings"].append({"source":"mirsad-source","category":"source_map_exposure","title":"Source Map Exposes Original Source",
                "severity":"Low","confidence":0.98,"asset":base_url,
                "evidence_redacted":_redact(str(result["source_maps"]["exposures"][0].get("source")),500),
                "remediation":"Remove production source maps or restrict their exposure if original source disclosure is not intended."})

        result["html"]["comments"]=result["html"]["comments"][:2000]
        result["html"]["meta"]=result["html"]["meta"][:2000]
        result["html"]["hidden_inputs"]=result["html"]["hidden_inputs"][:2000]
        result["html"]["forms"]=result["html"]["forms"][:1000]
        result["javascript"]["endpoints"]=result["javascript"]["endpoints"][:5000]
        result["javascript"]["websockets"]=result["javascript"]["websockets"][:1000]
        result["javascript"]["secret_candidates"]=list({json.dumps(x,sort_keys=True):x for x in result["javascript"]["secret_candidates"]}.values())[:500]
        result["javascript"]["dangerous_sinks"]=result["javascript"]["dangerous_sinks"][:1000]
        if run_detectors and detector_sources:
            try:
                result["detectors"] = await run_source_detectors(
                    detector_sources[: int(getattr(settings, "SOURCE_INTELLIGENCE_MAX_REPO_FILES", 2000))],
                    timeout_seconds=int(getattr(settings, "SOURCE_TOOL_TIMEOUT_SECONDS", 900)),
                )
                correlated = result["detectors"].get("correlated_secrets", [])
                for secret in correlated[:200]:
                    result["findings"].append({
                        "source":"gitleaks+trufflehog",
                        "category":"secret_exposure",
                        "title":"Correlated Secret Exposure",
                        "severity":"High","confidence":0.95,
                        "asset":str(secret.get("matched_at") or base_url),
                        "evidence_redacted":"REDACTED",
                        "fingerprint":secret.get("fingerprint"),
                        "detectors":secret.get("detectors",[]),
                        "remediation":"Rotate/revoke the credential if valid and remove it from client-delivered source.",
                    })
            except Exception as exc:
                _why=f"{type(exc).__name__}: {str(exc)[:200]}"
                result["detectors"]={n:{"status":"FAILED","findings":[],"reason":_why} for n in ("semgrep","gitleaks","trufflehog","trivy")}
                result["warnings"].append(f"Source detector layer failed: {type(exc).__name__}")

        result["coverage"]={
            "html_pages":result["html"]["pages"],"js_assets":len(js_bodies),
            "source_maps":len(result["source_maps"]["maps_analyzed"]),
            "technologies":len(result["technologies"]),
            "endpoints":len(set(result["javascript"]["endpoints"])),
            "secret_candidates":len(result["javascript"]["secret_candidates"])+len(result["source_maps"]["secret_candidates"]),
            "css_assets":len(result["css"]["assets"]),
            "json_documents":len(result["json"]["documents"]),
            "manifests":len(result["manifests"]["assets"]),
            "service_workers":len(result["service_workers"]["assets"]),
        }
        result["status"]="COMPLETED"
    except RequestBudgetExceeded:
        result["warnings"].append("Source intelligence stopped: shared request budget exhausted before analysis finished")
        result["status"] = "PARTIAL"
    except Exception as exc:
        import traceback
        # A single unexpected error used to wipe out this entire stage (the caller in
        # web_scan/scanner.py replaced the whole result with an empty FAILED dict).
        # Keep whatever was already gathered instead of throwing it away, and record
        # enough detail (exception type + short traceback) to actually diagnose it —
        # previously only the exception class name survived.
        result["warnings"].append(f"Source intelligence stopped early due to an unexpected error: {type(exc).__name__}: {str(exc)[:300]}")
        result["error_trace"] = traceback.format_exc(limit=6)
        has_partial_data = bool(
            result["html"]["pages"] or result["javascript"]["assets"] or
            result["technologies"] or result["source_maps"]["maps_analyzed"]
        )
        result["status"] = "PARTIAL" if has_partial_data else "FAILED"
    return result