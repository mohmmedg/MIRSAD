from __future__ import annotations
from app.core import execution_trace as _trace

import asyncio
import uuid
import logging
import json
import re
import hashlib
import os
import random
import shutil
import tempfile
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

from app.core.config import settings
from app.core.safety_policy import policy_for
from app.core.config import verify_target_in_scope, check_ssrf_risk, ScopeViolationError, SSRFRiskError
from app.modules.external_scanners.evasion import default_profile, EvasionProfile

# ════════════════════════════════════════════════════════════════════════════
# EVASION LAYER — تقنيات التخفي من جدران الحماية و IDS/IPS
# ════════════════════════════════════════════════════════════════════════════
# الهدف: جعل حركة الفحص أقل قابلية للكشف من قِبَل WAF/IDS/IPS.
# كل هذه التقنيات موثقة في أدوات اختبار الاختراق الرسمية (nmap, burpsuite,
# OWASP ZAP, metasploit) وهي جزء أساسي من أي اختبار اختراق مرخص.
# يجب استخدامها فقط على أهداف لديك تصريح خطي بفحصها.
# ════════════════════════════════════════════════════════════════════════════

# قائمة User-Agent حقيقية من متصفحات ومحركات بحث معروفة
# التنويع يمنع الـ WAF من تصفية الطلبات بناءً على UA ثابت
# Single source of truth for the User-Agent pool lives in evasion.py (was duplicated here).
from app.modules.external_scanners.evasion import _UA_POOL as _EVASION_USER_AGENTS

# تأخير عشوائي بين الطلبات (ثانية) — يعطي نمطاً بشرياً بدل آلي منتظم
_JITTER_MIN_S = float(getattr(settings, "EVASION_JITTER_MIN_S", "0.05"))
_JITTER_MAX_S = float(getattr(settings, "EVASION_JITTER_MAX_S", "0.35"))

def _random_ua() -> str:
    """إرجاع User-Agent عشوائي من القائمة."""
    return random.choice(_EVASION_USER_AGENTS)

async def _jitter() -> None:
    """تأخير عشوائي قصير لكسر الأنماط الآلية المنتظمة."""
    await asyncio.sleep(random.uniform(_JITTER_MIN_S, _JITTER_MAX_S))

def _evasion_headers() -> dict[str, str]:
    """ترويسات HTTP تجعل الطلبات تبدو أكثر طبيعية."""
    return {
        "User-Agent": _random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "ar,en;q=0.7"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }

def _build_evasion_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """متغيرات بيئة تُمرَّر للأدوات الفرعية لإخفاء هوية الماسح."""
    env = os.environ.copy()
    # بعض الأدوات تقرأ http_proxy/https_proxy تلقائياً إن كانت موجودة
    proxy = getattr(settings, "EVASION_HTTP_PROXY", "") or ""
    if proxy:
        env["http_proxy"] = proxy
        env["https_proxy"] = proxy
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy
    if extra_env:
        env.update(extra_env)
    return env



FINAL_TOOL_STATES = {"COMPLETED", "PARTIAL", "FAILED", "SKIPPED", "UNAVAILABLE"}
LEGACY_STATE_MAP = {"NOT_INSTALLED": "UNAVAILABLE", "NOT_CONFIGURED": "UNAVAILABLE", "DISABLED": "SKIPPED", "TIMEOUT": "PARTIAL"}

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

# ── Loopback → host alias resolution ────────────────────────────────────────
# A user-entered 127.0.0.1/localhost target means "a service on the machine
# running Docker", not the scanner container. `host.docker.internal` is the
# normal bridge, but it is not always reachable (missing extra_hosts, host
# firewall, Docker Desktop quirks). So we probe several candidate addresses
# with a plain TCP connect and use the first one that answers, caching it.
_LOOPBACK_CACHE: dict[int, tuple[float, str]] = {}
_LOOPBACK_OK_TTL = 120.0
_LOOPBACK_FAIL_TTL = 5.0


def _default_gateway_ip() -> str | None:
    """Docker bridge gateway (the host, on Linux) read from /proc/net/route."""
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            for line in fh.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000" and int(parts[3], 16) & 2:
                    raw = bytes.fromhex(parts[2])[::-1]
                    return ".".join(str(b) for b in raw)
    except (OSError, ValueError):
        pass
    return None


def _loopback_candidates() -> list[str]:
    cands = ["host.docker.internal"]
    gw = _default_gateway_ip()
    if gw:
        cands.append(gw)
    cands.append("172.17.0.1")
    # Last resort: the literal loopback address. Every candidate above is a Docker-only
    # path to reach the HOST from inside a container; running bare-metal (a plain dev
    # machine, CI, or `pytest` with no container at all), none of them exist, every probe
    # fails, and callers (e.g. request_budget.py's circuit breaker) saw 8 straight
    # connection failures against a target that was, in fact, up on 127.0.0.1 the whole
    # time. Each candidate is still verified with a real TCP connect below, so this only
    # wins when something is genuinely listening on the caller's own loopback.
    cands.append("127.0.0.1")
    seen: set[str] = set()
    return [c for c in cands if not (c in seen or seen.add(c))]


def resolve_loopback_host(port: int | None, *, force: bool = False) -> str:
    """Return a host alias that actually reaches the Docker host on `port`."""
    import socket
    key = int(port or 0)
    now = time.monotonic()
    cached = _LOOPBACK_CACHE.get(key)
    if cached and not force and cached[0] > now:
        return cached[1]
    probe_port = key or 80
    for cand in _loopback_candidates():
        try:
            with socket.create_connection((cand, probe_port), timeout=2.0):
                _LOOPBACK_CACHE[key] = (now + _LOOPBACK_OK_TTL, cand)
                return cand
        except OSError:
            continue
    # Nothing answered right now: keep the conventional alias, retry soon.
    _LOOPBACK_CACHE[key] = (now + _LOOPBACK_FAIL_TTL, "host.docker.internal")
    return "host.docker.internal"


def _auth_header_pairs(auth_header: str | None, cookie: str | None) -> list[tuple[str, str]]:
    """Operator-supplied credentials as (header, value) pairs, so every external
    engine tests the authenticated surface the same way the built-in scanner does.
    Values containing CR/LF are dropped (header-injection guard)."""
    pairs: list[tuple[str, str]] = []
    for name, value in (("Authorization", auth_header), ("Cookie", cookie)):
        v = str(value or "").strip()
        if v and "\r" not in v and "\n" not in v:
            pairs.append((name, v))
    return pairs


def normalize_engine_target(target: str) -> str:
    """Make a user-entered target reachable and meaningful for external engines.

    The scanner runs inside Docker, so 127.0.0.1/localhost would point to the
    scanner container itself (this is why sqlmap/ffuf/ZAP got "Connection
    refused" while the crawler, which already translates loopback, worked).
    The URL fragment ("#/", SPA routes) is never sent to a server, so keeping
    it only produces wrong URLs such as http://host/#/FUZZ.
    """
    try:
        p = urlparse(target)
    except ValueError:
        return target
    if not p.scheme or not p.netloc:
        return target
    netloc = p.netloc
    if (p.hostname or "") in _LOOPBACK_HOSTS:
        netloc = resolve_loopback_host(p.port) + (f":{p.port}" if p.port else "")
    return urlunparse(p._replace(netloc=netloc, fragment=""))


logger = logging.getLogger(__name__)

async def _preflight(target: str, timeout: float = 20.0, attempts: int | None = None) -> tuple[bool, str | None]:
    """Cheap reachability check so an engine fails fast instead of reporting
    COMPLETED after fuzzing/testing a target it could never reach.

    Retries with backoff: while Nuclei/ZAP/SQLMap saturate the host bridge
    (host.docker.internal on Docker Desktop) a single 8s probe used to time out
    and mark ffuf FAILED even though the target was fine a moment later.
    """
    if attempts is None:
        attempts = int(getattr(settings, "PREFLIGHT_ATTEMPTS", 2))
    # 2026-10-13: the orchestrator passes the raw user target (http://127.0.0.1:3000/#/). Inside the
    # container 127.0.0.1 is the container itself, so this gate failed with ConnectError for a target
    # the crawler had just reached, and ALL five external engines were skipped. Translate loopback
    # to the Docker-host alias (and drop the SPA fragment) exactly as the engines themselves do.
    target = normalize_engine_target(target)
    last = ""
    for i in range(max(1, attempts)):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                         verify=getattr(settings, "WEB_SCAN_VERIFY_TLS", True)) as c:
                await c.get(target)
            return True, None
        except httpx.HTTPError as exc:
            last = f"{type(exc).__name__}: {exc}"
            # If this was a Docker-host alias, re-probe the other candidate
            # addresses before the next attempt (the bridge may have changed).
            try:
                pp = urlparse(target)
                if pp.hostname in set(_loopback_candidates()):
                    alt = resolve_loopback_host(pp.port, force=True)
                    target = urlunparse(pp._replace(netloc=alt + (f":{pp.port}" if pp.port else "")))
            except ValueError:
                pass
            if i + 1 < attempts:
                await asyncio.sleep(min(30.0, 5.0 * (i + 1)))
    tried = ", ".join(_loopback_candidates())
    hint = ""
    try:
        if urlparse(target).hostname in set(_loopback_candidates()):
            hint = (f" | probed as {target}; docker-host candidates tried: {tried}. "
                    "Make sure the app listens on 0.0.0.0 (not only 127.0.0.1) and that the host firewall allows Docker.")
    except ValueError:
        pass
    return False, (f"target unreachable from the scanner container after {max(1, attempts)} attempt(s): {last}{hint}")[:600]


async def probe_target_reachability(target: str, *, tcp_timeout: float = 3.0, http_timeout: float = 8.0) -> dict:
    """Tell the operator, at the very start of a scan, whether the target is up and reachable
    FROM THE SCANNER CONTAINERS (not from the operator's browser).

    state: "up" | "port_closed" | "timeout" | "dns_failure" | "unchecked"
    Any HTTP response (even 404/500) counts as "up": the application is running.
    """
    import socket
    try:
        p = urlparse(target)
        port = p.port or (443 if p.scheme == "https" else 80)
        host = p.hostname or ""
    except ValueError:
        p, host, port = None, "", 0
    if p is None or p.scheme not in {"http", "https"} or not host:
        return {"checked": False, "reachable": None, "state": "unchecked", "target": target,
                "message_ar": "لم يُفحص الوصول (الهدف ليس رابط http/https)", "message_en": "Reachability not checked (not an http/https URL)"}
    is_loopback = host in _LOOPBACK_HOSTS
    candidates = _loopback_candidates() if is_loopback else [host]
    if is_loopback and not os.path.exists("/.dockerenv"):
        # Not inside a container (local dev run): loopback really is the machine running the app.
        candidates = [host] + candidates
    tried: list[dict] = []
    open_host = None
    for cand in candidates:
        started = time.monotonic()
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(cand, port), timeout=tcp_timeout)
            w.close()
            try: await w.wait_closed()
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
            tried.append({"host": cand, "result": "open", "ms": int((time.monotonic() - started) * 1000)})
            open_host = cand
            break
        except ConnectionRefusedError:
            tried.append({"host": cand, "result": "refused"})
        except (asyncio.TimeoutError, TimeoutError):
            tried.append({"host": cand, "result": "timeout"})
        except socket.gaierror:
            tried.append({"host": cand, "result": "dns_failure"})
        except OSError as exc:
            tried.append({"host": cand, "result": f"error:{type(exc).__name__}"})
    base = {"checked": True, "target": target, "port": port, "tried": tried}
    if open_host is None:
        results = {t["result"] for t in tried}
        where = "الجهاز المضيف (Docker host)" if is_loopback else host
        if results == {"dns_failure"}:
            return {**base, "reachable": False, "state": "dns_failure",
                    "message_ar": f"تعذّر تحليل اسم المضيف «{host}» من حاويات الفحص — تأكد من كتابته أو من DNS.",
                    "message_en": f"Hostname '{host}' cannot be resolved from the scanner containers."}
        if "timeout" in results and "refused" not in results:
            return {**base, "reachable": False, "state": "timeout",
                    "message_ar": f"انتهت مهلة الاتصال بالمنفذ {port} على {where} — غالبًا جدار ناري أو شبكة تحجب الوصول من حاويات الفحص.",
                    "message_en": f"Connection to port {port} on {where} timed out (firewall/network blocks the scanner containers)."}
        return {**base, "reachable": False, "state": "port_closed",
                "message_ar": (f"الهدف لا يعمل: لا يوجد أي تطبيق يستمع على المنفذ {port} على {where}. "
                               "شغّل الهدف أولًا، وإن كان يعمل فتأكد أنه يستمع على 0.0.0.0 وليس على 127.0.0.1 فقط."),
                "message_en": f"Target is down: nothing is listening on port {port} on {where}. Start it, and make sure it listens on 0.0.0.0, not only 127.0.0.1."}
    url = urlunparse(p._replace(netloc=open_host + (f":{p.port}" if p.port else ""), fragment=""))
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=http_timeout, follow_redirects=False, verify=False) as c:
            resp = await c.get(url, headers={"User-Agent": "MIRSAD-preflight"})
        ms = int((time.monotonic() - started) * 1000)
        return {**base, "reachable": True, "state": "up", "host_used": open_host, "http_status": resp.status_code, "latency_ms": ms,
                "message_ar": f"الهدف يعمل ويمكن الوصول إليه ✓ (HTTP {resp.status_code}، {ms}ms عبر {open_host}:{port})",
                "message_en": f"Target is up and reachable (HTTP {resp.status_code}, {ms}ms via {open_host}:{port})."}
    except httpx.HTTPError as exc:
        return {**base, "reachable": True, "state": "up", "host_used": open_host, "http_status": None,
                "message_ar": f"المنفذ {port} مفتوح لكن الرد على HTTP لم يكتمل ({type(exc).__name__}) — سيُكمل الفحص.",
                "message_en": f"Port {port} is open but the HTTP request did not complete ({type(exc).__name__}); continuing."}


_ENGINE_ARG_ERROR = re.compile(r"flag provided but not defined|unknown (flag|option)|unrecognized arguments|invalid (flag|argument)", re.I)


def _canonical_tool_status(status: str, *, has_output: bool = False) -> str:
    status = LEGACY_STATE_MAP.get(str(status).upper(), str(status).upper())
    if status == "FAILED" and has_output:
        return "PARTIAL"
    return status if status in FINAL_TOOL_STATES else "FAILED"

async def _run_process_streaming(binary: str, args: list[str], timeout_seconds: int, *, on_chunk=None, cwd: str | None = None, extra_env: dict[str, str] | None = None) -> tuple[int, str, str, str, float, str]:
    """Consume stdout/stderr concurrently; partial output survives timeout."""
    started=time.monotonic(); stdout_parts=[]; stderr_parts=[]; proc=None; readers=[]
    if not _available(binary): return -127,"","","UNAVAILABLE",0.0,"binary not found"
    async def consume(stream, name, parts):
        while True:
            chunk=await stream.readline()
            if not chunk: break
            value=chunk.decode("utf-8","replace"); parts.append(value)
            _trace.emit_output(name, value)
            if on_chunk:
                try:
                    result=on_chunk(name,value)
                    if asyncio.iscoroutine(result): await result
                except Exception as exc:
                    logger = __import__("logging").getLogger(__name__)
                    logger.exception("scanner output callback failed: %s", type(exc).__name__)
    try:
        _trace.emit_command([binary,*args],cwd=cwd,timeout=timeout_seconds)
        proc=await asyncio.create_subprocess_exec(binary,*args,cwd=cwd,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=_build_evasion_env(extra_env))
        readers=[asyncio.create_task(consume(proc.stdout,"stdout",stdout_parts)),asyncio.create_task(consume(proc.stderr,"stderr",stderr_parts))]
        try:
            # The deadline must cover both pipe consumption AND process exit.
            # A child can close stdout/stderr and keep running; waiting for it
            # after the readers finish without a timeout can hang the scan.
            await asyncio.wait_for(
                asyncio.gather(*readers, proc.wait()),
                timeout=max(1, int(timeout_seconds)),
            )
            state="COMPLETED" if proc.returncode==0 else "FAILED"
        except asyncio.TimeoutError:
            proc.kill(); await proc.wait(); await asyncio.gather(*readers,return_exceptions=True)
            state="PARTIAL" if stdout_parts or stderr_parts else "FAILED"
            _trace.emit_exit(binary,proc.returncode,time.monotonic()-started,state,"TIMEOUT")
            return proc.returncode if proc.returncode is not None else -124,"".join(stdout_parts),"".join(stderr_parts),state,time.monotonic()-started,"TIMEOUT"
        _trace.emit_exit(binary,proc.returncode,time.monotonic()-started,state)
        return proc.returncode,"".join(stdout_parts),"".join(stderr_parts),state,time.monotonic()-started,""
    except asyncio.CancelledError:
        # Job cancelled by the operator. CancelledError is a BaseException, so the generic
        # handler below never saw it and the external tool (ffuf/nuclei/zap/sqlmap/...) kept
        # running in the background after "Cancel". Kill it, then let the cancellation propagate.
        _trace.emit_exit(binary,None,time.monotonic()-started,"CANCELLED","CANCELLED")
        for r in readers: r.cancel()
        if proc is not None and proc.returncode is None:
            try: proc.kill()
            except ProcessLookupError: pass
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
            try: await asyncio.wait_for(asyncio.shield(proc.wait()),timeout=5)
            except BaseException: logger.debug("suppressed non-fatal error", exc_info=True)
        raise
    except Exception as exc:
        _trace.emit_exit(binary,None,time.monotonic()-started,"FAILED",str(exc)[:300])
        if proc is not None:
            try: proc.kill(); await proc.wait()
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        return -1,"".join(stdout_parts),"".join(stderr_parts),"FAILED",time.monotonic()-started,str(exc)[:1000]

_FFUF_CRITICAL = re.compile(r"(?:^|/)(?:\.git(?:/|$)|\.svn|\.hg|\.env(?:\.|$)|\.aws|\.ssh|id_rsa|\.htpasswd|wp-config|config\.php\.(?:bak|old|save|swp)|database\.sql|dump\.sql|\.sql(?:\.gz)?$|backup\.(?:zip|tar|gz|sql)|heapdump|actuator/(?:env|heapdump))", re.I)
_FFUF_HIGH = re.compile(r"(?:^|/)(?:phpinfo|phpmyadmin|adminer|server-status|server-info|jenkins|manager/html|console|debug|actuator|swagger|api-docs|graphql|\.DS_Store|backup|backups|old|bak|test|dev|staging|admin|administrator|wp-admin|cpanel)(?:/|\.|$)", re.I)

def _ffuf_severity(url: str, status) -> tuple[str, str]:
    """Classify a discovered path. A reachable (200/206) sensitive path is a real
    exposure; auth-gated (401/403) or redirected hits stay informational."""
    path = urlparse(str(url or "")).path or "/"
    ok = str(status) in {"200", "204", "206"}
    if _FFUF_CRITICAL.search(path):
        return ("High" if ok else "Info"), "sensitive-file-exposure"
    if _FFUF_HIGH.search(path):
        return ("Medium" if ok else "Info"), "exposed-administrative-or-debug-path"
    return "Info", "content-discovery"

def parse_ffuf_json(data: dict) -> list[dict]:
    out = []
    for i, item in enumerate(data.get("results") or []):
        sev, cat = _ffuf_severity(item.get("url"), item.get("status"))
        name = "Sensitive path exposed" if sev in {"High", "Medium"} else "Content discovery result"
        out.append({"name": name, "rule_id": f"FFUF-{cat.upper()}", "category": cat, "severity": sev,
                    "matched_at": item.get("url"),
                    "description": f"status={item.get('status')}; words={item.get('words')}; size={item.get('length')}",
                    "raw_locator": f"results[{i}]"})
    return out

def _zap_risk(value) -> str:
    try: return {0:"Info",1:"Low",2:"Medium",3:"High"}.get(int(str(value).split(".",1)[0]),"Info")
    except (TypeError,ValueError):
        first=str(value or "Info").strip().split()[0].split("(",1)[0].title()
        return first if first in {"Info","Low","Medium","High","Critical"} else "Info"

def parse_sqlmap_output(text: str, target: str) -> list[dict]:
    lines=text.splitlines(); findings=[]; current=None
    rx=re.compile(r"^\s*Parameter:\s*(.+?)\s*\((GET|POST|COOKIE|HEADER)\)\s*$",re.I)
    for line in lines:
        m=rx.search(line)
        if m:
            if current: findings.append(current)
            current={"parameter":m.group(1).strip(),"position":m.group(2).upper(),"type":None,"title":None,"payload":None,"matched_at":target,"severity":"High","name":"SQL injection reported by sqlmap","_evidence":[],"_start_line":len(findings) + 1}
            continue
        if not current: continue
        stripped=line.strip()
        for key in ("Type","Title","Payload","back-end DBMS"):
            prefix=key+":"
            if stripped.lower().startswith(prefix.lower()):
                val=stripped[len(prefix):].strip(); current[key.lower().replace("-", "_")]=val; current["_evidence"].append(stripped); break
    if current: findings.append(current)
    if not findings:
        # Fallback only for POSITIVE sqlmap verdict lines naming a parameter, e.g.
        #   GET parameter 'id' appears to be 'AND 1=1' injectable
        #   POST parameter 'q' might be injectable (possible DBMS: 'SQLite')
        # Negative verdicts ("does not seem to be injectable", "is not injectable",
        # "all tested parameters do not appear to be injectable") and the banner /
        # legal-disclaimer text must never become findings.
        pos=re.compile(r"(?P<pos>GET|POST|COOKIE|HEADER|URI|\(custom\) POST|\(custom\) GET)?\s*(?:parameter|header)\s+'(?P<param>[^']+)'\s+(?P<verdict>(?:appears to be|is|might be|seems to be)\b.*)$",re.I)
        neg=re.compile(r"\b(?:not|n't|no)\b",re.I)
        # sqlmap can retract its own early verdict (2026-11-01: "appears to be ... injectable" at 18:11:14, then
        # "parameter 'q' does not seem to be injectable" at 18:11:36 after confirmation failed). A FINAL negative
        # verdict for a parameter that comes AFTER its positive line cancels that positive. The "heuristic ...
        # might not be injectable" hint is only a pre-check, never a retraction.
        final_neg=re.compile(r"parameter\s+'(?P<param>[^']+)'\s+(?:does not seem to be|is not)\s+injectable",re.I)
        retracted_after={}
        for idx,ln in enumerate(lines):
            if "heuristic" in ln.lower():
                continue
            mn=final_neg.search(ln)
            if mn: retracted_after[mn.group("param").lower()]=idx
        seen=set()
        for idx,ln in enumerate(lines):
            m=pos.search(ln.strip())
            if not m: continue
            verdict=m.group("verdict")
            low=verdict.lower()
            if neg.search(verdict) or not ("injectable" in low or "vulnerable" in low): continue
            param=m.group("param"); key=param.lower()
            if retracted_after.get(key,-1)>idx: continue
            if key in seen: continue
            seen.add(key)
            maybe="might be" in low
            findings.append({"name":f"Possible SQL injection in parameter '{param}'" if maybe else f"SQL injection in parameter '{param}'",
                             "parameter":param,"position":(m.group("pos") or "").upper() or None,
                             "severity":"Medium" if maybe else "High","matched_at":target,"endpoint":target,
                             "confidence":0.55 if maybe else 0.8,"detected_only":maybe,
                             "_evidence":[ln.strip()]})
    for f in findings:
        f["description"]="\n".join(f.pop("_evidence",[])) or f.get("description","")
        f.setdefault("endpoint",target)
        f.setdefault("cwe","CWE-89")
        f.setdefault("solution","Use parameterized queries / prepared statements, validate input server-side, and run the database account with least privilege.")
        f["raw_locator"]=f"stdout:parameter:{f.get('parameter','')}"
        if "might be injectable" in f["description"].lower(): f["severity"]="Medium"; f["confidence"]=0.55; f["detected_only"]=True
    return findings

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def parse_ghauri_output(text: str, target: str) -> list[dict]:
    """Ghauri prints sqlmap-style result blocks ("Parameter: q (GET) / Type / Title / Payload") and the same
    "parameter 'q' appears to be ... injectable" / "does not seem to be injectable" verdict lines, so the
    sqlmap parser (including its retraction rule) is reused after stripping ANSI colour codes."""
    findings = parse_sqlmap_output(_ANSI_ESCAPE.sub("", text), target)
    for f in findings:
        f["detected_by"] = "ghauri"
        f["name"] = f.get("name", "").replace("reported by sqlmap", "reported by Ghauri")
    return findings


EXTERNAL_ENGINE_NAMES = ("nuclei", "zap", "sqlmap", "ghauri", "ffuf", "testssl")

MIRSAD_USER_AGENT = "MIRSAD-Scanner"

def _validate_new_engine_target(target: str) -> tuple[bool, str | None]:
    """Apply the same scope/SSRF gate used by the core assessment path."""
    try:
        verify_target_in_scope(target)
        check_ssrf_risk(target)
        return True, None
    except (ScopeViolationError, SSRFRiskError, ValueError) as exc:
        return False, str(exc)[:500]

def _severity_from_testssl(value) -> str:
    raw = str(value or "INFO").strip().upper()
    return {"CRITICAL":"Critical","HIGH":"High","MEDIUM":"Medium","LOW":"Low","WARN":"Low","WARNING":"Low"}.get(raw, "Info")


def _iter_testssl_records(node, inherited_host: str | None = None, inherited_port: int | None = None):
    """Yield flat finding records from both testssl JSON layouts."""
    if isinstance(node, list):
        for item in node:
            yield from _iter_testssl_records(item, inherited_host, inherited_port)
        return
    if not isinstance(node, dict):
        return
    host = str(node.get("targetHost") or node.get("host") or node.get("hostname") or inherited_host or "")
    port_raw = node.get("port") or inherited_port
    try: port = int(port_raw) if port_raw is not None else None
    except (TypeError, ValueError): port = inherited_port
    severity = str(node.get("severity") or node.get("severityLevel") or node.get("level") or "").upper()
    finding = node.get("finding") or node.get("result") or node.get("value") or node.get("findingValue")
    ident = node.get("id") or node.get("findingName") or node.get("parameter") or node.get("name")
    if severity and finding is not None:
        yield {"id": ident, "severity": severity, "finding": str(finding), "host": host, "port": port,
               "cve": node.get("cve"), "cwe": node.get("cwe"), "reference": node.get("reference") or node.get("references")}
    for key, value in node.items():
        if key in {"severity", "severityLevel", "level", "finding", "result", "value", "findingValue", "id", "findingName", "parameter", "name", "cve", "cwe", "reference", "references"}:
            continue
        yield from _iter_testssl_records(value, host, port)


def parse_testssl_json(data) -> list[dict]:
    """Parse testssl flat JSON and jsonfile-pretty/nested JSON."""
    findings=[]
    for i,item in enumerate(_iter_testssl_records(data)):
        severity_raw=str(item.get("severity") or "INFO").upper()
        if severity_raw in {"OK","INFO","DEBUG",""}:
            continue
        host=str(item.get("host") or "")
        port=item.get("port")
        matched_at=f"{host}:{port}" if host and port else host or "tls"
        ident=str(item.get("id") or "TLS-CONFIG")[:200]
        reference=item.get("reference")
        if isinstance(reference, list): reference=reference[0] if reference else None
        findings.append({
            "name": ident,
            "severity": _severity_from_testssl(severity_raw),
            "category": "tls-configuration",
            "matched_at": matched_at,
            "host": host,
            "port": port,
            "description": str(item.get("finding") or ident)[:4000],
            "cve": item.get("cve"),
            "cwe": item.get("cwe"),
            "remediation": "Review the reported TLS configuration and disable weak or obsolete protocol, cipher, certificate, or server settings as appropriate.",
            "reference": reference,
            "rule_id": f"testssl:{ident}",
            "tags": ["tls", "testssl"],
            "raw_locator": f"record:{i}",
        })
    return findings


async def run_testssl(target: str, *, safe_mode: str = "safe", scan_profile: str = "standard", timeout_seconds: int | None = None, on_chunk=None) -> dict:
    target = normalize_engine_target(target)
    if not settings.ENABLE_TESTSSL:
        return {"status":"DISABLED","reason":"ENABLE_TESTSSL=false","findings":[]}
    binary=settings.TESTSSL_BINARY_PATH
    if not _available(binary):
        return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    parsed=urlparse(target if "://" in target else "https://"+target)
    if parsed.scheme.lower() != "https":
        return {"status":"NOT_TESTED","binary":binary,"findings":[],"reason":"testssl requires an HTTPS target"}
    host=parsed.hostname or ""
    port=parsed.port or 443
    if not host or host.startswith("-") or not (1 <= int(port) <= 65535):
        return {"status":"FAILED","binary":binary,"findings":[],"reason":"invalid host/port"}
    ok, reason = _validate_new_engine_target(host)
    if not ok:
        return {"status":"FAILED","binary":binary,"findings":[],"reason":reason}
    version=await _binary_version(binary,["--version"])
    with tempfile.NamedTemporaryFile(prefix="mirsad-testssl-",suffix=".json",delete=False) as fh: output=fh.name
    args=["--jsonfile",output,"--warnings","batch","--color","0","--quiet","--connect-timeout","10","--openssl-timeout","10"]
    # TLS configuration checks are non-destructive. Keep the fast subset for
    # passive/quick profiles, but let standard/deep/maximum run the complete
    # testssl catalogue even in safe mode; safe mode must not silently erase
    # the coverage requested by the selected scan profile.
    profile = str(scan_profile or "standard").strip().lower()
    if profile not in {"passive", "quick", "standard", "deep", "maximum"}:
        profile = "standard"
    if policy_for(safe_mode).mode == "safe" and profile in {"passive", "quick"}:
        args.append("--fast")
    args.append(f"{host}:{port}")
    try:
        # 2026-10-09: testssl.sh's internal MAX_SOCKET_FAIL defaults to 2 and
        # aborts the ENTIRE run ("Fatal error: repeated TCP connect problems
        # ... giving up") the moment a couple of probes hit a connect timeout —
        # which happens routinely against a subdomain that is flaky, rate
        # limiting, or just slow, and previously turned the whole TLS
        # assessment into a PARTIAL with zero findings instead of tolerating
        # a few bad probes among the hundreds testssl makes. testssl.sh reads
        # this as an environment variable override, so raise it instead of
        # giving up after two failures.
        rc,out,err,state,duration,reason=await _run_process_streaming(binary,args,int(timeout_seconds or settings.TESTSSL_TIMEOUT_SECONDS),on_chunk=on_chunk,extra_env={"MAX_SOCKET_FAIL": str(int(getattr(settings,"TESTSSL_MAX_SOCKET_FAIL",8)))})
        raw_file = ""
        data=None
        try:
            raw_file=Path(output).read_text(encoding="utf-8",errors="replace")
            data=json.loads(raw_file)
        except Exception as exc:
            # The raw file is evidence even when its JSON is malformed/partial.
            if raw_file:
                reason = reason or f"testssl JSON parse failed: {type(exc).__name__}"
            try:
                data=json.loads(out) if out else []
            except Exception:
                data=[]
        findings=parse_testssl_json(data)
        if reason=="TIMEOUT": state="PARTIAL"
        status=_canonical_tool_status(state,has_output=bool(out or err or raw_file or findings))
        return {"status":status,"binary":binary,"version":version,"findings":findings,
                "stdout":out,"stderr":err,"raw_json":data,"raw_output":raw_file or out,
                "raw_file":raw_file,"exit_code":rc,"duration_seconds":duration,
                "reason":reason or (err[-500:] if rc not in (0,None) else None),
                "tls_snapshot":data}
    finally:
        try: Path(output).unlink()
        except OSError: pass

async def run_subfinder_source(base_domain: str, *, timeout_seconds: int | None = None) -> dict[str,dict]:
    if not settings.ENABLE_SUBFINDER: return {}
    base=str(base_domain or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",base): return {}
    binary=settings.SUBFINDER_BINARY_PATH
    if not _available(binary): return {}
    ok, _reason = _validate_new_engine_target(base)
    if not ok and settings.ENFORCE_TARGET_SCOPE: return {}
    args=["-d",base,"-silent","-json","-max-time",str(max(1,int(settings.SUBFINDER_MAX_TIME_MINUTES))),"-timeout",str(max(1,int(settings.SUBFINDER_TIMEOUT_SECONDS)))]
    rc,out,err,state,_,_=await _run_process_streaming(binary,args,int(timeout_seconds or settings.SUBFINDER_MAX_TIME_MINUTES*60))
    found={}
    for line in out.splitlines():
        try: item=json.loads(line)
        except Exception: continue
        host=str(item.get("host") or item.get("subdomain") or "").strip().lower().rstrip(".")
        if not host or "*" in host or host==base or not host.endswith("."+base): continue
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"+re.escape(base),host): continue
        found[host]={"hostname":host,"method":"Passive subdomain enumeration","source":"Subfinder","evidence":"Subfinder passive source"}
    return found

async def run_httpx_probe(hosts: list[str], *, safe_mode: str = "safe", base_domain: str | None = None, timeout_seconds: int | None = None) -> dict:
    if not settings.ENABLE_HTTPX_PROBE: return {"status":"DISABLED","hosts":[],"enrichment":{}}
    binary=settings.HTTPX_BINARY_PATH
    if not _available(binary): return {"status":"UNAVAILABLE","binary":binary,"hosts":[],"enrichment":{},"reason":"binary not found"}
    accepted=[]
    max_hosts=max(0,int(settings.HTTPX_MAX_HOSTS))
    base=(str(base_domain or "").lower().rstrip(".")) or None
    for raw in hosts:
        host=str(raw or "").strip().lower().rstrip(".")
        if not host or host.startswith("-"): continue
        if base and host != base and not host.endswith("." + base): continue
        ok, _reason=_validate_new_engine_target(host)
        if not ok:
            # If the discovered host is inside the already-authorized target base,
            # preserve the same SSRF gate while allowing the parent scope to authorize it.
            if not (base and settings.ENFORCE_TARGET_SCOPE and host != base and host.endswith("." + base)):
                continue
            try: check_ssrf_risk(host)
            except SSRFRiskError: continue
        accepted.append(host)
        if len(accepted) >= max_hosts: break
    if not accepted: return {"status":"NOT_TESTED","binary":binary,"hosts":[],"enrichment":{}}
    fd,path=tempfile.mkstemp(prefix="mirsad-httpx-",suffix=".txt"); os.close(fd)
    try:
        Path(path).write_text("\n".join(accepted)+"\n",encoding="utf-8")
        policy=policy_for(safe_mode)
        rate_limit=max(1,int(getattr(settings,"REQUESTS_PER_SECOND",5)))
        args=["-l",path,"-json","-silent","-status-code","-title","-tech-detect","-web-server","-ip","-follow-redirects","-timeout","10","-retries","1","-rate-limit",str(rate_limit),"-H",f"User-Agent: {MIRSAD_USER_AGENT}"]
        rc,out,err,state,_,reason=await _run_process_streaming(binary,args,int(timeout_seconds or settings.HTTPX_TIMEOUT_SECONDS))
        enrichment={}
        for line in out.splitlines():
            try: item=json.loads(line)
            except Exception: continue
            url=str(item.get("url") or item.get("input") or "")
            host=urlparse(url).hostname or str(item.get("host") or item.get("input") or "").lower().rstrip(".")
            if host not in accepted: continue
            enrichment[host]={
                "host":host,"url":url,"alive":bool(item.get("status_code") or item.get("url")),
                "status_code":item.get("status_code"),"title":item.get("title"),
                "technologies":item.get("tech") or item.get("technologies") or [],
                "web_server":item.get("webserver") or item.get("web_server"),"ip":item.get("a") or item.get("ip"),
            }
        return {"status":_canonical_tool_status(state,has_output=bool(out or err)),"binary":binary,"hosts":accepted,"enrichment":enrichment,"stdout":out,"stderr":err,"exit_code":rc,"reason":reason or None}
    finally:
        try: Path(path).unlink()
        except OSError: pass

def _available(binary: str) -> bool:
    return bool(shutil.which(binary) or Path(binary).exists())

async def _binary_version(binary: str, args: list[str] | None = None) -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(binary, *(args or ["--version"]), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=10)
        text=(out+err).decode("utf-8","ignore").strip()
        return text[:1000] or None
    except Exception:
        return None


# Tags that only make sense for one product. They are dropped when technology detection ran
# (non-empty fingerprint) and did NOT see that product; with no fingerprint nothing is dropped,
# so detection failure can never reduce coverage. Product tags for detected technologies are added.
_NUCLEI_TECH_ONLY_TAGS = {"wordpress": {"wordpress", "wp-plugin", "wp-theme", "wp"}}
_NUCLEI_TECH_TAG_MAP = {
    "drupal": "drupal", "laravel": "laravel", "django": "django", "rails": "rails", "next.js": "nextjs",
    "node.js": "nodejs", "express": "nodejs", "nginx": "nginx", "apache": "apache", "graphql": "graphql",
    "jquery": "jquery", "angular": "angular", "react": "react", "vue": "vue", "wordpress": "wordpress",
}


def nuclei_tags_for(base_tags: str, detected_tech: list[str] | None) -> str:
    tags = [t for t in (base_tags or "").split(",") if t]
    tech = {str(x).lower() for x in (detected_tech or [])}
    if tech:
        for product, product_tags in _NUCLEI_TECH_ONLY_TAGS.items():
            if product not in tech:
                tags = [t for t in tags if t not in product_tags]
        for name, tag in _NUCLEI_TECH_TAG_MAP.items():
            if name in tech and tag not in tags:
                tags.append(tag)
    return ",".join(tags)


def _nuclei_template_count(template_root: Path = Path("/opt/nuclei-templates")) -> int:
    """Count installed Nuclei templates; an empty tree is not a successful scan."""
    if not template_root.is_dir():
        return 0
    return sum(1 for _ in template_root.rglob("*.yaml"))


async def run_nuclei(target: str, *, safe_mode: str, detected_tech: list[str] | None = None, scan_profile: str = "standard", rate_limit: int, timeout_seconds: int, evasion: EvasionProfile | None = None, on_chunk=None, auth_header: str | None = None, cookie: str | None = None) -> dict:
    started=time.time()
    target = normalize_engine_target(target)
    if not settings.ENABLE_NUCLEI: return {"status":"SKIPPED","reason":"ENABLE_NUCLEI=false","findings":[]}
    binary=settings.NUCLEI_BINARY_PATH
    if not _available(binary): return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    policy=policy_for(safe_mode); ev=evasion or default_profile(safe_mode,scan_profile); version=await _binary_version(binary,["-version"])
    template_root=Path("/opt/nuclei-templates"); template_count=_nuclei_template_count(template_root)
    if template_count == 0:
        return {"status":"UNAVAILABLE","binary":binary,"version":version,"template_count":0,
                "findings":[],"reason":f"Nuclei templates are missing or empty: {template_root}; rebuild the scanner image with its pinned templates."}
    await asyncio.sleep(ev.jitter_seconds())
    args=["-u",target,"-jsonl","-no-color","-silent","-rate-limit",str(max(1,rate_limit)),"-concurrency",str(max(1,int(getattr(settings,"NUCLEI_CONCURRENCY",15)))),"-templates","/opt/nuclei-templates"]+ev.nuclei_flags()  # nuclei does not follow redirects by default; "-no-redirects" is not a valid flag in v3
    allowed_tags=",".join(x.strip() for x in str(getattr(settings,"NUCLEI_ALLOWED_TAGS","")).split(",") if x.strip() and re.fullmatch(r"[A-Za-z0-9_.-]+",x.strip()))
    allowed_tags=nuclei_tags_for(allowed_tags,detected_tech)
    if allowed_tags: args += ["-tags",allowed_tags]
    # `fuzz`/DAST templates only send read-only canaries (reflected XSS/SQLi error
    # probes), so they run in every mode; truly intrusive classes stay gated.
    if not policy.allow_intrusive_template_tags: args += ["-exclude-tags","dos,intrusive,bruteforce,brute-force"]
    for _h, _v in _auth_header_pairs(auth_header, cookie): args += ["-H", f"{_h}: {_v}"]
    try:
        hp=await asyncio.create_subprocess_exec(binary,"-help",stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=ev.env()); ho,he=await asyncio.wait_for(hp.communicate(),timeout=10); ht=(ho+he).decode("utf-8","ignore")
        if "-dast" in ht: args.append("-dast")
        if "-include-rr" in ht: args.append("-include-rr")
        elif "-irr" in ht: args.append("-irr")
    except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
    ok_reach, reach_reason = await _preflight(target)
    if not ok_reach:
        return {"status":"FAILED","binary":binary,"version":version,"template_count":template_count,"findings":[],"reason":reach_reason}
    rc,out,err,state,duration,reason=await _run_process_streaming(binary,args,timeout_seconds,on_chunk=on_chunk)
    if rc not in (0,None) and _ENGINE_ARG_ERROR.search(out+"\n"+err):
        first=(out+err).strip().splitlines()[0][:300] if (out+err).strip() else "invalid nuclei arguments"
        return {"status":"FAILED","binary":binary,"version":version,"template_count":template_count,"findings":[],"stdout":out,"stderr":err,"exit_code":rc,"reason":"nuclei rejected its command line: "+first}
    findings=[]; parser_errors=[]
    for line_no,line in enumerate(out.splitlines(),1):
        if not line.strip(): continue
        try: item=json.loads(line)
        except Exception as exc: parser_errors.append({"line":line_no,"reason":str(exc)}); continue
        info=item.get("info") or {}; findings.append({"template_id":item.get("template-id") or item.get("template_id"),"name":info.get("name") or item.get("template-id") or "Nuclei finding","severity":str(info.get("severity","info")).title(),"matched_at":item.get("matched-at") or item.get("matched_at") or item.get("host") or target,"type":item.get("type"),"matcher_name":item.get("matcher-name"),"description":info.get("description"),"solution":info.get("remediation"),"reference":info.get("reference"),"classification":info.get("classification") or {},"request":item.get("request"),"response":item.get("response"),"raw_locator":f"line:{line_no}"})
    if reason=="TIMEOUT" or parser_errors: state="PARTIAL"
    finished=time.time(); return {"status":_canonical_tool_status(state,has_output=bool(out or err)),"binary":binary,"version":version,"template_count":template_count,"findings":findings,"stdout":out,"stderr":err,"parser_errors":parser_errors,"started_at":started,"finished_at":finished,"duration_seconds":finished-started,"exit_code":rc,"reason":reason or (err[-500:] if rc not in (0,None) else None)}


async def run_zap(target: str, *, safe_mode: str, scan_profile: str = "standard", timeout_seconds: int, evasion: EvasionProfile | None = None, on_chunk=None, seed_urls: list[str] | None = None, auth_header: str | None = None, cookie: str | None = None) -> dict:
    """Run a ZAP scan against target.

    Primary path: the `zap` daemon service (docker-compose.yml), reached via
    ZAP_SERVICE_URL over its REST API — this is what "maximum"/destructive
    scans actually use, including a real active scan (see run_zap_service).
    Fallback path: a locally installed ZAP CLI binary, if someone has put one
    on PATH themselves (not installed by this project's Dockerfile — see the
    note there). Kept only for people who set ZAP_BINARY_PATH to their own
    working install; degrades to NOT_INSTALLED otherwise, same as before.
    """
    target = normalize_engine_target(target)
    if not settings.ENABLE_ZAP:
        return {"status": "DISABLED", "reason": "ENABLE_ZAP=false", "findings": []}
    policy = policy_for(safe_mode)
    if getattr(settings, "ZAP_SERVICE_URL", ""):
        return await run_zap_service(target, safe_mode=safe_mode, scan_profile=scan_profile,
                                      timeout_seconds=timeout_seconds, active=(policy.mode in {"caution", "destructive"}), seed_urls=seed_urls, auth_header=auth_header, cookie=cookie)
    binary = settings.ZAP_BINARY_PATH
    if policy.allow_intrusive_template_tags:
        if Path(binary).name.startswith("zap-baseline"):
            binary = binary.replace("zap-baseline", "zap-full-scan")
        elif "baseline" in Path(binary).name:
            binary = binary.replace("baseline", "full-scan")
    else:
        if "full-scan" in Path(binary).name:
            binary = binary.replace("full-scan", "baseline")
    if not _available(binary):
        return {"status": "UNAVAILABLE", "binary": binary, "findings": [], "reason":"binary not found"}
    version = await _binary_version(binary)
    with tempfile.NamedTemporaryFile(prefix="mirsad-zap-", suffix=".json", delete=False) as fh:
        output = fh.name
    try:
        # Evasion: جيتر قبل ZAP وإضافة UA مخصص
        ev = evasion or default_profile(safe_mode, scan_profile)
        import asyncio as _asyncio_zap
        await _asyncio_zap.sleep(ev.jitter_seconds())
        ua = ev.random_ua()
        args = [binary, "-t", target, "-J", output, "-config", "connection.followRedirects=false", "-config", f"replacer.full_list(0).matchtype=REQ_HEADER",
                "-config", f"replacer.full_list(0).matchstr=User-Agent",
                "-config", f"replacer.full_list(0).replacement={ua}"]
        rc_stream, out_text, err_text, state_stream, duration_stream, reason_stream = await _run_process_streaming(args[0], args[1:], timeout_seconds, on_chunk=on_chunk)
        data = {}
        try:
            data = json.loads(Path(output).read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            data = {}
        findings=[]
        for site in data.get("site", []) if isinstance(data, dict) else []:
            for alert in site.get("alerts", []) if isinstance(site, dict) else []:
                findings.append({
                    "plugin_id": alert.get("pluginid"), "name": alert.get("name", "ZAP alert"),
                    "risk": _zap_risk(alert.get("riskcode") if alert.get("riskcode") is not None else alert.get("riskdesc")),
                    "riskcode": alert.get("riskcode"), "riskdesc": alert.get("riskdesc"),
                    "confidence": alert.get("confidence"), "url": alert.get("url") or site.get("@name"),
                    "param": alert.get("param"), "evidence": alert.get("evidence"),
                    "description": alert.get("desc"), "solution": alert.get("solution"),
                    "reference": alert.get("reference"), "cwe": alert.get("cweid"),
                })
        stderr_text = err_text
        raw_report = Path(output).read_bytes() if Path(output).exists() else b""
        result = {"status": "COMPLETED" if rc_stream in (0,2) and not reason_stream else "PARTIAL", "binary": binary, "version": version,
                "findings": findings, "stdout": out_text, "stderr": stderr_text, "raw_report": raw_report, "started_at": None, "finished_at": None, "duration_seconds": duration_stream, "exit_code": rc_stream}
        if rc_stream != 0 or reason_stream: result["reason"] = reason_stream or stderr_text[-500:] or f"zap exited with code {rc_stream}"
        return result
    except asyncio.TimeoutError:
        return {"status":"PARTIAL","binary":binary,"findings":[],"reason":"TIMEOUT"}
    except Exception as exc:
        return {"status":"FAILED","binary":binary,"findings":[],"stderr":str(exc)[:1000]}
    finally:
        try: os.unlink(output)
        except OSError: pass

async def _run_process(binary: str, args: list[str], timeout_seconds: int, *, on_chunk=None) -> tuple[int, str, str, str]:
    """Compatibility wrapper around the live streaming process runner.

    Older callers still receive the historical four-tuple, but stdout/stderr are
    consumed incrementally so a timeout cannot erase output already produced.
    """
    rc, out, err, state, _duration, reason = await _run_process_streaming(
        binary, args, timeout_seconds, on_chunk=on_chunk
    )
    if state == "UNAVAILABLE":
        state = "UNAVAILABLE"
    elif state == "PARTIAL" and not reason:
        reason = "partial process output preserved"
    return rc, out, err or reason, state


async def run_sqlmap(target: str, *, safe_mode: str, scan_profile: str = "standard", timeout_seconds: int, destructive_confirmation: bool = False, evasion: EvasionProfile | None = None, on_chunk=None, data: str | None = None, extra_args: list[str] | None = None, auth_header: str | None = None, cookie: str | None = None) -> dict:
    started=time.time()
    target = normalize_engine_target(target)
    if not settings.ENABLE_SQLMAP: return {"status":"SKIPPED","reason":"ENABLE_SQLMAP=false","findings":[]}
    binary=settings.SQLMAP_BINARY_PATH
    if not _available(binary): return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    version=await _binary_version(binary,["--version"]); ev=evasion or default_profile(safe_mode,scan_profile); await asyncio.sleep(ev.jitter_seconds())
    ok_reach, reach_reason = await _preflight(target)
    if not ok_reach:
        return {"status":"FAILED","binary":binary,"version":version,"findings":[],"reason":reach_reason}
    output_dir=tempfile.mkdtemp(prefix="mirsad-sqlmap-")
    # --timeout/--retries/--time-sec raise sqlmap's own tolerance for a lagging or briefly
    # unreachable target above its stock defaults (30s/3/5s). sqlmap's own CRITICAL output
    # ("considerable lagging has been detected... use as high value for --time-sec as possible")
    # was asking for exactly this (2026-11-02 incident). Does not change detection logic.
    args=["-u",target]+(["--data",data] if data else [])+list(extra_args or [])+["--batch","--output-dir",output_dir,"--flush-session","--disable-coloring","--level=3","--risk=1","--threads=1",
          f"--timeout={int(getattr(settings,'SQLMAP_REQUEST_TIMEOUT_SECONDS',45))}",
          f"--retries={int(getattr(settings,'SQLMAP_RETRIES',5))}",
          f"--time-sec={int(getattr(settings,'SQLMAP_TIME_SEC',8))}",
          ]+ev.sqlmap_flags()
    # --smart was removed: it skips every parameter without a positive heuristic,
    # which hides real blind injections. level=3 also tests Cookie, User-Agent and Referer; risk stays 1 (no OR-based/heavy payloads).
    if cookie and "\r" not in cookie and "\n" not in cookie: args.append(f"--cookie={cookie}")
    if auth_header and "\r" not in auth_header and "\n" not in auth_header: args.append(f"--header=Authorization: {auth_header}")
    args += ["--level=3","--risk=2","--technique=BEUSTQ"] if safe_mode=="destructive" and destructive_confirmation else ["--technique=BEUST","--skip-waf"]
    rc,out,err,state,duration,reason=await _run_process_streaming(binary,args,timeout_seconds,on_chunk=on_chunk)
    findings=parse_sqlmap_output(out+"\n"+err,target); raw_files=[]
    sqlmap_unreachable = bool(re.search(r"unable to connect to the target URL|connection refused", out+"\n"+err, re.I)) and not findings
    for path in sorted(Path(output_dir).rglob("*")):
        if path.is_file():
            try: raw_files.append({"name":str(path.relative_to(output_dir)),"content":path.read_text(encoding="utf-8",errors="replace")})
            except Exception: raw_files.append({"name":str(path.relative_to(output_dir)),"binary":True,"size":path.stat().st_size})
    try: shutil.rmtree(output_dir)
    except OSError: pass
    if sqlmap_unreachable:
        # The head of sqlmap's output is only its banner; the useful part is its own
        # [CRITICAL]/[ERROR]/[WARNING] lines, and whether it got as far as testing payloads.
        _text = out + "\n" + err
        _diag_lines = list(dict.fromkeys(_SQLMAP_DIAG_LINE.findall(_text)))[-4:]
        diagnostic = _redact_sqlmap_text(" | ".join(_diag_lines), limit=400)
        _tested = bool(re.search(r"\[INFO\] testing '", _text))
        state="FAILED"
        reason=("sqlmap lost the connection to the target URL after starting its tests" if _tested
                else "sqlmap could not connect to the target URL (nothing was tested)") + (f": {diagnostic}" if diagnostic else "")
    finished=time.time(); return {"status":("FAILED" if sqlmap_unreachable else _canonical_tool_status(state,has_output=bool(out or err or raw_files))),"binary":binary,"version":version,"findings":findings,"stdout":out,"stderr":err,"raw_files":raw_files,"started_at":started,"finished_at":finished,"duration_seconds":finished-started,"exit_code":rc,"reason":reason or (err[-500:] if rc not in (0,None) else None)}


async def run_ghauri(target: str, *, safe_mode: str, scan_profile: str = "standard", timeout_seconds: int, destructive_confirmation: bool = False, evasion: EvasionProfile | None = None, on_chunk=None, data: str | None = None, extra_args: list[str] | None = None, auth_header: str | None = None, cookie: str | None = None) -> dict:
    """Second SQL-injection engine, run per target exactly like run_sqlmap (same selected targets, same
    result shape) so run_sqlmap_multi can drive both. Detection only: no enumeration switches are passed.
    --confirm makes Ghauri re-validate each injected payload (fewer false positives); --level=3 mirrors
    sqlmap's level 3 (cookie, User-Agent, Referer). The risk/destructive options do not exist in Ghauri."""
    started = time.time()
    target = normalize_engine_target(target)
    if not settings.ENABLE_GHAURI: return {"status":"SKIPPED","reason":"ENABLE_GHAURI=false","findings":[]}
    binary = settings.GHAURI_BINARY_PATH
    if not _available(binary): return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    ok_reach, reach_reason = await _preflight(target)
    if not ok_reach:
        return {"status":"FAILED","binary":binary,"findings":[],"reason":reach_reason}
    home = tempfile.mkdtemp(prefix="mirsad-ghauri-")  # Ghauri keeps its session files under $HOME
    args = ["-u", target] + (["--data", data] if data else []) + list(extra_args or []) + ["--batch", "--flush-session", "--confirm", "--level=3"]
    if cookie and "\r" not in cookie and "\n" not in cookie: args.append(f"--cookie={cookie}")
    if auth_header and "\r" not in auth_header and "\n" not in auth_header: args += ["-H", f"Authorization: {auth_header}"]
    try:
        rc, out, err, state, duration, reason = await _run_process_streaming(binary, args, timeout_seconds, on_chunk=on_chunk, extra_env={"HOME": home})
    finally:
        shutil.rmtree(home, ignore_errors=True)
    text = _ANSI_ESCAPE.sub("", out + "\n" + err)
    findings = parse_ghauri_output(text, target)
    unreachable = bool(re.search(r"target URL is not responding|unable to connect|connection (?:refused|reset|timed out)|network is unreachable", text, re.I)) and not findings
    if unreachable:
        state = "FAILED"
        reason = "ghauri lost the connection to the target URL"
    finished = time.time()
    return {"status": "FAILED" if unreachable else _canonical_tool_status(state, has_output=bool(out or err)), "binary": binary, "findings": findings,
            "stdout": out, "stderr": err, "raw_files": [], "started_at": started, "finished_at": finished,
            "duration_seconds": finished - started, "exit_code": rc, "reason": reason or (err[-500:] if rc not in (0, None) else None)}


_SQLMAP_DIAG_LINE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\] \[(?:CRITICAL|ERROR|WARNING)\].*$", re.M)
_SQLI_LOGIN_PATH = re.compile(r"login|signin|sign-in|auth|session|token", re.I)
_SQLMAP_PROTOCOL_PATH = re.compile(r"/(?:socket\.io|engine\.io)(?:/|$)", re.I)
_SQLMAP_PROTOCOL_PARAMS = {"eio", "transport", "t", "sid", "b64", "j", "polling", "heartbeat"}
_STATIC_EXT = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|mp4|webp|pdf)(?:\?|$)", re.I)


def select_sqlmap_targets(target: str, *, endpoints=None, forms=None, api_endpoints=None, max_targets: int = 8) -> list[dict]:
    """Pick injectable-looking requests from what the crawler already found.

    Before this, sqlmap only ever received the site root, so it never tested
    e.g. GET /rest/products/search?q= or POST /rest/user/login. Returns
    [{"url", "data", "extra_args", "label"}], same-host only, de-duplicated,
    capped by ``max_targets``. Protocol-only and unparameterized URLs are not
    sent to SQLMap because they provide no meaningful injection point.
    """
    base = normalize_engine_target(target)
    try:
        host = urlparse(base).netloc
    except ValueError:
        return []
    out: list[dict] = []
    seen: set[tuple] = set()

    def _add(url: str, data: str | None, extra: list[str], label: str):
        if _SQLMAP_PROTOCOL_PATH.search(urlparse(url).path or ""):
            return
        key = (url, data)
        if key in seen or len(out) >= max_targets:
            return
        seen.add(key)
        out.append({"url": url, "data": data, "extra_args": extra, "label": label})

    def _same_host(u: str) -> bool:
        try:
            return urlparse(normalize_engine_target(u)).netloc == host
        except ValueError:
            return False

    def _with_params(url: str, params: list[str]) -> str | None:
        u = normalize_engine_target(url)
        pu = urlparse(u)
        if _STATIC_EXT.search(pu.path or "") or _SQLMAP_PROTOCOL_PATH.search(pu.path or ""):
            return None
        query_pairs = parse_qsl(pu.query, keep_blank_values=True)
        is_engine_protocol = any(name.lower() in {"eio", "transport"} for name, _ in query_pairs)
        protocol_params = _SQLMAP_PROTOCOL_PARAMS if is_engine_protocol else set()
        q = {
            name: value for name, value in query_pairs
            if name.lower() not in protocol_params
        }
        for name in params or []:
            if name and name.lower() not in protocol_params and name not in q:
                q[name] = ""
        if not q:
            return None
        # sqlmap needs a concrete value to mutate; blank values were being dropped.
        q = {k: (v if v != "" else "1") for k, v in q.items()}
        return urlunparse(pu._replace(query=urlencode(q), fragment=""))

    for ep in endpoints or []:
        url = getattr(ep, "url", None) or (ep.get("url") if isinstance(ep, dict) else None)
        method = str(getattr(ep, "method", None) or (ep.get("method") if isinstance(ep, dict) else "GET") or "GET").upper()
        params = list(getattr(ep, "parameters", None) or (ep.get("parameters") if isinstance(ep, dict) else []) or [])
        if not url or not _same_host(url) or method != "GET":
            continue
        u = _with_params(url, params)
        if u:
            _add(u, None, [], "GET parameters")

    for f in forms or []:
        action = getattr(f, "action", None) or (f.get("action") if isinstance(f, dict) else None)
        method = str(getattr(f, "method", None) or (f.get("method") if isinstance(f, dict) else "GET") or "GET").upper()
        inputs = list(getattr(f, "inputs", None) or (f.get("inputs") if isinstance(f, dict) else []) or [])
        types = dict(getattr(f, "input_types", None) or (f.get("input_types") if isinstance(f, dict) else {}) or {})
        if not action or not inputs or not _same_host(action):
            continue
        fields = {n: ("test@example.com" if types.get(n) == "email" else "1") for n in inputs if types.get(n) not in {"submit", "button", "hidden", "file"}}
        if not fields:
            continue
        if method == "POST":
            _add(normalize_engine_target(action), urlencode(fields), [], "POST form")
        else:
            u = _with_params(action, list(fields))
            if u:
                _add(u, None, [], "GET form")

    # API GET parameters are valid candidates too; API login-style POST bodies
    # remain a separate, conservative heuristic with synthetic test values.
    for ep in api_endpoints or []:
        url = getattr(ep, "url", None) or (ep.get("url") if isinstance(ep, dict) else None)
        methods = [str(m).upper() for m in (getattr(ep, "methods", None) or (ep.get("methods") if isinstance(ep, dict) else []) or [])]
        params = list(getattr(ep, "parameters", None) or (ep.get("parameters") if isinstance(ep, dict) else []) or [])
        if not url or not _same_host(url):
            continue
        if "GET" in methods:
            candidate = _with_params(url, params)
            if candidate:
                _add(candidate, None, [], "API GET parameters")
        if "POST" in methods and _SQLI_LOGIN_PATH.search(urlparse(url).path or ""):
            _add(normalize_engine_target(url), json.dumps({"email": "test@example.com", "password": "test"}), ["--headers=Content-Type: application/json"], "POST JSON login")

    # Do not launch SQLMap against an unparameterized site root. It would not
    # test an injection point and can waste the whole per-tool time budget.
    return out


_SQLMAP_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _redact_sqlmap_text(value: str, limit: int | None = 4000) -> str:
    """Redact URL credentials/query values and common secrets in SQLMap diagnostics."""
    text = str(value or "")

    def _redact_url(match: re.Match) -> str:
        raw = match.group(0)
        suffix = ""
        while raw and raw[-1] in ".,);]}":
            suffix = raw[-1] + suffix
            raw = raw[:-1]
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            if parsed.port:
                host = f"{host}:{parsed.port}"
            if parsed.username is not None or parsed.password is not None:
                host = "[REDACTED]@" + host
            query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
            return urlunparse(parsed._replace(netloc=host, query=query, fragment="")) + suffix
        except Exception:
            return "[REDACTED_URL]" + suffix

    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key)(\s*[:=]\s*)(['\"]?)[^'\"\s,;&]{4,}\3", r"\1\2[REDACTED]", text)
    text = _SQLMAP_URL_RE.sub(_redact_url, text)
    return text if limit is None else text[:limit]


async def run_sqlmap_multi(target: str, *, web=None, api=None, safe_mode: str, scan_profile: str = "standard", timeout_seconds: int, destructive_confirmation: bool = False, evasion: EvasionProfile | None = None, on_chunk=None, max_targets: int | None = None, auth_header: str | None = None, cookie: str | None = None, runner=None, tool: str = "sqlmap") -> dict:
    """Run sqlmap (or, with runner=run_ghauri, Ghauri) against every injectable-looking request the crawler found."""
    if max_targets is None:
        max_targets = int(getattr(settings, "SQLMAP_MAX_TARGETS", 4))
    targets = select_sqlmap_targets(
        target,
        endpoints=getattr(web, "endpoints", None) if web else None,
        forms=getattr(web, "forms", None) if web else None,
        api_endpoints=getattr(api, "endpoints", None) if api else None,
        max_targets=max_targets,
    )
    if not targets:
        return {
            "status": "NOT_TESTED", "findings": [], "targets_tested": [],
            "reason": "No in-scope query, form, or API request with injectable parameters was discovered; SQLMap was not run.",
        }
    started = time.time()
    results: list[tuple[dict, dict]] = []
    unrun_targets: list[dict] = []
    precheck_enabled = bool(getattr(settings, "SQLMAP_PRECHECK_GET_TARGETS", True))
    precheck_timeout = float(getattr(settings, "SQLMAP_PRECHECK_TIMEOUT_SECONDS", 8.0))
    retry_attempts = max(0, int(getattr(settings, "SQLMAP_CONNECT_RETRY_ATTEMPTS", 3)))
    retry_base = max(1, int(getattr(settings, "SQLMAP_CONNECT_RETRY_BASE_SECONDS", 20)))
    for target_index, t in enumerate(targets):
        if time.time() - started >= timeout_seconds:
            unrun_targets = targets[target_index:]
            break
        # Dynamic per-target budget: split what is LEFT over the targets LEFT, instead of a fixed
        # division computed once up front. A target that finishes (or is precheck-skipped) early
        # now donates its unused time to the remaining targets, instead of that time being wasted -
        # the single biggest driver of PARTIAL/TIMEOUT against real sites (portal.cpu.edu.sy,
        # 2026-11-01: 2 of 4 targets ran out of their fixed 450s slice mid time-based-blind test).
        targets_left = len(targets) - target_index
        remaining = max(60, int(timeout_seconds - (time.time() - started)))
        per_target = max(120, remaining // targets_left)
        # Precheck GET-only candidates (never POST: submitting data has side effects we must not
        # trigger just to probe existence). A 404 here means select_sqlmap_targets() reconstructed
        # a URL/query shape that does not actually exist on the server - sending it to sqlmap/ghauri
        # would only burn a full per_target slice for "page not found (404)" and nothing else
        # (observed against portal.cpu.edu.sy, 2026-11-01: 2 of 4 sqlmap targets were exactly this).
        if precheck_enabled and not t["data"]:
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=precheck_timeout) as _hc:
                    _resp = await _hc.get(t["url"])
                if _resp.status_code == 404:
                    results.append((t, {"status": "SKIPPED", "findings": [], "reason": "target returned HTTP 404 on precheck; not sent to sqlmap/ghauri"}))
                    continue
            except Exception:
                pass  # precheck itself failing is not evidence of anything; fall through to the real attempt
        async def _attempt(budget: int) -> dict:
            return await (runner or run_sqlmap)(t["url"], safe_mode=safe_mode, scan_profile=scan_profile, timeout_seconds=budget, destructive_confirmation=destructive_confirmation, evasion=evasion, on_chunk=on_chunk, data=t["data"], extra_args=t["extra_args"], auth_header=auth_header, cookie=cookie)
        r = await _attempt(min(per_target, remaining))
        # A dropped connection (2026-11-01: "Network is unreachable" while other engines loaded the
        # Docker host bridge) is often transient. Retry with linear backoff (20s, 40s, 60s, ...),
        # each time only after the target answers again on preflight and the remaining budget still
        # allows it. A single fixed-30s retry (the previous behaviour) did not recover in the
        # 2026-11-02 incident - all 3 targets stayed FAILED after exactly one attempt each.
        attempt_n = 0
        while (attempt_n < retry_attempts and r.get("status") == "FAILED"
                and re.search(r"connect", str(r.get("reason") or ""), re.I)
                and timeout_seconds - (time.time() - started) >= 120):
            attempt_n += 1
            await asyncio.sleep(retry_base * attempt_n)
            if (await _preflight(t["url"]))[0]:
                r = await _attempt(min(per_target, max(60, int(timeout_seconds - (time.time() - started)))))
        results.append((t, r))
        if r.get("status") in {"SKIPPED", "UNAVAILABLE"}:
            return r
    if results and not unrun_targets and all(r.get("status") == "SKIPPED" for _, r in results):
        # Every candidate was processed (no time-budget break) and 404'd on precheck - this is
        # "nothing to test", same family as the no-targets-found case above, not a scanner failure.
        # Guarded on `not unrun_targets` so a genuine time-budget exhaustion (some targets never
        # even reached the precheck) still falls through to the existing PARTIAL/FAILED logic below.
        return {"status": "NOT_TESTED", "findings": [], "targets_tested": [
                    {"url": _redact_sqlmap_text(t["url"], limit=None), "method": "GET", "label": t["label"], "status": "SKIPPED", "reason": r.get("reason")} for t, r in results],
                "reason": "every candidate target returned HTTP 404 on precheck; none were sent to sqlmap/ghauri"}
    if not results:
        not_run = [{"url": _redact_sqlmap_text(t["url"], limit=None),
                    "method": "POST" if t["data"] else "GET", "label": t["label"],
                    "status": "NOT_TESTED", "reason": "overall SQLMap time budget exhausted before this target"}
                   for t in unrun_targets]
        return {"status": "PARTIAL" if not_run else "FAILED", "findings": [],
                "targets_tested": not_run,
                "reason": "overall SQLMap time budget exhausted before any target was tested" if not_run else "no sqlmap targets were run"}
    findings, raw_files, stdout, stderr = [], [], [], []
    for i, (t, r) in enumerate(results):
        for f in r.get("findings") or []:
            f = dict(f)
            f.setdefault("request", f"{'POST' if t['data'] else 'GET'} {t['url']}")
            if f.get("request"):
                f["request"] = _redact_sqlmap_text(f["request"], limit=2000)
            for location_key in ("matched_at", "endpoint"):
                if f.get(location_key):
                    f[location_key] = _redact_sqlmap_text(f[location_key], limit=2000)
            findings.append(f)
        for rf in r.get("raw_files") or []:
            rf = dict(rf); rf["name"] = f"target{i+1}/{rf.get('name')}"; raw_files.append(rf)
        safe_url = _redact_sqlmap_text(t["url"], limit=None)
        stdout.append(_redact_sqlmap_text(f"### {tool} target {i+1}/{len(results)} [{t['label']}] {'POST' if t['data'] else 'GET'} {safe_url}\n{r.get('stdout') or ''}", limit=20000))
        stderr.append(_redact_sqlmap_text(r.get("stderr") or "", limit=4000))
    statuses = [r.get("status") for _, r in results]
    ok = [s_ for s_ in statuses if s_ in {"COMPLETED", "PARTIAL"}]
    if not ok:
        status = "PARTIAL" if unrun_targets else "FAILED"
    elif all(s_ == "COMPLETED" for s_ in statuses) and not unrun_targets:
        status = "COMPLETED"
    else:
        status = "PARTIAL"
    last = results[-1][1]
    finished = time.time()
    failed_reasons = [
        _redact_sqlmap_text(f"{t['label']} ({'POST' if t['data'] else 'GET'} {t['url']}): {r.get('reason')}", limit=500)
        for t, r in results if r.get("status") == "FAILED" and r.get("reason")
    ]
    return {"status": status, "binary": last.get("binary"), "version": last.get("version"), "findings": findings,
            "stdout": "\n".join(stdout), "stderr": "\n".join(x for x in stderr if x), "raw_files": raw_files,
            "started_at": started, "finished_at": finished, "duration_seconds": finished - started,
            "exit_code": last.get("exit_code"), "targets_tested": (
                [{"url": _redact_sqlmap_text(t["url"], limit=None), "method": "POST" if t["data"] else "GET", "label": t["label"], "status": r.get("status"), "reason": _redact_sqlmap_text(r.get("reason") or "", limit=500) or None} for t, r in results]
                + [{"url": _redact_sqlmap_text(t["url"], limit=None), "method": "POST" if t["data"] else "GET", "label": t["label"], "status": "NOT_TESTED", "reason": "overall SQLMap time budget exhausted before this target"} for t in unrun_targets]
            ),
            "reason": (("; ".join(failed_reasons + ([f"{len(unrun_targets)} target(s) not tested: overall time budget exhausted"] if unrun_targets else [])))[:500] or None)}


def _estimate_ffuf_minimum_seconds(wordlist_entries: int | None, rate: int) -> int | None:
    """Lower-bound duration at the configured request rate (excludes latency/retries)."""
    if wordlist_entries is None or wordlist_entries < 0 or rate <= 0:
        return None
    return (wordlist_entries + rate - 1) // rate


async def run_ffuf(target: str, *, safe_mode: str, scan_profile: str = "standard", timeout_seconds: int, wordlist: str | None = None, evasion: EvasionProfile | None = None, on_chunk=None, auth_header: str | None = None, cookie: str | None = None) -> dict:
    """Run ffuf only for content discovery, with a bounded local wordlist.

    Two bundled wordlist tiers ship with the image:
      - quick (~200 curated entries: common sensitive paths/files, admin
        panels, backups, framework-specific endpoints) for standard-profile
        scans — fast and low-noise.
      - deep (~157,000 entries: quick + SecLists' raft-large-words,
        raft-large-directories, raft-large-files, and two API-endpoint
        lists) for deep/maximum profiles. This is the same class of
        wordlist professional pentesters use with ffuf/gobuster/feroxbuster
        for real content-discovery coverage, not a token sample.

    -ac (auto-calibration) is always enabled so ffuf learns the target's
    "everything returns 200" / soft-404 baseline and filters it out instead
    of reporting thousands of false positives on SPA catch-all routes.
    """
    target = normalize_engine_target(target)
    if not settings.ENABLE_FFUF:
        return {"status": "DISABLED", "reason": "ENABLE_FFUF=false", "findings": []}
    binary = settings.FFUF_BINARY_PATH
    if not _available(binary):
        return {"status": "UNAVAILABLE", "binary": binary, "findings": [], "reason":"binary not found"}
    deep = scan_profile in {"deep", "maximum"}
    default_wl = settings.FFUF_WORDLIST_DEEP_PATH if deep else settings.FFUF_WORDLIST_QUICK_PATH
    wl = wordlist or default_wl
    if not Path(wl).exists():
        # Never silently replace the configured discovery corpus with a tiny
        # fallback: that would reduce coverage to make a scan appear healthy.
        return {"status":"FAILED","binary":binary,"findings":[],"reason":"configured ffuf wordlist is missing"}
    ok_reach, reach_reason = await _preflight(target)
    if not ok_reach:
        return {"status": "FAILED", "binary": binary, "findings": [], "reason": reach_reason}
    output = tempfile.NamedTemporaryFile(prefix="mirsad-ffuf-", suffix=".json", delete=False).name
    # The deep wordlist is ~750x the quick one (~157k vs ~211 entries), so
    # thread count/rate are raised accordingly to actually finish the run
    # inside EXTERNAL_DAST_TIMEOUT_SECONDS instead of being killed mid-fuzz
    # (157,000 requests / 80 req/s ≈ 33 min — comfortably under the 3600s/
    # 90-min defaults, leaving headroom for a slow target or retries).
    # 80 req/s stays well inside what a normal production web server or
    # CDN absorbs without degrading service — this is content discovery,
    # not a load test.
    threads = "40" if deep else "2"
    rate = "80" if deep else "5"
    # Evasion: UA + ترويسات + jitter من EvasionProfile
    ev = evasion or default_profile(safe_mode, scan_profile)
    import asyncio as _asyncio_ev2
    await _asyncio_ev2.sleep(ev.jitter_seconds())
    args = [
        "-u", target.rstrip("/") + "/FUZZ",
        "-w", wl,
        "-of", "json", "-o", output,
        "-t", threads, "-rate", rate,
        "-timeout", "5", "-ac", "-s",
        "-maxtime", str(max(30, int(timeout_seconds) - 45)),
    ] + ev.ffuf_flags()
    for _h, _v in _auth_header_pairs(auth_header, cookie): args += ["-H", f"{_h}: {_v}"]
    if safe_mode == "safe":
        args += ["-mc", "200,204,301,302,307,308,401,403"]
    try:
        with Path(wl).open("r", encoding="utf-8", errors="ignore") as wordlist_file:
            wordlist_entries = sum(1 for _ in wordlist_file)
    except OSError:
        wordlist_entries = None
    configured_rate = int(rate)
    estimated_minimum_seconds = _estimate_ffuf_minimum_seconds(wordlist_entries, configured_rate)
    rc, out, err, state, duration, reason = await _run_process_streaming(binary, args, timeout_seconds, on_chunk=on_chunk)
    findings=[]
    parse_error=None
    raw_output=""
    try:
        raw_output=Path(output).read_text(encoding="utf-8", errors="replace")
        data=json.loads(raw_output)
        # -ac already filtered soft-404 noise. Preserve every parser result;
        # request budgets are the safety boundary, not result-retention caps.
        findings.extend(parse_ffuf_json(data))
    except Exception as exc:
        parse_error=type(exc).__name__ + ": " + str(exc)
    try: os.unlink(output)
    except OSError: pass
    result = {"status":_canonical_tool_status(state,has_output=bool(out or err or findings or raw_output)),
              "binary":binary,"wordlist_tier":"deep" if deep else "quick","findings":findings,
              "stdout":out,"stderr":err,"raw_output":raw_output,"parse_error":parse_error,
              "exit_code":rc,"duration_seconds":duration,
              "timeout_seconds":int(timeout_seconds),"configured_rate":configured_rate,
              "wordlist_entries":wordlist_entries,
              "estimated_minimum_seconds":estimated_minimum_seconds}
    if parse_error and result["status"] == "COMPLETED": result["status"]="PARTIAL"
    if rc != 0: result["reason"] = err[-500:] or f"ffuf exited with code {rc}"
    return result


def _redact_detector_output(value: str, limit: int = 4000) -> str:
    """Keep external-tool evidence safe for persistence/AI."""
    value = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key)\s*([:=])\s*(['\"]?)[^'\"\s,;]{6,}\3", r"\1\2[REDACTED]", value)
    return value[:limit]


async def _run_bounded_exec(binary: str, args: list[str], timeout_seconds: int, *, cwd: str | None = None) -> tuple[str, int, str, str]:
    """Strict argv-only subprocess helper; never invokes a shell."""
    if not _available(binary):
        return "NOT_INSTALLED", -127, "", ""
    t0 = time.monotonic()
    proc = None
    try:
        _trace.emit_command([binary, *args], cwd=cwd, timeout=timeout_seconds)
        proc = await asyncio.create_subprocess_exec(
            binary, *args, cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_build_evasion_env(),
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=max(1, int(timeout_seconds)))
        _o, _e = out.decode("utf-8","ignore"), err.decode("utf-8","ignore")
        for _line in _o.splitlines()[:300]: _trace.emit_output("stdout", _line)
        for _line in _e.splitlines()[:300]: _trace.emit_output("stderr", _line)
        _trace.emit_exit(binary, proc.returncode, time.monotonic()-t0, "COMPLETED" if proc.returncode == 0 else "PARTIAL")
        return "COMPLETED" if proc.returncode == 0 else "PARTIAL", proc.returncode, _o, _e
    except asyncio.CancelledError:
        # Job cancelled: do not leave the child process running in the background.
        if proc is not None and proc.returncode is None:
            try: proc.kill()
            except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
            try: await asyncio.wait_for(asyncio.shield(proc.wait()), timeout=5)
            except BaseException: logger.debug("suppressed non-fatal error", exc_info=True)
        _trace.emit_exit(binary, None, time.monotonic()-t0, "CANCELLED", "CANCELLED")
        raise
    except asyncio.TimeoutError:
        try:
            proc.kill(); await proc.wait()
        except Exception:
            logger.debug("suppressed non-fatal error", exc_info=True)
        _trace.emit_exit(binary, -124, time.monotonic()-t0, "TIMEOUT", "TIMEOUT")
        return "TIMEOUT", -124, "", "TIMEOUT"
    except Exception as exc:
        _trace.emit_exit(binary, None, time.monotonic()-t0, "FAILED", str(exc)[:300])
        return "FAILED", -1, "", str(exc)[:1000]


def _source_snapshot_relative_path(root: str, reported_path: str) -> str:
    """Convert a detector path into a stable snapshot-relative evidence path."""
    candidate = Path(str(reported_path or ""))
    try:
        resolved = candidate.resolve() if candidate.is_absolute() else (Path(root) / candidate).resolve()
        relative = resolved.relative_to(Path(root).resolve())
        return relative.as_posix()
    except (OSError, ValueError):
        # A detector may report an unknown or malformed path; do not persist
        # host/container absolute paths or paths outside the isolated snapshot.
        return candidate.name[:500] or "unknown-source"


def _write_source_snapshot(source_files: list[tuple[str, str]], max_files: int = 2000) -> tuple[str, dict[str, str]]:
    root = Path(tempfile.mkdtemp(prefix="mirsad-source-"))
    manifest = {}
    for index, (name, content) in enumerate(source_files[:max_files]):
        safe_name = re.sub(r"[^A-Za-z0-9._/-]+", "_", name or f"source-{index}.js").lstrip("/")
        if not safe_name or safe_name.startswith(".."):
            safe_name = f"source-{index}.js"
        path = (root / safe_name).resolve()
        if root not in path.parents:
            path = root / f"source-{index}.js"
        path.parent.mkdir(parents=True, exist_ok=True)
        data = (content or "")[:int(getattr(settings, "SOURCE_INTELLIGENCE_MAX_SOURCE_SIZE", 5_000_000))]
        path.write_text(data, encoding="utf-8", errors="ignore")
        manifest[str(path.relative_to(root))] = str(path)
    return str(root), manifest


async def run_semgrep_source_scan(source_files: list[tuple[str, str]], *, timeout_seconds: int | None = None) -> dict:
    """Optional Semgrep layer over a bounded in-memory web-source snapshot.

    Only the bundled local ruleset is allowed; callers cannot supply arbitrary
    rules/configuration through the frontend.
    """
    if not settings.ENABLE_SEMGREP:
        return {"status":"DISABLED","reason":"ENABLE_SEMGREP=false","findings":[]}
    binary=settings.SEMGREP_BINARY_PATH
    if not _available(binary):
        return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    if not source_files:
        return {"status":"NOT_TESTED","reason":"No JavaScript/TypeScript source in the fetched page source","findings":[]}
    root, _ = _write_source_snapshot(source_files)
    try:
        rules_dir = Path(__file__).resolve().parent / "rules"
        config = rules_dir / "mirsad-javascript.yml"
        status, rc, out, err = await _run_bounded_exec(
            binary,
            ["--config", str(config), "--json", "--no-git-ignore", "--metrics","off", root],
            int(timeout_seconds or settings.SOURCE_TOOL_TIMEOUT_SECONDS),
        )
        combined_diagnostics = (out or "") + "\n" + (err or "")
        if re.search(r"semgrep-core.*rule validation failed|RuleParseError", combined_diagnostics, re.I):
            # A ruleset that cannot be validated never reached source analysis;
            # PARTIAL would falsely imply that some source was scanned.
            status = "FAILED"
        findings=[]; parser_errors=[]
        try:
            data=json.loads(out or "{}")
            for item in (data.get("results") or []):
                extra=item.get("extra") or {}
                findings.append({
                    "name": extra.get("message") or item.get("check_id") or "Semgrep finding",
                    "severity": str(extra.get("severity") or "medium").title(),
                    "matched_at": _source_snapshot_relative_path(root, item.get("path") or "unknown-source"),
                    "description": _redact_detector_output(str(extra.get("message") or "")),
                    "evidence": _redact_detector_output(str(extra.get("lines") or "")),
                    "rule_id": item.get("check_id"),
                    "line": (item.get("start") or {}).get("line"),
                })
        except Exception as exc:
            parser_errors.append({"reason":type(exc).__name__})
            if status=="COMPLETED": status="PARTIAL"
        diagnostic = _redact_detector_output((err or "").strip() or (out or "").strip(), 1200)
        reason = None
        if status != "COMPLETED":
            if rc not in (0, None):
                reason = f"Semgrep exited with code {rc}" + (f": {diagnostic}" if diagnostic else "")
            else:
                reason = diagnostic or "Semgrep did not complete successfully"
        return {"status":status,"binary":binary,"findings":findings,
                "version":await _binary_version(binary,["--version"]),
                "exit_code":rc,"stderr":_redact_detector_output(err,2000),
                "reason":reason,"parser_errors":parser_errors}
    finally:
        shutil.rmtree(root,ignore_errors=True)


async def run_gitleaks_source_scan(source_files: list[tuple[str, str]], *, timeout_seconds: int | None = None) -> dict:
    if not settings.ENABLE_GITLEAKS:
        return {"status":"DISABLED","reason":"ENABLE_GITLEAKS=false","findings":[]}
    binary=settings.GITLEAKS_BINARY_PATH
    if not _available(binary):
        return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    if not source_files:
        return {"status":"NOT_TESTED","reason":"No source snapshot available","findings":[]}
    root,_=_write_source_snapshot(source_files)
    output_fd, output_name = tempfile.mkstemp(prefix="mirsad-gitleaks-",suffix=".json")
    os.close(output_fd)
    output=Path(output_name)
    try:
        status, rc, out, err=await _run_bounded_exec(
            binary, ["detect","--source",root,"--no-banner","--report-format","json","--report-path",str(output),"--redact"],
            int(timeout_seconds or settings.SOURCE_TOOL_TIMEOUT_SECONDS), cwd=root)
        findings=[]; parser_errors=[]; report_valid=False
        try:
            data=json.loads(output.read_text(encoding="utf-8",errors="ignore") or "[]")
            if isinstance(data,dict): data=data.get("findings") or []
            if not isinstance(data,list):
                raise ValueError("Gitleaks report must be a JSON array")
            report_valid=True
            for item in data:
                if not isinstance(item,dict):
                    parser_errors.append({"reason":"invalid_finding_record"})
                    continue
                findings.append({
                    "name":item.get("Description") or item.get("RuleID") or "Gitleaks secret",
                    "severity":"High",
                    "matched_at":_source_snapshot_relative_path(root, item.get("File") or "unknown-source"),
                    "description":"Gitleaks detected a secret candidate in source.",
                    "evidence":"REDACTED",
                    "rule_id":item.get("RuleID"),
                    "fingerprint":hashlib.sha256(str(item.get("Fingerprint") or item.get("Secret") or "").encode()).hexdigest(),
                })
        except Exception as exc:
            parser_errors.append({"reason":type(exc).__name__})
        # Gitleaks uses exit code 1 for a successful detection run with leaks.
        # Do not downgrade a valid report containing findings to PARTIAL.
        if status == "PARTIAL" and rc == 1 and report_valid and findings and not parser_errors:
            status = "COMPLETED"
        elif parser_errors and status == "COMPLETED":
            status = "PARTIAL"
        diagnostic = _redact_detector_output((err or "").strip() or (out or "").strip(), 1200)
        reason = None if status == "COMPLETED" else (diagnostic or f"Gitleaks exited with code {rc}")
        return {"status":status,"binary":binary,"findings":findings,
                "version":await _binary_version(binary,["version"]),
                "exit_code":rc,"stderr":_redact_detector_output(err,2000),
                "reason":reason,"parser_errors":parser_errors}
    finally:
        try: output.unlink()
        except OSError: pass
        shutil.rmtree(root,ignore_errors=True)


async def run_trufflehog_source_scan(source_files: list[tuple[str, str]], *, timeout_seconds: int | None = None) -> dict:
    if not settings.ENABLE_TRUFFLEHOG:
        return {"status":"DISABLED","reason":"ENABLE_TRUFFLEHOG=false","findings":[]}
    binary=settings.TRUFFLEHOG_BINARY_PATH
    if not _available(binary):
        return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    if not source_files:
        return {"status":"NOT_TESTED","reason":"No source snapshot available","findings":[]}
    root,_=_write_source_snapshot(source_files)
    try:
        status, rc, out, err=await _run_bounded_exec(
            binary, ["filesystem","--directory",root,"--json","--no-update"],
            int(timeout_seconds or settings.SOURCE_TOOL_TIMEOUT_SECONDS), cwd=root)
        findings=[]; parser_errors=[]
        for line_no,line in enumerate(out.splitlines(),1):
            if not line.strip():
                continue
            try:
                item=json.loads(line)
            except Exception as exc:
                parser_errors.append({"line":line_no,"reason":type(exc).__name__})
                continue
            raw=item.get("Raw") or item.get("raw") or ""
            filesystem_path=((item.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem")
            findings.append({
                "name":item.get("DetectorName") or item.get("DetectorType") or "TruffleHog secret",
                "severity":"High",
                "matched_at":_source_snapshot_relative_path(root, filesystem_path or "unknown-source"),
                "description":"TruffleHog detected a secret candidate in source.",
                "evidence":"REDACTED","rule_id":item.get("DetectorName") or item.get("DetectorType"),
                "fingerprint":hashlib.sha256(str(raw).encode()).hexdigest(),
                "verified":bool(item.get("Verified")),
            })
        if parser_errors and status == "COMPLETED":
            status = "PARTIAL"
        return {"status":status,"binary":binary,"findings":findings,
                "version":await _binary_version(binary,["--version"]),
                "stderr":_redact_detector_output(err,2000),"exit_code":rc,"parser_errors":parser_errors}
    finally:
        shutil.rmtree(root,ignore_errors=True)


async def run_trivy_source_scan(source_files: list[tuple[str, str]], *, timeout_seconds: int | None = None) -> dict:
    if not settings.ENABLE_TRIVY: return {"status":"DISABLED","reason":"ENABLE_TRIVY=false","findings":[]}
    binary=settings.TRIVY_BINARY_PATH
    if not _available(binary): return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"binary not found"}
    if not source_files: return {"status":"NOT_TESTED","reason":"No source snapshot available","findings":[]}
    cache_dir=Path(settings.TRIVY_CACHE_DIR)
    if not any(cache_dir.glob("**/trivy.db")):
        return {"status":"UNAVAILABLE","binary":binary,"findings":[],"reason":"Trivy vulnerability DB is unavailable; worker remains healthy and this detector is skipped."}
    root,_=_write_source_snapshot(source_files)
    try:
        args=["fs","--format","json","--scanners","vuln,misconfig","--skip-db-update","--cache-dir",settings.TRIVY_CACHE_DIR,"--quiet",root]
        rc,out,err,state,_,reason=await _run_process_streaming(binary,args,int(timeout_seconds or settings.TRIVY_TIMEOUT_SECONDS),cwd=root)
        findings=[]
        try: data=json.loads(out or "{}")
        except Exception: data={}
        for result in (data.get("Results") or []):
            target=str(result.get("Target") or "")
            for item in (result.get("Vulnerabilities") or []):
                findings.append({"name":item.get("VulnerabilityID") or "Trivy vulnerability","severity":str(item.get("Severity") or "Info").title(),"category":"dependency-vulnerability","matched_at":target,"description":item.get("Title") or item.get("Description"),"package":item.get("PkgName"),"installed_version":item.get("InstalledVersion"),"fixed_version":item.get("FixedVersion"),"references":item.get("References") or []})
            for item in (result.get("Misconfigurations") or []):
                findings.append({"name":item.get("ID") or "Trivy misconfiguration","severity":str(item.get("Severity") or "Info").title(),"category":"misconfiguration","matched_at":target,"description":item.get("Title") or item.get("Message"),"resolution":item.get("Resolution"),"references":item.get("References") or []})
        # Never expose the temporary absolute root path in result fields.
        for f in findings:
            f["matched_at"]=str(f.get("matched_at") or "").replace(root.rstrip("/"), "") or "/"
        return {"status":_canonical_tool_status(state,has_output=bool(out or findings)),"binary":binary,"findings":findings,"stdout":out,"stderr":err,"exit_code":rc,"reason":reason or None,"manifests_available":any(Path(name).name.lower() in {"package.json","package-lock.json","requirements.txt","pyproject.toml","poetry.lock","pom.xml","go.mod","go.sum","composer.json","gemfile.lock"} for name,_ in source_files)}
    finally:
        shutil.rmtree(root,ignore_errors=True)

async def run_source_detectors(source_files: list[tuple[str, str]], *, timeout_seconds: int | None = None) -> dict:
    """Run optional Semgrep/Gitleaks/TruffleHog/Trivy concurrently.

    Each detector has independent availability and timeout. Their results are
    later correlated by fingerprint/rule+asset so one secret is one issue.
    """
    if not source_files:
        return {
            "semgrep":{"status":"NOT_TESTED","findings":[]},
            "gitleaks":{"status":"NOT_TESTED","findings":[]},
            "trufflehog":{"status":"NOT_TESTED","findings":[]},
            "trivy":{"status":"NOT_TESTED","findings":[]},
        }
    results=await asyncio.gather(
        run_semgrep_source_scan(source_files,timeout_seconds=timeout_seconds),
        run_gitleaks_source_scan(source_files,timeout_seconds=timeout_seconds),
        run_trufflehog_source_scan(source_files,timeout_seconds=timeout_seconds),
        run_trivy_source_scan(source_files,timeout_seconds=timeout_seconds),
        return_exceptions=True,
    )
    names=("semgrep","gitleaks","trufflehog","trivy")
    out={}
    for name,result in zip(names,results):
        out[name]=result if isinstance(result,dict) else {"status":"FAILED","findings":[],"reason":str(result)[:500]}
    # Cross-detector correlation: same fingerprint is one secret issue.
    by_fp={}
    for detector,payload in out.items():
        for finding in payload.get("findings") or []:
            fp=finding.get("fingerprint")
            if fp:
                by_fp.setdefault(fp,{"name":"Correlated Secret Exposure","severity":"High",
                    "matched_at":finding.get("matched_at"),"description":"Multiple secret detectors identified the same source candidate.",
                    "evidence":"REDACTED","fingerprint":fp,"detectors":[]})
                by_fp[fp]["detectors"].append(detector)
    out["correlated_secrets"]=list(by_fp.values())[:1000]
    return out

async def _zap_request(client, method: str, url: str, *, params: dict | None = None, retries: int = 5):
    """GET/etc against the ZAP daemon with retries on transient transport
    errors. A long-running active scan can see the daemon briefly drop a
    connection (GC pause, connection pool churn) without actually dying —
    retrying the single call is far cheaper than losing the whole scan's
    accumulated alerts to one flaky request at the end."""
    last_exc = None
    for attempt in range(retries):
        t0 = time.monotonic()
        try:
            resp = await client.request(method, url, params=params)
            try:
                _trace.emit_http(method=method, url=str(resp.request.url), request_headers=resp.request.headers,
                                 status=resp.status_code, reason=resp.reason_phrase, response_headers=resp.headers,
                                 response_body=resp.content[:8192], response_content_type=resp.headers.get("content-type", ""),
                                 duration_ms=(time.monotonic()-t0)*1000, source="zap-api")
            except Exception:
                logger.debug("suppressed non-fatal error", exc_info=True)
            return resp
        except (httpx.RemoteProtocolError, httpx.ReadTimeout, httpx.ConnectError,
                httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            _trace.emit_http(method=method, url=url, request_headers={}, duration_ms=(time.monotonic()-t0)*1000,
                             error=f"{type(exc).__name__}: {exc}", source="zap-api")
            last_exc = exc
            if attempt < retries - 1:
                await asyncio.sleep(1.5 * (attempt + 1))
    raise last_exc


# ZAP isolation (2026-10-17): the ZAP daemon is ONE shared process whose site tree,
# alerts and message history are global. Two overlapping scans (two users, or two
# tenants scanning the same host) used to read each other's alerts/evidence because
# alerts are only filtered by `baseurl`. The daemon is therefore used by at most
# ZAP_MAX_CONCURRENT_SCANS scans at a time (default 1, cluster-wide through Redis,
# plus an in-process lock for dev stacks without Redis) and its session + alerts
# are wiped before and after every scan.
_ZAP_LOCAL_LOCK: asyncio.Lock | None = None


def _zap_local_lock() -> asyncio.Lock:
    global _ZAP_LOCAL_LOCK
    if _ZAP_LOCAL_LOCK is None:
        _ZAP_LOCAL_LOCK = asyncio.Lock()
    return _ZAP_LOCAL_LOCK


async def _zap_reset_state(base: str) -> None:
    """Best-effort: drop every alert and start a fresh ZAP session so the next scan
    cannot see this scan's data (and vice versa). Never raises."""
    headers = {"X-ZAP-API-Key": settings.ZAP_API_KEY} if settings.ZAP_API_KEY else {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=10.0), headers=headers) as client:
            for path, params in (
                ("/JSON/core/action/deleteAllAlerts/", None),
                ("/JSON/core/action/newSession/", {"name": f"mirsad-{uuid.uuid4().hex[:8]}", "overwrite": "true"}),
            ):
                try:
                    await _zap_request(client, "GET", f"{base}{path}", params=params, retries=2)
                except Exception as exc:
                    logger.debug("ZAP state reset step %s failed: %s", path, type(exc).__name__)
    except Exception as exc:
        logger.debug("ZAP state reset failed: %s", type(exc).__name__)


async def run_zap_service(target: str, *, safe_mode: str, scan_profile: str = "standard",
                           timeout_seconds: int, active: bool = False, seed_urls: list[str] | None = None,
                           auth_header: str | None = None, cookie: str | None = None) -> dict:
    """Serialised, state-isolated entry point for the shared ZAP daemon."""
    from app.core.distributed_semaphore import distributed_slot
    base = (getattr(settings, "ZAP_SERVICE_URL", "") or "").rstrip("/")
    if not base:
        return await _run_zap_service_locked(target, safe_mode=safe_mode, scan_profile=scan_profile, timeout_seconds=timeout_seconds,
                                             active=active, seed_urls=seed_urls, auth_header=auth_header, cookie=cookie)
    limit = max(1, int(getattr(settings, "ZAP_MAX_CONCURRENT_SCANS", 1) or 1))
    async with _zap_local_lock():
        async with distributed_slot("zap:daemon", limit):
            await _zap_reset_state(base)
            try:
                return await _run_zap_service_locked(target, safe_mode=safe_mode, scan_profile=scan_profile, timeout_seconds=timeout_seconds,
                                                     active=active, seed_urls=seed_urls, auth_header=auth_header, cookie=cookie)
            finally:
                await _zap_reset_state(base)


async def _run_zap_service_locked(target: str, *, safe_mode: str, scan_profile: str = "standard",
                           timeout_seconds: int, active: bool = False, seed_urls: list[str] | None = None,
                           auth_header: str | None = None, cookie: str | None = None) -> dict:
    """Wrapper that installs operator credentials as ZAP replacer rules for the
    duration of the scan and ALWAYS removes them afterwards (the ZAP daemon is
    shared between scans, so credentials must never leak into the next one)."""
    base = (getattr(settings, "ZAP_SERVICE_URL", "") or "").rstrip("/")
    pairs = _auth_header_pairs(auth_header, cookie)
    if not base or not pairs:
        return await _run_zap_service_inner(target, safe_mode=safe_mode, scan_profile=scan_profile, timeout_seconds=timeout_seconds, active=active, seed_urls=seed_urls)
    headers = {"X-ZAP-API-Key": settings.ZAP_API_KEY} if settings.ZAP_API_KEY else {}
    rule_names = [f"mirsad-auth-{name.lower()}-{uuid.uuid4().hex[:8]}" for name, _ in pairs]
    installed: list[str] = []
    auth_warning = None
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=30.0), headers=headers) as client:
        for (name, value), rule in zip(pairs, rule_names):
            try:
                r = await _zap_request(client, "GET", f"{base}/JSON/replacer/action/addRule/", params={"description": rule, "enabled": "true", "matchType": "REQ_HEADER", "matchRegex": "false", "matchString": name, "replacement": value, "initiators": ""}, retries=6)
                if r.status_code < 400: installed.append(rule)
                else: auth_warning = f"ZAP replacer rule for {name} rejected (HTTP {r.status_code}); ZAP ran unauthenticated"
            except Exception as exc:
                auth_warning = f"ZAP auth rule for {name} could not be installed ({type(exc).__name__}); ZAP ran unauthenticated"
        try:
            result = await _run_zap_service_inner(target, safe_mode=safe_mode, scan_profile=scan_profile, timeout_seconds=timeout_seconds, active=active, seed_urls=seed_urls)
        finally:
            for rule in installed:
                try: await _zap_request(client, "GET", f"{base}/JSON/replacer/action/removeRule/", params={"description": rule}, retries=3)
                except Exception: logger.warning("could not remove ZAP auth rule %s", rule)
    if isinstance(result, dict):
        result["authenticated"] = bool(installed)
        if auth_warning: result["auth_warning"] = auth_warning
    return result


def _zap_liveness() -> None:
    """A ZAP poll that got an answer is real progress. Without this, a legitimately long ZAP
    scan (no log/progress writes for an hour) looked like a zombie to the stall watchdog and the
    job was cancelled mid-scan (2026-10-16)."""
    try:
        from app.core.execution_trace import current_job
        from app.core.stall_watchdog import touch
        job = current_job()
        if job is not None:
            touch(getattr(job, "job_id", None))
    except Exception:
        logger.debug("suppressed non-fatal error", exc_info=True)


async def _run_zap_service_inner(target: str, *, safe_mode: str, scan_profile: str = "standard",
                           timeout_seconds: int, active: bool = False, seed_urls: list[str] | None = None) -> dict:
    """Talk to the `zap` daemon container (docker-compose.yml) over its REST API.

    Always spiders the target first. When `active` is true (destructive
    confirmation + a policy that allows intrusive scanning — see
    policy_for().allow_intrusive_template_tags in run_zap()), this also runs
    a genuine ZAP active scan (real attack payloads against every URL the
    spider found) via /JSON/ascan/action/scan/ and waits for it to finish,
    exactly like zap-full-scan.py would — just over REST instead of the
    ZAP CLI wrapper script. Otherwise it stays spider + passive-scan only,
    matching what zap-baseline.py does for safe/caution modes.
    """
    base = (getattr(settings, "ZAP_SERVICE_URL", "") or "").rstrip("/")
    if not base:
        return {"status": "UNAVAILABLE", "findings": [], "reason": "ZAP_SERVICE_URL is empty"}
    mode = "passive+client-spider"
    try:
        headers = {"X-ZAP-API-Key": settings.ZAP_API_KEY} if settings.ZAP_API_KEY else {}
        overall_deadline = time.monotonic() + max(10, timeout_seconds - 90)  # reserve time to collect alerts
        timeout = httpx.Timeout(20.0, connect=30.0)
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            # The Java daemon can take 15-40s to finish booting after
            # `docker compose up` — poll its version endpoint instead of
            # failing on the very first request.
            ver = None
            last_err = "no response"
            ready_deadline = min(overall_deadline, time.monotonic() + 180)
            while time.monotonic() < ready_deadline:
                _t0 = time.monotonic()
                try:
                    ver = await client.get(f"{base}/JSON/core/view/version/")
                    _trace.emit_http(method="GET", url=f"{base}/JSON/core/view/version/", request_headers=ver.request.headers,
                                     status=ver.status_code, reason=ver.reason_phrase, response_headers=ver.headers,
                                     response_body=ver.content[:2048], response_content_type=ver.headers.get("content-type", ""),
                                     duration_ms=(time.monotonic()-_t0)*1000, source="zap-api")
                    if ver.status_code < 400:
                        break
                    last_err = f"HTTP {ver.status_code}"
                except httpx.HTTPError as exc:
                    last_err = f"{type(exc).__name__}: {str(exc)[:120]}"
                    _trace.emit_http(method="GET", url=f"{base}/JSON/core/view/version/", request_headers={},
                                     duration_ms=(time.monotonic()-_t0)*1000, error=last_err, source="zap-api")
                await asyncio.sleep(2)
            if ver is None or ver.status_code >= 400:
                return {"status": "FAILED", "findings": [],
                        "reason": f"ZAP daemon at {base} did not answer within 180s ({last_err}); check `docker compose logs zap`"}

            access = await _zap_request(client, "GET", f"{base}/JSON/core/action/accessUrl/", params={"url": target, "followRedirects": "true"})
            access_ok = access.status_code < 400
            access_body = {}
            if access.headers.get("content-type", "").startswith("application/json"):
                try:
                    access_body = access.json()
                except Exception:
                    access_body = {}
            # ZAP's accessUrl action returns 200 with an embedded error code
            # (e.g. "url_not_found", "illegal_parameter") when it *did*
            # reach the network layer but the request itself failed, and it
            # can also just hang/return a non-2xx if the daemon rejected the
            # call outright. Either way, capture the signal now — the
            # spider/alerts calls below always talk to the ZAP container
            # itself (which is always up), so they can never see this.
            access_error = access_body.get("code") if isinstance(access_body, dict) else None

            spider = await _zap_request(client, "GET", f"{base}/JSON/spider/action/scan/", params={"url": target, "recurse": "true", "maxChildren": "500"})
            spider_id = (spider.json().get("scan") if spider.headers.get("content-type", "").startswith("application/json") else None)
            spider_deadline = min(overall_deadline, time.monotonic() + 600)
            while spider_id and time.monotonic() < spider_deadline:
                await asyncio.sleep(1)
                state = await _zap_request(client, "GET", f"{base}/JSON/spider/view/status/", params={"scanId": spider_id})
                _zap_liveness()
                try:
                    pct = int(state.json().get("status", "100"))
                except Exception:
                    pct = 100
                if pct >= 100:
                    break

            # --- Seed ZAP's site tree -------------------------------------------
            # Some single-page applications expose almost nothing to the classic
            # spider, so the active scan may run its injection rules against zero
            # parameters (0 messages sent). Feed it the URLs MIRSAD's own crawler
            # found, then run the AJAX spider (real browser) on the target.
            seeded = 0
            try:
                seen_seed = set()
                for u in (seed_urls or [])[:int(getattr(settings, "ZAP_MAX_SEED_URLS", 1500))]:
                    try:
                        nu = normalize_engine_target(u)
                    except Exception:
                        continue
                    if not nu or nu in seen_seed or time.monotonic() >= overall_deadline:
                        continue
                    seen_seed.add(nu)
                    r = await _zap_request(client, "GET", f"{base}/JSON/core/action/accessUrl/", params={"url": nu, "followRedirects": "true"}, retries=2)
                    if r.status_code < 400:
                        seeded += 1
            except Exception as exc:
                logger.warning("ZAP seeding failed: %s", type(exc).__name__)
            ajax_status = None
            if getattr(settings, "ZAP_ENABLE_AJAX_SPIDER", True):
                try:
                    started_ajax = await _zap_request(client, "GET", f"{base}/JSON/ajaxSpider/action/scan/", params={"url": target, "inScope": "false", "subtreeOnly": "true"}, retries=2)
                    if started_ajax.status_code < 400:
                        ajax_deadline = min(overall_deadline, time.monotonic() + int(getattr(settings, "ZAP_AJAX_SPIDER_MAX_SECONDS", 1800)))
                        while time.monotonic() < ajax_deadline:
                            await asyncio.sleep(5)
                            st = await _zap_request(client, "GET", f"{base}/JSON/ajaxSpider/view/status/", retries=2)
                            _zap_liveness()
                            try:
                                ajax_status = st.json().get("status")
                            except Exception:
                                ajax_status = None
                            if ajax_status == "stopped":
                                break
                        if ajax_status != "stopped":
                            await _zap_request(client, "GET", f"{base}/JSON/ajaxSpider/action/stop/", retries=1)
                except Exception as exc:
                    logger.warning("ZAP AJAX spider unavailable: %s", type(exc).__name__)
            mode = f"{mode}+seeded({seeded})+ajax({ajax_status or 'n/a'})"

            if active:
                # ZAP's FAQ ("how can you speed up scans"): more threads, bounded rules. The defaults
                # (2 threads/host, unbounded rule time) left one slow rule holding the scan for hours.
                # Best-effort: an option the running ZAP rejects must never fail the scan.
                _remaining_min = max(1, int((overall_deadline - time.monotonic()) // 60))
                for _opt, _val in (
                    ("setOptionThreadPerHost", int(getattr(settings, "ZAP_ASCAN_THREADS_PER_HOST", 8))),
                    ("setOptionMaxRuleDurationInMins", int(getattr(settings, "ZAP_ASCAN_MAX_RULE_MINUTES", 5))),
                    ("setOptionMaxScanDurationInMins", _remaining_min),
                ):
                    try:
                        await _zap_request(client, "GET", f"{base}/JSON/ascan/action/{_opt}/", params={"Integer": str(_val)}, retries=1)
                    except Exception as exc:
                        logger.debug("ZAP %s not applied: %s", _opt, type(exc).__name__)
                ascan = await _zap_request(client, "GET", f"{base}/JSON/ascan/action/scan/", params={"url": target, "recurse": "true"})
                ascan_id = (ascan.json().get("scan") if ascan.headers.get("content-type", "").startswith("application/json") else None)
                if ascan_id is not None:
                    mode = "active+passive+client-spider"
                    while time.monotonic() < overall_deadline:
                        await asyncio.sleep(2)
                        state = await _zap_request(client, "GET", f"{base}/JSON/ascan/view/status/", params={"scanId": ascan_id})
                        _zap_liveness()
                        try:
                            pct = int(state.json().get("status", "100"))
                        except Exception:
                            pct = 100
                        if pct >= 100:
                            break
                # Let passive scanning drain the records the active scan generated.
                pscan_deadline = min(overall_deadline, time.monotonic() + 60)
                while time.monotonic() < pscan_deadline:
                    rtc = await _zap_request(client, "GET", f"{base}/JSON/pscan/view/recordsToScan/")
                    try:
                        remaining = int(rtc.json().get("recordsToScan", "0"))
                    except Exception:
                        remaining = 0
                    if remaining <= 0:
                        break
                    await asyncio.sleep(2)

            findings=[]; alerts_ok=True; start=0; page_size=250
            # Evidence collection has its own 2h budget (independent of the scan
            # phase) so reaching the scan deadline never truncates the alerts.
            evidence_deadline = time.monotonic() + max(600, int(getattr(settings, "EXTERNAL_EVIDENCE_COLLECTION_TIMEOUT_SECONDS", 7200)))
            evidence_deadline_hit = False
            while True:
                if time.monotonic() >= evidence_deadline:
                    evidence_deadline_hit = True; break
                page=await _zap_request(client,"GET",f"{base}/JSON/core/view/alerts/",params={"baseurl":target,"start":str(start),"count":str(page_size)})
                if page.status_code >= 400:
                    alerts_ok=False; break
                data=page.json() if page.headers.get("content-type","").startswith("application/json") else {}
                batch=data.get("alerts") or []
                for a in batch:
                    item={"plugin_id":a.get("pluginId"),"name":a.get("name","ZAP alert"),"risk":_zap_risk(a.get("riskcode") if a.get("riskcode") is not None else a.get("risk")),"riskcode":a.get("riskcode"),"riskdesc":a.get("riskdesc"),"confidence":a.get("confidence"),"url":a.get("url") or target,"param":a.get("param"),"method":a.get("method"),"alertRef":a.get("alertRef"),"wascid":a.get("wascid"),"cwe":(f"CWE-{a.get('cweid')}" if str(a.get("cweid") or "").lstrip("-").isdigit() and int(a.get("cweid")) > 0 else None),"sourceid":a.get("sourceid"),"messageId":a.get("messageId"),"evidence":a.get("evidence"),"description":a.get("description"),"solution":a.get("solution"),"reference":a.get("reference"),"passive":not active,"raw_locator":f"alert:{start+len(findings)}"}
                    message_id=a.get("messageId")
                    if message_id is not None:
                        try:
                            message_resp=await _zap_request(client,"GET",f"{base}/JSON/core/view/message/",params={"id":str(message_id)})
                            if message_resp.status_code < 400 and message_resp.headers.get("content-type","").startswith("application/json"):
                                message_data=message_resp.json()
                                item["request"]=message_data.get("requestHeader") or message_data.get("request")
                                item["response"]=message_data.get("responseHeader") or message_data.get("response")
                        except Exception as exc:
                            item["message_error"]=type(exc).__name__
                    findings.append(item)
                if len(batch)<page_size: break
                start += len(batch)
            urls=await _zap_request(client,"GET",f"{base}/JSON/core/view/urls/")
            discovered_urls=(urls.json().get("urls") or []) if urls.status_code < 400 else []
            # A spider that only ever "saw" the seed URL (or nothing at all)
            # and produced zero alerts is indistinguishable, at the ZAP-API
            # level, from "target has no content" — but in practice it
            # almost always means ZAP never got past the TCP/TLS layer with
            # the real target (handshake rejected, WAF/CDN fingerprint
            # block, wrong SNI/cipher, connection reset, etc). Report that
            # honestly instead of a silent COMPLETED with empty results.
            non_seed_urls = [u for u in discovered_urls if u and u.rstrip("/") != target.rstrip("/")]
            reached_target = access_ok and not access_error
            if not reached_target and not non_seed_urls and not findings:
                reason_bits = []
                if not access_ok:
                    reason_bits.append(f"accessUrl returned HTTP {access.status_code}")
                if access_error:
                    reason_bits.append(f"ZAP reported error code '{access_error}'")
                reason_bits.append("spider discovered no pages beyond the seed URL and no alerts were raised")
                return {
                    "status": "PARTIAL",
                    "binary": "ZAP service",
                    "version": (ver.json().get("version") if ver.status_code < 400 else None),
                    "findings": findings,
                    "urls": discovered_urls,
                    "mode": mode,
                    "reason": (
                        "ZAP could not establish a working connection to the target "
                        "(likely TLS handshake rejection, WAF/CDN block, or a "
                        "connection reset by the target); results are empty because "
                        "the scan never reached the target, not because the target "
                        "has nothing to find. " + "; ".join(reason_bits)
                    ),
                }
            deadline_hit=evidence_deadline_hit
            return {"status": "PARTIAL" if deadline_hit or not alerts_ok else "COMPLETED", "binary": "ZAP service",
                    "version": (ver.json().get("version") if ver.status_code < 400 else None),
                    "findings": findings, "urls": discovered_urls, "mode": mode,
                    "raw_report": json.dumps({"target":target,"mode":mode,"alerts":findings,"urls":discovered_urls}, ensure_ascii=False, default=str),
                    "reason": "evidence collection budget exhausted before all ZAP alerts were collected" if deadline_hit else ("alert pagination returned an HTTP error" if not alerts_ok else None)}
    except Exception as exc:
        # `mode` tells us whether this died during/after an active scan —
        # useful to know a 48-minute active scan's alerts were lost to one
        # request, vs. dying during the cheap passive/spider phase.
        return {"status": "FAILED", "findings": [], "mode": mode,
                "reason": f"ZAP service error: {type(exc).__name__} (during '{mode}' phase; retries were exhausted on the failing request)"}