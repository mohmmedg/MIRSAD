"""Live execution trace: every request, response, command and output line a scan
produces, attributed to the stage/tool that produced it.

Design notes
------------
* Producers (httpx transport, Playwright routes, subprocess runners, ZAP/DefectDojo
  clients) call ``emit_*`` which is *non-blocking*: it only appends to an in-memory
  queue. Scans can issue thousands of requests, so one synchronous DB transaction
  per request (what ``JobRecord.record_event`` does) would stall the event loop.
* A single daemon thread drains the queue and writes batches, one transaction per
  (execution, batch). Sequence numbers are allocated inside that transaction under
  the same ``SELECT ... FOR UPDATE`` lock on the execution row that
  ``record_event`` uses, so both writers interleave safely.
* Attribution uses ``ContextVar`` so parallel engines (``asyncio.gather``) each
  keep their own stage/tool.
* Secrets are redacted before anything is queued (headers, bearer tokens, common
  query parameters, command-line credentials).
"""
from __future__ import annotations

import contextvars
import logging
import queue
import re
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# ---- limits ---------------------------------------------------------------
MAX_EVENTS_PER_EXECUTION = 40_000
MAX_BODY_CHARS = 4_000
MAX_REQ_BODY_CHARS = 2_000
MAX_OUTPUT_LINE_CHARS = 2_000
MAX_URL_CHARS = 2_000
BATCH_SIZE = 250
FLUSH_INTERVAL_SECONDS = 0.5

# ---- context --------------------------------------------------------------
_job_var: contextvars.ContextVar[Any] = contextvars.ContextVar("mirsad_trace_job", default=None)
_scope_var: contextvars.ContextVar[tuple[str | None, str | None]] = contextvars.ContextVar(
    "mirsad_trace_scope", default=(None, None))


def bind_job(job: Any) -> None:
    """Bind the job whose execution receives trace events (call once per scan task)."""
    _job_var.set(job)


def current_job() -> Any:
    return _job_var.get()


def set_scope(stage: str | None, tool: str | None = None) -> None:
    _scope_var.set((stage, tool))


def clear_scope_if(stage: str) -> None:
    if _scope_var.get()[0] == stage:
        _scope_var.set((None, None))


@contextmanager
def trace_scope(stage: str | None, tool: str | None = None):
    token = _scope_var.set((stage, tool))
    try:
        yield
    finally:
        _scope_var.reset(token)


# ---- redaction ------------------------------------------------------------
_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key",
    "x-auth-token", "x-csrf-token", "x-xsrf-token", "apikey", "x-zap-api-key",
}
_SECRET_QS = re.compile(r"(?i)([?&](?:access_token|token|api[_-]?key|key|secret|password|passwd|auth|sig|signature|session)=)([^&#\s]+)")
_SECRET_ARG = re.compile(r"(?i)^(authorization|cookie|x-api-key|proxy-authorization)\s*:")
_SECRET_FLAGS = {"--cookie", "--auth-cred", "--headers", "--data-urlencode"}
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{8,}")
_JSON_SECRET = re.compile(r'(?i)("(?:password|passwd|secret|token|access_token|refresh_token|api[_-]?key|authorization)"\s*:\s*")([^"]{1,500})(")')


def redact_text(value: str) -> str:
    if not value:
        return value
    value = _SECRET_QS.sub(lambda m: m.group(1) + "***", value)
    value = _BEARER.sub(lambda m: m.group(1) + " ***", value)
    value = _JSON_SECRET.sub(lambda m: m.group(1) + "***" + m.group(3), value)
    return value


def redact_headers(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        items = headers.items() if hasattr(headers, "items") else list(headers or [])
    except Exception:
        return out
    for k, v in items:
        key = k.decode("latin-1") if isinstance(k, bytes) else str(k)
        val = v.decode("latin-1") if isinstance(v, bytes) else str(v)
        if key.lower() in _SENSITIVE_HEADERS:
            val = "***redacted***"
        out[key] = val[:1000]
        if len(out) >= 60:
            break
    return out


def redact_argv(argv: Iterable[str]) -> list[str]:
    out: list[str] = []
    mode = ""  # "hide" -> next arg is a secret, "header" -> next arg is an HTTP header
    for a in (str(x) for x in argv):
        if mode == "hide":
            out.append("***"); mode = ""; continue
        if mode == "header":
            m = _SECRET_ARG.match(a)
            out.append(a[: m.end()] + " ***" if m else redact_text(a)[:MAX_URL_CHARS]); mode = ""; continue
        if a in _SECRET_FLAGS:
            out.append(a); mode = "hide"; continue
        if a in {"-H", "--header", "-header"}:
            out.append(a); mode = "header"; continue
        out.append(redact_text(a)[:MAX_URL_CHARS])
    return out


def _clip(text: Any, limit: int) -> tuple[str, bool]:
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    if len(s) <= limit:
        return s, False
    return s[:limit], True


def body_preview(raw: bytes | str | None, content_type: str = "", limit: int = MAX_BODY_CHARS) -> dict[str, Any]:
    """Safe text preview of a body; binary payloads are described, never dumped."""
    if raw is None or raw == b"" or raw == "":
        return {"size": 0, "text": ""}
    ctype = (content_type or "").lower()
    if isinstance(raw, bytes):
        size = len(raw)
        textual = any(t in ctype for t in ("text", "json", "xml", "javascript", "html", "x-www-form", "yaml")) or not ctype
        if not textual:
            return {"size": size, "text": "", "binary": True, "note": f"binary body ({ctype or 'unknown type'})"}
        text = raw[: limit * 2].decode("utf-8", "replace")
        if "\x00" in text[:512]:
            return {"size": size, "text": "", "binary": True, "note": "binary body"}
    else:
        text = raw
        size = len(raw)
    clipped, was = _clip(redact_text(text), limit)
    return {"size": size, "text": clipped, "truncated": was}


# ---- persisted per-execution statistics -------------------------------------
# The numbers the execution page shows (event/request/command/error counts per
# stage) used to be computed in the browser from whatever events happened to be
# loaded, so they were empty/partial whenever the page had not been open. They
# are now accumulated by the writers (under the same execution-row lock that
# allocates sequence numbers) and stored in scan_executions.metadata["stats"].
_BUCKETS = ("req", "ok", "redir", "c4", "c5", "fail", "cmds", "errs")


def empty_stats() -> dict:
    return {"total": 0, "last_sequence": 0, "stages": {}, "buckets": {}}


def tally_event(stats: dict, event_type: str, stage: str | None, payload: dict | None, sequence: int) -> None:
    """Fold one event into ``stats`` (mutates). Mirrors the UI's isErrorEvent/status buckets."""
    p = payload or {}
    key = stage or "_none"
    stats["total"] = int(stats.get("total", 0)) + 1
    stats["last_sequence"] = max(int(stats.get("last_sequence", 0)), int(sequence))
    st = stats.setdefault("stages", {}).setdefault(key, {})
    st[event_type] = int(st.get(event_type, 0)) + 1
    b = stats.setdefault("buckets", {}).setdefault(key, {k: 0 for k in _BUCKETS})
    err = False
    if event_type in ("http", "browser_request"):
        b["req"] += 1
        code = (p.get("response") or {}).get("status")
        if p.get("error"): b["fail"] += 1
        elif isinstance(code, int):
            if code >= 500: b["c5"] += 1
            elif code >= 400: b["c4"] += 1
            elif code >= 300: b["redir"] += 1
            elif code >= 200: b["ok"] += 1
        err = bool(p.get("error")) or (code or 0) >= 400
    elif event_type == "command":
        b["cmds"] += 1
    elif event_type == "command_exit":
        err = (p.get("exit_code") or 0) != 0 or str(p.get("state")) in ("FAILED", "TIMEOUT")
    elif event_type == "output":
        err = p.get("stream") == "stderr"
    elif event_type == "stage":
        err = p.get("status") == "failed"
    elif event_type == "external_result":
        err = str(p.get("status")) in ("FAILED", "TIMEOUT", "UNAVAILABLE")
    if err:
        b["errs"] += 1


def add_events_to_meta(execution: Any, events: Iterable[tuple[str, str | None, dict | None, int]]) -> None:
    """Update ``execution.meta['stats']`` for (type, stage, payload, sequence) tuples.
    No-op when the execution predates stats (the summary endpoint backfills those)."""
    meta = dict(execution.meta or {})
    stats = meta.get("stats")
    if not isinstance(stats, dict):
        return
    stats = {**stats, "stages": {k: dict(v) for k, v in (stats.get("stages") or {}).items()},
             "buckets": {k: dict(v) for k, v in (stats.get("buckets") or {}).items()}}
    for et, stage, payload, seq in events:
        tally_event(stats, et, stage, payload, seq)
    meta["stats"] = stats
    execution.meta = meta  # reassign: JSON columns don't detect in-place mutation


# ---- queue + flusher ------------------------------------------------------
_q: "queue.Queue[tuple[Any, dict]]" = queue.Queue(maxsize=50_000)
_counts: dict[str, int] = {}
_counts_lock = threading.Lock()
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()
_stop = threading.Event()


def _ensure_thread() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    with _thread_lock:
        if _thread and _thread.is_alive():
            return
        _stop.clear()
        _thread = threading.Thread(target=_run, name="mirsad-trace-flusher", daemon=True)
        _thread.start()


def _enqueue(event: dict) -> None:
    job = _job_var.get()
    if job is None:
        return
    execution_id = getattr(job, "execution_id", None)
    if not execution_id:
        return
    with _counts_lock:
        n = _counts.get(execution_id, 0)
        if n >= MAX_EVENTS_PER_EXECUTION + 1:
            return
        _counts[execution_id] = n + 1
        if n == MAX_EVENTS_PER_EXECUTION:
            event = {"event_type": "trace_truncated", "stage": event.get("stage"), "tool": event.get("tool"),
                     "message": f"Trace limit of {MAX_EVENTS_PER_EXECUTION} events reached; later traffic is not recorded.",
                     "payload": {}}
    stage, tool = _scope_var.get()
    event.setdefault("stage", stage)
    event.setdefault("tool", tool)
    event["ts"] = time.time()
    try:
        from app.core.auth_context import tenant_context
        event["_tenant"] = tenant_context.get()
    except Exception:
        event["_tenant"] = None
    try:
        _q.put_nowait((job, event))
        _ensure_thread()
    except queue.Full:
        pass  # never block a scan because the trace is behind


def _run() -> None:
    while not _stop.is_set():
        batch: list[tuple[Any, dict]] = []
        try:
            batch.append(_q.get(timeout=FLUSH_INTERVAL_SECONDS))
        except queue.Empty:
            continue
        deadline = time.monotonic() + FLUSH_INTERVAL_SECONDS
        while len(batch) < BATCH_SIZE and time.monotonic() < deadline:
            try:
                batch.append(_q.get(timeout=0.05))
            except queue.Empty:
                break
        _write_batch(batch)


def _write_batch(batch: list[tuple[Any, dict]]) -> None:
    if not batch:
        return
    by_job: dict[int, tuple[Any, list[dict]]] = {}
    for job, ev in batch:
        by_job.setdefault(id(job), (job, []))[1].append(ev)
    for job, events in by_job.values():
        try:
            job_write_events(job, events)
        except Exception:
            logger.warning("trace batch write failed (%d events lost)", len(events), exc_info=True)


def job_write_events(job: Any, events: list[dict]) -> None:
    from datetime import datetime, timezone
    from sqlalchemy import func, select
    from app.core.database import ScanExecutionEventRow, ScanExecutionRow, session_scope_sync, with_db_retry
    from app.core.job_manager import _owned_row, jsonable

    execution_id = getattr(job, "execution_id", None)
    if not execution_id:
        logger.warning("execution events dropped (%d): job %s has no execution_id", len(events), getattr(job, "job_id", "?"))
        return
    # The flusher runs in its own thread, which has no request/task context:
    # restore the tenant the events were produced under (RLS + _owned_row need it).
    # Fall back to the tenant recorded on the job itself so a missing per-event
    # tenant can never make _owned_row() fail closed and silently drop the batch.
    try:
        from app.core.auth_context import tenant_context
        tenant_context.set(next((e.get("_tenant") for e in events if e.get("_tenant")), None)
                           or getattr(job, "tenant_id", None))
    except Exception:
        pass

    def _txn():
        with session_scope_sync() as db:
            row = _owned_row(db, job.job_id)
            if not row:
                logger.warning("execution events dropped (%d): job %s not visible under tenant context", len(events), job.job_id)
                return
            execution = db.execute(select(ScanExecutionRow).where(
                ScanExecutionRow.execution_id == execution_id,
                ScanExecutionRow.tenant_id == row.tenant_id).with_for_update()).scalar_one_or_none()
            if not execution:
                logger.warning("execution events dropped (%d): execution %s has no scan_executions row", len(events), execution_id)
                return
            last = db.execute(select(func.max(ScanExecutionEventRow.sequence)).where(
                ScanExecutionEventRow.tenant_id == row.tenant_id,
                ScanExecutionEventRow.execution_id == execution_id)).scalar_one() or 0
            tallied: list[tuple[str, str | None, dict | None, int]] = []
            for i, ev in enumerate(events, start=1):
                tallied.append((str(ev["event_type"])[:64], (str(ev.get("stage") or "")[:128] or None), ev.get("payload") or {}, int(last) + i))
                db.add(ScanExecutionEventRow(
                    event_id=uuid.uuid4().hex, tenant_id=row.tenant_id, scan_id=row.job_id,
                    execution_id=execution_id, operation_id=None, sequence=int(last) + i,
                    event_type=str(ev["event_type"])[:64], stage=(str(ev.get("stage") or "")[:128] or None),
                    tool=(str(ev.get("tool") or "")[:128] or None), message=str(ev.get("message") or "")[:4000],
                    payload=jsonable(ev.get("payload") or {}),
                    created_at=datetime.fromtimestamp(ev.get("ts") or time.time(), tz=timezone.utc)))
            add_events_to_meta(execution, tallied)

    with_db_retry(_txn)


def flush(timeout: float = 10.0) -> None:
    """Synchronously drain whatever is queued (called when an execution ends)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        batch: list[tuple[Any, dict]] = []
        while len(batch) < BATCH_SIZE:
            try:
                batch.append(_q.get_nowait())
            except queue.Empty:
                break
        if not batch:
            # the background thread may hold a batch it is writing; give it a moment
            time.sleep(0.2)
            if _q.empty():
                return
            continue
        _write_batch(batch)


def forget(execution_id: str | None) -> None:
    if execution_id:
        with _counts_lock:
            _counts.pop(execution_id, None)


# ---- producers ------------------------------------------------------------
def emit(event_type: str, message: str, payload: dict | None = None, *, stage: str | None = None, tool: str | None = None) -> None:
    ev: dict[str, Any] = {"event_type": event_type, "message": message[:4000], "payload": payload or {}}
    if stage:
        ev["stage"] = stage
    if tool:
        ev["tool"] = tool
    _enqueue(ev)


def emit_http(*, method: str, url: str, request_headers: Any = None, request_body: Any = None,
              status: int | None = None, reason: str = "", response_headers: Any = None,
              response_body: Any = None, response_content_type: str = "", duration_ms: float | None = None,
              error: str | None = None, source: str = "httpx", resource_type: str | None = None,
              http_version: str | None = None, remote_ip: str | None = None) -> None:
    """One request/response pair (or failed attempt)."""
    safe_url = redact_text(str(url))[:MAX_URL_CHARS]
    req_ct = ""
    try:
        req_ct = (request_headers.get("content-type") if hasattr(request_headers, "get") else "") or ""
    except Exception:
        pass
    payload: dict[str, Any] = {
        "source": source,
        "request": {"method": method.upper(), "url": safe_url, "headers": redact_headers(request_headers),
                    "body": body_preview(request_body, str(req_ct), MAX_REQ_BODY_CHARS)},
        "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
    }
    if resource_type:
        payload["resource_type"] = resource_type
    if status is not None:
        payload["response"] = {"status": status, "reason": reason, "headers": redact_headers(response_headers),
                               "body": body_preview(response_body, response_content_type),
                               **({"http_version": http_version} if http_version else {}),
                               **({"remote_ip": remote_ip} if remote_ip else {})}
    if error:
        payload["error"] = error[:600]
    head = f"{method.upper()} {safe_url}"
    tail = f" → {status}" if status is not None else (f" ✗ {error[:120]}" if error else "")
    _enqueue({"event_type": "http", "message": (head + tail)[:3900], "payload": payload})


def emit_command(argv: Iterable[str], *, cwd: str | None = None, timeout: int | float | None = None, operation: str = "") -> None:
    red = redact_argv(argv)
    _enqueue({"event_type": "command", "message": " ".join(red)[:3900],
              "payload": {"command": " ".join(red), "argv": red, "cwd": cwd, "timeout_seconds": timeout, "operation": operation}})


def emit_output(stream: str, line: str) -> None:
    text, was = _clip(redact_text(line.rstrip("\n")), MAX_OUTPUT_LINE_CHARS)
    if not text:
        return
    _enqueue({"event_type": "output", "message": text[:3900],
              "payload": {"stream": stream, **({"truncated": True} if was else {})}})


def emit_exit(argv0: str, rc: int | None, duration: float, state: str, reason: str = "") -> None:
    _enqueue({"event_type": "command_exit",
              "message": f"{argv0} exited rc={rc} state={state} in {duration:.1f}s" + (f" ({reason})" if reason else ""),
              "payload": {"exit_code": rc, "state": state, "duration_seconds": round(duration, 2), "reason": reason}})
