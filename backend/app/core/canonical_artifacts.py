from __future__ import annotations
import hashlib, json, uuid, asyncio, time
from datetime import datetime, timezone
from sqlalchemy import select
from app.core.database import RawArtifactRow, EngineResultRow, FindingSourceRow, session_scope_sync, session_scope
from app.core.raw_artifact_crypto import encrypt_artifact
from app.core.auth_context import tenant_context

def _now(): return datetime.now(timezone.utc)

def _aggregate_stdout_id(aggregate_ids_by_kind: dict[str, str]) -> str | None:
    """Return only the canonical stdout aggregate, never stderr by position."""
    return aggregate_ids_by_kind.get("stdout")

def _bytes(value) -> bytes:
    if isinstance(value,bytes): return value
    if isinstance(value,str): return value.encode("utf-8","surrogatepass")
    return json.dumps(value,ensure_ascii=False,default=str,separators=(",",":")).encode("utf-8")

def persist_engine_result(*, scan_id:str, engine:str, payload:dict, execution_id:str|None=None, tenant_id:str|None=None) -> tuple[str,list[str]]:
    tenant_id=tenant_id or tenant_context.get()
    if not tenant_id: raise PermissionError("tenant context required")
    eid="eng_"+uuid.uuid4().hex
    started=payload.get("started_at"); finished=payload.get("finished_at")
    def dt(v):
        if isinstance(v,datetime): return v
        if isinstance(v,(int,float)): return datetime.fromtimestamp(v,tz=timezone.utc)
        return None
    artifacts=[]
    artifact_by_kind={}
    with session_scope_sync() as db:
        db.add(EngineResultRow(engine_result_id=eid,tenant_id=tenant_id,scan_id=scan_id,execution_id=execution_id,engine=engine,version=payload.get("version"),command=payload.get("command") or [],started_at=dt(started),finished_at=dt(finished),duration_seconds=payload.get("duration_seconds"),exit_code=payload.get("exit_code"),status=str(payload.get("status") or "FAILED"),metadata_json={"reason":payload.get("reason"),"parser_errors":payload.get("parser_errors") or payload.get("parse_error")}))
        candidates=[]
        for kind,key in (("stdout","stdout"),("stderr","stderr"),("report","raw_report"),("json","raw_json"),("output","raw_output")):
            if payload.get(key) not in (None,""): candidates.append((kind,payload[key]))
        for rf in payload.get("raw_files") or []:
            if rf.get("content") not in (None,""): candidates.append(("output",rf.get("content")))
        for idx,(kind,value) in enumerate(candidates):
            raw=_bytes(value); aid="art_"+uuid.uuid4().hex; digest=hashlib.sha256(raw).hexdigest(); enc=encrypt_artifact(raw)
            db.add(RawArtifactRow(artifact_id=aid,tenant_id=tenant_id,scan_id=scan_id,execution_id=execution_id,engine_result_id=eid,tool=engine,kind=kind,content=enc,sha256=digest,size_bytes=len(raw),encoding="fernet+utf-8",part_index=idx,metadata_json={"encrypted":True,"empty":False}))
            artifacts.append(aid)
            artifact_by_kind.setdefault(kind, (aid, digest))
        artifact_by_id = {aid: digest for aid, digest in artifact_by_kind.values()}
        # Bind findings only when their locator identifies the evidence stream.
        # This is deterministic provenance, not a positional guess.
        for item in payload.get("findings") or []:
            if item.get("raw_artifact_id") in artifact_by_id:
                item["raw_artifact_sha256"] = artifact_by_id[item["raw_artifact_id"]]
                continue
            # Ignore an unowned locator supplied by a parser; it cannot prove
            # provenance within this engine execution.
            item.pop("raw_artifact_id", None)
            item.pop("raw_artifact_sha256", None)
            loc=str(item.get("raw_locator") or "")
            aid = None
            if loc.startswith("line:") or loc.startswith("stdout:"):
                aid = artifact_by_kind.get("stdout")
            elif loc.startswith("alert:"):
                aid = artifact_by_kind.get("report")
            elif loc.startswith("results["):
                aid = artifact_by_kind.get("json")
            elif item.get("description") and (engine in ("sqlmap", "ghauri") or item.get("detected_only")):
                aid = artifact_by_kind.get("stdout")
            if aid:
                item["raw_artifact_id"], item["raw_artifact_sha256"] = aid
        return eid,artifacts

def attach_finding_sources(*, scan_id:str, findings:list, engine_result_id:str, artifact_ids:list[str], engine:str, execution_id:str|None=None, tenant_id:str|None=None):
    tenant_id=tenant_id or tenant_context.get()
    if not tenant_id: raise PermissionError("tenant context required")
    with session_scope_sync() as db:
        for f in findings:
            # Never guess an evidence artifact. A locator without a proven
            # artifact is still useful and is preferable to a false provenance link.
            aid=f.raw_artifact_id if f.raw_artifact_id in set(artifact_ids) else None
            db.add(FindingSourceRow(source_id="src_"+uuid.uuid4().hex,tenant_id=tenant_id,scan_id=scan_id,finding_id=f.finding_id,engine=engine,engine_result_id=engine_result_id,execution_id=execution_id,raw_artifact_id=aid,raw_locator=f.raw_locator,observation=f.model_dump(mode="json")))


class CanonicalStreamRecorder:
    """Append-only live stdout/stderr evidence recorder.

    2026-10-05: chunks are now persisted in small batches instead of one DB
    session + commit per output line. With Nuclei, ZAP and SQLMap running at
    once, per-line writes checked out thousands of connections and exhausted
    the small QueuePool (size 2 + overflow 4), which made the API return 500
    for /jobs/{id} and made the scan look failed. Nothing is dropped: a batch is
    flushed when it reaches SCANNER_CHUNK_FLUSH_BYTES or is older than
    SCANNER_CHUNK_FLUSH_SECONDS, and finalize() flushes whatever is left, so
    the evidence set is identical - only the number of rows/transactions drops.
    """
    def __init__(self, *, scan_id:str, engine:str, execution_id:str|None=None, tenant_id:str|None=None):
        self.scan_id=scan_id; self.engine=engine; self.execution_id=execution_id; self.tenant_id=tenant_id or tenant_context.get(); self.engine_result_id="eng_"+uuid.uuid4().hex; self.part_index=0; self.artifact_ids=[]; self.started_at=_now(); self._chunks={"stdout":[],"stderr":[]}; self._chunk_lock=asyncio.Lock()
        self._pending={"stdout":[],"stderr":[]}; self._pending_bytes=0; self._last_flush=time.monotonic()
        if not self.tenant_id: raise PermissionError("tenant context required")
        with session_scope_sync(tenant_id=self.tenant_id) as db:
            db.add(EngineResultRow(engine_result_id=self.engine_result_id,tenant_id=self.tenant_id,scan_id=scan_id,execution_id=execution_id,engine=engine,status="RUNNING",command=[],metadata_json={"streaming":True},started_at=self.started_at))
    def _flush_limits(self) -> tuple[int, float]:
        from app.core.config import settings
        return (max(1024, int(getattr(settings, "SCANNER_CHUNK_FLUSH_BYTES", 16384))),
                max(0.2, float(getattr(settings, "SCANNER_CHUNK_FLUSH_SECONDS", 2.0))))
    async def on_chunk(self, kind:str, value:str|bytes):
        raw=_bytes(value)
        # Progress is recorded on every chunk (in-memory, cheap) so the stall
        # watchdog sees live output even between DB flushes.
        try:
            from app.core.stall_watchdog import touch
            touch(self.scan_id)
        except Exception:
            pass
        if kind in self._chunks:
            self._chunks[kind].append(raw)
        max_bytes, max_age = self._flush_limits()
        async with self._chunk_lock:
            bucket=self._pending.setdefault(kind,[])
            bucket.append(raw); self._pending_bytes+=len(raw)
            if (self._pending_bytes >= max_bytes or (time.monotonic()-self._last_flush) >= max_age) \
                    and time.monotonic() >= getattr(self, "_retry_after", 0.0):
                try:
                    await self._flush_pending_locked()
                except Exception:
                    # DB briefly unreachable: keep buffering (nothing is dropped, finalize() persists the
                    # rest) and retry in a few seconds instead of re-hitting the DB on every output line,
                    # which produced 41 "scanner output callback failed: TimeoutError" and stalled the loop.
                    self._retry_after = time.monotonic() + 10.0
    async def flush(self) -> None:
        """Persist any buffered output now (one DB session for the whole batch)."""
        async with self._chunk_lock:
            await self._flush_pending_locked()
    async def _flush_pending_locked(self) -> None:
        batches=[(kind,b"".join(parts)) for kind,parts in self._pending.items() if parts]
        if not batches:
            self._last_flush=time.monotonic(); return
        rows=[]
        for kind,raw in batches:
            aid="art_"+uuid.uuid4().hex
            rows.append((aid,kind,raw,self.part_index)); self.part_index+=1
        try:
            async with session_scope(tenant_id=self.tenant_id) as db:
                for aid,kind,raw,part_index in rows:
                    db.add(RawArtifactRow(artifact_id=aid,tenant_id=self.tenant_id,scan_id=self.scan_id,execution_id=self.execution_id,engine_result_id=self.engine_result_id,tool=self.engine,kind=kind,content=encrypt_artifact(raw),sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),encoding="fernet+utf-8",part_index=part_index,metadata_json={"encrypted":True,"streaming":True,"batched":True}))
        except Exception:
            # Keep the buffer so the next flush (or finalize) retries it; the
            # in-memory copy in self._chunks still feeds the aggregate artifact.
            self.part_index-=len(rows)
            raise
        for aid,_,_,_ in rows:
            self.artifact_ids.append(aid)
        self._pending={"stdout":[],"stderr":[]}; self._pending_bytes=0; self._last_flush=time.monotonic()
    def finalize(self,payload:dict) -> tuple[str,list[str]]:
        # Keep the live chunks as immutable evidence, then materialize one
        # deterministic aggregate artifact per stream so parser locators such as
        # line:N can point at a stable complete representation. This updates the
        # original RUNNING EngineResult; it never creates a second EngineResult.
        aggregate_ids=[]
        aggregate_ids_by_kind={}
        aggregate_digests_by_kind={}
        with session_scope_sync(tenant_id=self.tenant_id) as db:
            # Persist the last buffered batch (see class docstring) before the
            # aggregate, so chunk_artifact_ids covers every received byte.
            for kind,parts in list(self._pending.items()):
                if not parts: continue
                raw_tail=b"".join(parts); tail_id="art_"+uuid.uuid4().hex
                db.add(RawArtifactRow(artifact_id=tail_id,tenant_id=self.tenant_id,scan_id=self.scan_id,execution_id=self.execution_id,engine_result_id=self.engine_result_id,tool=self.engine,kind=kind,content=encrypt_artifact(raw_tail),sha256=hashlib.sha256(raw_tail).hexdigest(),size_bytes=len(raw_tail),encoding="fernet+utf-8",part_index=self.part_index,metadata_json={"encrypted":True,"streaming":True,"batched":True}))
                self.artifact_ids.append(tail_id); self.part_index+=1
            self._pending={"stdout":[],"stderr":[]}; self._pending_bytes=0
            row=db.get(EngineResultRow,self.engine_result_id)
            if row:
                row.version=payload.get("version"); row.command=payload.get("command") or []; row.finished_at=(datetime.fromtimestamp(payload["finished_at"],tz=timezone.utc) if isinstance(payload.get("finished_at"),(int,float)) else _now()); row.duration_seconds=payload.get("duration_seconds"); row.exit_code=payload.get("exit_code"); row.status=str(payload.get("status") or "FAILED"); row.metadata_json={"reason":payload.get("reason"),"parser_errors":payload.get("parser_errors") or payload.get("parse_error"),"streaming":True,"chunk_artifact_ids":list(self.artifact_ids)}
            # Preserve a final structured report as canonical evidence as well.
            # ZAP's service API returns alerts and sanitized request/response
            # context in ``raw_report`` after the live stream has ended; keeping
            # only stdout/stderr left every ZAP finding without a reproducible
            # artifact link.
            aggregate_inputs = [("stdout", b"".join(self._chunks.get("stdout", []))),
                                ("stderr", b"".join(self._chunks.get("stderr", [])))]
            report_value = payload.get("raw_report")
            if report_value not in (None, ""):
                aggregate_inputs.append(("report", _bytes(report_value)))
            for kind, raw in aggregate_inputs:
                if not raw:
                    continue
                aid="art_"+uuid.uuid4().hex; digest=hashlib.sha256(raw).hexdigest(); part_index=self.part_index
                db.add(RawArtifactRow(artifact_id=aid,tenant_id=self.tenant_id,scan_id=self.scan_id,execution_id=self.execution_id,engine_result_id=self.engine_result_id,tool=self.engine,kind=f"{kind}_aggregate",content=encrypt_artifact(raw),sha256=digest,size_bytes=len(raw),encoding="fernet+utf-8",part_index=part_index,metadata_json={"encrypted":True,"streaming":True,"aggregate":True,"chunk_count":len(self._chunks.get(kind,[]))}))
                aggregate_ids.append(aid); aggregate_ids_by_kind[kind]=aid; aggregate_digests_by_kind[kind]=digest; self.part_index += 1
        all_ids=self.artifact_ids + aggregate_ids
        aggregate_stdout = _aggregate_stdout_id(aggregate_ids_by_kind)
        # Attach a stable aggregate stdout artifact to line-oriented findings.
        # The individual live chunks remain available in all_ids for audit replay.
        if aggregate_stdout:
            for item in payload.get("findings") or []:
                if item.get("raw_artifact_id"):
                    continue
                loc=str(item.get("raw_locator") or "")
                if loc.startswith("line:") or loc.startswith("stdout:") or (self.engine in ("sqlmap", "ghauri") and item.get("description")):
                    item["raw_artifact_id"]=aggregate_stdout
                    item["raw_artifact_sha256"]=aggregate_digests_by_kind["stdout"]
            payload["raw_artifact_id"]=aggregate_stdout
            payload["raw_artifact_sha256"]=aggregate_digests_by_kind["stdout"]
        # ZAP alert locators are indices into its final JSON report, not its
        # process output. Bind them to that report deterministically.
        aggregate_report = aggregate_ids_by_kind.get("report")
        if aggregate_report:
            for item in payload.get("findings") or []:
                if not item.get("raw_artifact_id") and str(item.get("raw_locator") or "").startswith("alert:"):
                    item["raw_artifact_id"] = aggregate_report
                    item["raw_artifact_sha256"] = aggregate_digests_by_kind["report"]
        return self.engine_result_id,all_ids
