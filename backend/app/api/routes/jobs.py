import logging

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from starlette.concurrency import run_in_threadpool
from app.core.security import verify_api_key, require_analyst, require_viewer, require_scanner_run, require_scanner_pause, require_scanner_cancel
from app.core.job_manager import job_manager, JobRecord, read_live_result_cached
from app.core.database import ScanExecutionRow, ScanExecutionEventRow, session_scope_sync, with_db_retry
from app.core.auth_context import tenant_context
from app.schemas.jobs import JobSnapshot, ExecutionSummary, ExecutionEvent

router = APIRouter(prefix='/jobs', tags=['jobs'])
logger = logging.getLogger(__name__)


@router.get('/active', response_model=list[JobSnapshot], dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def active_jobs():
    """Return durable jobs still in progress for the authenticated tenant.

    This is intentionally DB-backed so a browser refresh/new tab can recover
    the running scan without depending on React state or an old WebSocket.
    """
    from app.core.auth_context import tenant_context
    from app.core.database import JobRow, session_scope
    from sqlalchemy import select
    tid = tenant_context.get() or "legacy"
    async with session_scope(tid) as db:
        # Only the 3 columns JobRecord needs; full rows carry ~500KB of payload/result each.
        rows = (await db.execute(
            select(JobRow.job_id, JobRow.job_type, JobRow.target).where(JobRow.tenant_id == tid, JobRow.status.in_(["pending", "running", "paused"]))
            .order_by(JobRow.created_at.desc())
        )).all()
    return [JobRecord(row.job_id,row.job_type,row.target,job_manager._tasks.get(row.job_id)).snapshot() for row in rows]

@router.post('/cancel-active', dependencies=[Depends(verify_api_key), Depends(require_scanner_cancel)])
async def cancel_active_jobs():
    """Cancel every in-progress job for the caller's tenant.

    2026-09-16: added so the frontend can call this on logout (see
    signOut() in auth/supabase.ts) — a scan the user started previously kept
    running against the target in the background indefinitely after they
    signed out, with no way to tell it was still going from a signed-out
    session.
    """
    from app.core.auth_context import tenant_context
    from app.core.database import JobRow, session_scope
    from sqlalchemy import select
    tid = tenant_context.get() or "legacy"
    async with session_scope(tid) as db:
        job_ids = (await db.execute(
            select(JobRow.job_id).where(JobRow.tenant_id == tid, JobRow.status.in_(["pending", "running", "paused"]))
        )).scalars().all()
    cancelled = [jid for jid in job_ids if await job_manager.cancel(jid)]
    return {"cancelled": cancelled}

def _job(job_id):
    job = job_manager.get(job_id)
    if not job: raise HTTPException(status_code=404, detail='Job not found')
    return job

@router.get('/{job_id}', response_model=JobSnapshot, dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def get_job(job_id: str): return _job(job_id).snapshot()

@router.post('/{job_id}/pause', response_model=JobSnapshot, dependencies=[Depends(verify_api_key), Depends(require_scanner_pause)])
async def pause_job(job_id: str):
    if not await job_manager.pause(job_id): raise HTTPException(status_code=409, detail='Job is not running')
    return _job(job_id).snapshot()

@router.post('/{job_id}/resume', response_model=JobSnapshot, dependencies=[Depends(verify_api_key), Depends(require_scanner_pause)])
async def resume_job(job_id: str):
    if not await job_manager.resume(job_id): raise HTTPException(status_code=409, detail='Job is not paused')
    return _job(job_id).snapshot()

@router.post('/{job_id}/cancel', response_model=JobSnapshot, dependencies=[Depends(verify_api_key), Depends(require_scanner_cancel)])
async def cancel_job(job_id: str):
    if not await job_manager.cancel(job_id): raise HTTPException(status_code=409, detail='Job cannot be cancelled')
    return _job(job_id).snapshot()


@router.get('/{job_id}/live-result', dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def live_result(job_id: str, since: str | None = None):
    """Return the durable partial raw engine bundle for the selected scan.
    This endpoint is intentionally separate from the progress snapshot so the
    progress page never receives or renders raw result data.

    Served from Redis while the scan runs (no database read). ``since`` is the
    ``updated_at`` the client already holds: when nothing changed the response is the
    tiny ``{"unchanged": true}`` instead of the full (hundreds of KB) bundle."""
    job = await run_in_threadpool(_job, job_id)
    tid = tenant_context.get() or "legacy"
    def _unchanged(live):
        return bool(since) and isinstance(live, dict) and live.get("updated_at") == since
    def _read():
        cached = read_live_result_cached(tid, job_id)
        if cached:
            return {"unchanged": True, "updated_at": since} if _unchanged(cached) else cached
        row = job._row(defer_result=True)
        if not row:
            raise HTTPException(status_code=404, detail='Job not found')
        live = (row.payload or {}).get("_live_result")
        if live:
            return {"unchanged": True, "updated_at": since} if _unchanged(live) else live
        return job._result_only() if row.status in {"completed","partial","failed","cancelled"} else {}
    return await run_in_threadpool(lambda: with_db_retry(_read))

@router.get('/{job_id}/executions', response_model=list[ExecutionSummary], dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def list_job_executions(job_id: str):
    job = await run_in_threadpool(_job, job_id)
    def _read():
        with session_scope_sync() as db:
            from sqlalchemy import func
            tid = tenant_context.get() or 'legacy'
            rows = db.query(ScanExecutionRow).filter(ScanExecutionRow.job_id == job_id, ScanExecutionRow.tenant_id == tid).order_by(ScanExecutionRow.started_at.desc()).all()
            ids = [row.execution_id for row in rows]
            counts = {}
            if ids:
                counts = {eid: int(count) for eid, count in db.query(ScanExecutionEventRow.execution_id, func.count(ScanExecutionEventRow.event_id)).filter(ScanExecutionEventRow.execution_id.in_(ids), ScanExecutionEventRow.tenant_id == tid).group_by(ScanExecutionEventRow.execution_id).all()}
            return [ExecutionSummary(execution_id=row.execution_id, scan_id=row.scan_id, job_id=row.job_id, attempt=row.attempt, job_type=row.job_type, target=row.target, status=row.status, current_engine=row.current_engine, metadata=row.meta or {}, started_at=row.started_at, finished_at=row.finished_at, event_count=counts.get(row.execution_id, 0)) for row in rows]
    return await run_in_threadpool(lambda: with_db_retry(_read))

@router.get('/{job_id}/executions/{execution_id}/events', response_model=list[ExecutionEvent], dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def list_execution_events(job_id: str, execution_id: str, limit: int = 2000, offset: int = 0, after_sequence: int | None = None, stage: str | None = None, event_type: str | None = None, before_sequence: int | None = None, newest_first: bool = False):
    await run_in_threadpool(_job, job_id)
    def _read():
        with session_scope_sync() as db:
            tid = tenant_context.get() or 'legacy'
            execution = db.query(ScanExecutionRow).filter(ScanExecutionRow.execution_id == execution_id, ScanExecutionRow.job_id == job_id, ScanExecutionRow.tenant_id == tid).first()
            if not execution: raise HTTPException(status_code=404, detail='Execution not found')
            query = db.query(ScanExecutionEventRow).filter(ScanExecutionEventRow.execution_id == execution_id, ScanExecutionEventRow.tenant_id == tid)
            if after_sequence is not None:
                query = query.filter(ScanExecutionEventRow.sequence > max(0, int(after_sequence)))
            if stage:
                query = query.filter(ScanExecutionEventRow.stage == stage)
            if event_type:
                kinds = [k.strip() for k in event_type.split(',') if k.strip()][:12]
                if kinds: query = query.filter(ScanExecutionEventRow.event_type.in_(kinds))
            if before_sequence is not None:
                query = query.filter(ScanExecutionEventRow.sequence < int(before_sequence))
            if newest_first:
                rows = query.order_by(ScanExecutionEventRow.sequence.desc()).limit(min(5000, max(1, limit))).all()
                rows.reverse()
            else:
                rows = query.order_by(ScanExecutionEventRow.sequence.asc()).offset(0 if after_sequence is not None else max(0, offset)).limit(min(5000, max(1, limit))).all()
            return [ExecutionEvent(event_id=r.event_id, execution_id=r.execution_id, scan_id=r.scan_id, operation_id=r.operation_id, sequence=r.sequence, event_type=r.event_type, stage=r.stage, tool=r.tool, message=r.message, payload=r.payload or {}, created_at=r.created_at) for r in rows]
    return await run_in_threadpool(lambda: with_db_retry(_read))

@router.get('/{job_id}/executions/{execution_id}/events-summary', dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def execution_events_summary(job_id: str, execution_id: str):
    """Persisted per-stage counters (events by type + request/command/error buckets).

    Served from scan_executions.metadata['stats'], which the trace writers keep
    current whether or not any browser is open. Executions that predate this are
    backfilled once, under the same row lock the writers use, then served the same way.
    """
    await run_in_threadpool(_job, job_id)
    def _read():
        from sqlalchemy import select
        from app.core.execution_trace import empty_stats, tally_event
        with session_scope_sync() as db:
            tid = tenant_context.get() or 'legacy'
            ex = db.execute(select(ScanExecutionRow).where(
                ScanExecutionRow.execution_id == execution_id, ScanExecutionRow.job_id == job_id,
                ScanExecutionRow.tenant_id == tid).with_for_update()).scalar_one_or_none()
            if not ex: raise HTTPException(status_code=404, detail='Execution not found')
            stats = (ex.meta or {}).get('stats')
            if not isinstance(stats, dict):
                stats = empty_stats()
                rows = db.query(ScanExecutionEventRow.sequence, ScanExecutionEventRow.event_type, ScanExecutionEventRow.stage, ScanExecutionEventRow.payload).filter(
                    ScanExecutionEventRow.execution_id == execution_id, ScanExecutionEventRow.tenant_id == tid
                ).order_by(ScanExecutionEventRow.sequence.asc()).yield_per(500)
                for seq, et, st, pl in rows:
                    tally_event(stats, et, st, pl, seq)
                ex.meta = {**(ex.meta or {}), 'stats': stats}
            return stats
    return await run_in_threadpool(lambda: with_db_retry(_read))

_WS_MAX_STREAM_SECONDS = 60 * 60  # re-authenticate at least hourly


@router.websocket('/{job_id}/ws')
async def job_progress_ws(websocket: WebSocket, job_id: str):
    """Authenticated live job stream.

    Browser WebSocket cannot set arbitrary Authorization headers. The frontend
    therefore sends the existing Supabase bearer token in the
    Sec-WebSocket-Protocol header as `bearer,<token>`. The server verifies the
    token and then streams the durable DB-backed snapshot, so this also works
    when the scan executes in a separate worker process.
    """
    from fastapi import WebSocketDisconnect
    from app.core.auth import _authenticate_supabase
    from app.core.auth_context import tenant_context
    import asyncio

    await websocket.accept(subprotocol=(websocket.headers.get('sec-websocket-protocol','').split(',')[0].strip() or None))
    try:
        raw=websocket.headers.get('sec-websocket-protocol','')
        parts=[p.strip() for p in raw.split(',') if p.strip()]
        scheme=parts[0].lower() if parts else ""
        credential=parts[1] if len(parts) >= 2 else None
        if not credential or scheme not in {"bearer","api-key"}:
            await websocket.close(code=4401, reason='Authentication required')
            return
        if scheme == "bearer":
            principal=await _authenticate_supabase(credential)
        else:
            from app.core.auth import authenticate_request
            principal=await authenticate_request(None, credential)
        # Same minimum role as the REST read endpoints (require_viewer). Tenant isolation of
        # the job itself is enforced inside job_manager.get() (_owned_row fails closed).
        from app.core.auth import ROLE_RANK
        if ROLE_RANK.get(getattr(principal, "role", ""), 0) < ROLE_RANK["viewer"]:
            await websocket.close(code=4403, reason='Insufficient role')
            return
        tenant_context.set(principal.tenant_id)
        # job_manager.get() does a synchronous DB read: keep it off the event loop
        # (to_thread copies the tenant ContextVar).
        job=await asyncio.to_thread(job_manager.get, job_id)
        if not job:
            await websocket.close(code=4404, reason='Job not found')
            return
        last=None
        opened=asyncio.get_running_loop().time()
        while True:
            # A stream authenticated once must not live forever (the bearer token expires).
            if asyncio.get_running_loop().time() - opened > _WS_MAX_STREAM_SECONDS:
                await websocket.close(code=4408, reason='Stream expired; reconnect')
                return
            snap=(await job.snapshot_async()).model_dump(mode='json')
            # Do not include wall-clock elapsed_seconds in the change signature.
            # Doing so would force a full JSON frame and React render every 200ms
            # even when the scan has made no progress.
            signature=(snap.get('status'),snap.get('progress'),snap.get('current_engine'),
                       str(snap.get('stages')),len(snap.get('logs') or []),snap.get('error_message'))
            if signature != last:
                await websocket.send_json(snap)
                last=signature
            if snap.get('status') in {'completed','partial','failed','cancelled'}:
                # Keep the socket alive briefly enough for the client to receive
                # the terminal frame, then close cleanly.
                await asyncio.sleep(0.25)
                await websocket.close(code=1000, reason='Job finished')
                return
            # 1s (was 200ms): when the Redis hot snapshot is unavailable, every sample falls back to a
            # full DB row read (payload+result, up to ~500KB) - 5/s per open tab was a major source of
            # the Supabase egress overage (2026-10).
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
    except Exception:
        logger.debug("Job progress websocket stream failed", exc_info=True)
        try:
            await websocket.close(code=1011, reason='Progress stream failed')
        except Exception:
            logger.debug("Closing already-broken progress websocket also failed", exc_info=True)