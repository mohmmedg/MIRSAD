from __future__ import annotations
import uuid
from app.core.config import settings
from app.core.database import ExternalSyncJobRow, session_scope_sync, utcnow
from sqlalchemy import select

async def enqueue_sync(scan_id:str,tenant_id:str):
    if not settings.DEFECTDOJO_ENABLED:
        return {"status":"DISABLED"}
    key=f"defectdojo:{scan_id}"
    with session_scope_sync(tenant_id=tenant_id) as db:
        row=db.execute(select(ExternalSyncJobRow).where(ExternalSyncJobRow.tenant_id==tenant_id,ExternalSyncJobRow.idempotency_key==key)).scalar_one_or_none()
        if row is None:
            row=ExternalSyncJobRow(job_id="ddjob_"+uuid.uuid4().hex,tenant_id=tenant_id,scan_id=scan_id,provider="defectdojo",status="PENDING",attempt_count=0,next_retry_at=utcnow(),idempotency_key=key,payload={},created_at=utcnow(),updated_at=utcnow())
            db.add(row)
            return {"status":"PENDING","idempotency_key":key,"job_id":row.job_id}
        if row.status in {"FAILED","DEAD_LETTER"}:
            row.status="PENDING"; row.next_retry_at=utcnow(); row.updated_at=utcnow()
        return {"status":row.status,"idempotency_key":key,"job_id":row.job_id}
