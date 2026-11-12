from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select
from app.core.database import FindingLifecycleRow, FindingLifecycleIdempotencyRow, session_scope, utcnow
from app.core.auth_context import tenant_context
from app.modules.correlator.correlator import finding_fingerprint

LIFECYCLE = ("DISCOVERED","TRIAGED","VERIFIED","REPORTED","FIXED","RETESTED","CLOSED")

class LifecycleVersionConflict(Exception):
    """*** إضافة ***: يُرفع عندما base_version المُرسَل من العميل لا يطابق
    version الحالي بالسيرفر — تعارض حقيقي (تعديل آخر وصل أولًا)، بدل الكتابة
    فوقه بصمت. current يحمل الحالة الحالية بالسيرفر ليستخدمها العميل لحل
    التعارض محليًا (mergeByFieldLWW) بدون طلب GET إضافي."""
    def __init__(self, current: dict):
        self.current = current
        super().__init__("finding lifecycle version conflict")

def finding_key(finding: Any) -> str:
    fp = getattr(finding, "fingerprint", None) or finding_fingerprint(finding)
    return str(fp)

async def sync_scan_findings(scan) -> list[dict]:
    tid=tenant_context.get() or "legacy"; out=[]
    findings_list = getattr(scan,"findings",[]) or []
    keyed = [(f, hashlib.sha256(f"{tid}|{scan.scan_id}|{finding_key(f)}".encode()).hexdigest()[:48]) for f in findings_list]
    async with session_scope(tid) as db:
        existing_rows: dict[str, FindingLifecycleRow] = {}
        if keyed:
            keys = [key for _, key in keyed]
            existing_rows = {row.lifecycle_id: row for row in (await db.scalars(
                select(FindingLifecycleRow).where(FindingLifecycleRow.lifecycle_id.in_(keys))
            )).all()}
        for f, key in keyed:
            fp=finding_key(f)
            row=existing_rows.get(key)
            if row is None:
                row=FindingLifecycleRow(lifecycle_id=key,tenant_id=tid,scan_id=scan.scan_id,finding_id=f.finding_id,status=("VERIFIED" if str(getattr(f,"verification_status","")).upper()=="VERIFIED" else "DISCOVERED"),created_at=utcnow(),updated_at=utcnow())
                db.add(row)
                existing_rows[key] = row
            out.append({"finding_id":f.finding_id,"fingerprint":fp,"status":row.status,"updated_at":row.updated_at.isoformat()})
    return out

def _row_dict(row: FindingLifecycleRow) -> dict:
    return {
        "finding_id": row.finding_id,
        "status": row.status,
        "note": row.note,
        "updated_at": row.updated_at.isoformat(),
        "version": row.version,
    }

def update_status(
    scan_id: str,
    finding_id: str,
    status: str,
    note: str = "",
    base_version: int | None = None,
    idempotency_key: str | None = None,
) -> dict | None:
    raise NotImplementedError("use update_status_async")

async def update_status_async(
    scan_id: str,
    finding_id: str,
    status: str,
    note: str = "",
    base_version: int | None = None,
    idempotency_key: str | None = None,
) -> dict | None:
    """*** مُعدَّلة (دعم Local-First) ***
    - base_version (اختياري، متوافق للخلف): لو مُرسَل ولا يطابق version
      الحالي بالسجل، تُرفع LifecycleVersionConflict بدل الكتابة فوق تعديل
      موازٍ بصمت. لو لم يُرسَل (كل الاستدعاءات القديمة)، السلوك يبقى تمامًا
      كما كان — كتابة غير شرطية.
    - idempotency_key (اختياري): لو مُرسَل ونفس المفتاح نُفِّذ سابقًا لنفس
      المستأجر، تُرجَع نفس النتيجة المخزَّنة بدل إعادة تطبيق التعديل —
      يحمي من تنفيذ مضاعف عند إعادة إرسال بعد timeout شبكة
      (مهم خصوصًا لمسار Background Sync الذي لا يعرف هل نجحت المحاولة
      السابقة فعليًا أم لا).
    """
    if status not in LIFECYCLE: raise ValueError(f"status must be one of {', '.join(LIFECYCLE)}")
    tid=tenant_context.get() or "legacy"
    async with session_scope(tid) as db:
        if idempotency_key:
            cached=await db.get(FindingLifecycleIdempotencyRow,(tid,idempotency_key))
            if cached is not None:
                return cached.result

        row=(await db.scalars(select(FindingLifecycleRow).filter_by(tenant_id=tid,scan_id=scan_id,finding_id=finding_id).limit(1))).first()
        if row is None: return None

        if base_version is not None and row.version != base_version:
            raise LifecycleVersionConflict(_row_dict(row))

        row.status=status; row.note=note[:2000]; row.updated_at=utcnow(); row.version=row.version+1
        result=_row_dict(row)

        if idempotency_key:
            db.add(FindingLifecycleIdempotencyRow(
                tenant_id=tid, idempotency_key=idempotency_key, result=result, created_at=utcnow(),
            ))

        return result

async def list_status(scan_id:str) -> list[dict]:
    tid=tenant_context.get() or "legacy"
    async with session_scope(tid) as db:
        rows=(await db.scalars(select(FindingLifecycleRow).filter_by(tenant_id=tid,scan_id=scan_id).order_by(FindingLifecycleRow.updated_at.desc()))).all()
        return [_row_dict(r) for r in rows]
