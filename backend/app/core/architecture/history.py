from app.core.auth_context import tenant_context
from app.core.auth import current_principal_optional
from app.core.database import ScanRow, ScanSnapshotRow, session_scope, utcnow
from app.schemas.platform import UnifiedScanResult
from app.core.json_sanitizer import sanitize_json
from sqlalchemy import select

class UnifiedHistory:
    async def save(self, scan, owner_user_id: str | None = None):
        tid=tenant_context.get() or "legacy"
        if owner_user_id is None:
            principal = current_principal_optional()
            owner_user_id = principal.user_id if principal else None
        data=sanitize_json(scan.model_dump(mode="json"))
        async with session_scope(tid) as db:
            row=await db.get(ScanRow,scan.scan_id)
            if row is None:
                db.add(ScanRow(scan_id=scan.scan_id,tenant_id=tid,created_by_user_id=owner_user_id,job_id=scan.scan_id,scan_kind="full",target=scan.target,status=scan.status,result=data,error_message=None,created_at=scan.started_at or utcnow(),finished_at=scan.finished_at))
            else:
                row.result=data; row.status=scan.status; row.finished_at=scan.finished_at
            snap=await db.get(ScanSnapshotRow, scan.scan_id)
            if snap is None:
                db.add(ScanSnapshotRow(scan_id=scan.scan_id, tenant_id=tid, snapshot_version=scan.snapshot_version,
                    data=data, created_at=scan.started_at or utcnow(), finalized_at=scan.finished_at))
            else:
                if snap.finalized_at is None:
                    snap.data=data; snap.snapshot_version=scan.snapshot_version; snap.finalized_at=scan.finished_at
                # A finalized snapshot is immutable. A new scan/revision gets a new scan_id.

    async def previous_findings_for_target(self, target: str, exclude_scan_id: str | None = None) -> tuple[list[dict], str | None]:
        """Returns (findings, previous_scan_id) from the most recent
        completed scan of the exact same normalized target for this tenant,
        or ([], None) if there isn't one yet — i.e. this is the first scan
        of this target, which is not itself a finding of anything.

        This is what makes trend tracking possible: 'what's new since last
        time, what got fixed, what's still open' — arguably more valuable
        to a repeat customer than the raw finding count on any single scan."""
        tid=tenant_context.get() or "legacy"
        async with session_scope(tid) as db:
            stmt = select(ScanRow).where(ScanRow.tenant_id==tid, ScanRow.target==target, ScanRow.status=="completed")
            if exclude_scan_id:
                stmt = stmt.where(ScanRow.scan_id != exclude_scan_id)
            stmt = stmt.order_by(ScanRow.finished_at.desc()).limit(1)
            row = (await db.execute(stmt)).scalars().first()
            if not row or not row.result:
                return [], None
            return row.result.get("findings") or [], row.scan_id

    async def get(self,scan_id):
        tid=tenant_context.get() or "legacy"
        async with session_scope(tid) as db:
            row=await db.get(ScanSnapshotRow,scan_id)
            if not row or row.tenant_id != tid or row.finalized_at is None:
                return None
            return UnifiedScanResult.model_validate(row.data) if row.data else None

    async def list(self,limit=50):
        tid=tenant_context.get() or "legacy"
        async with session_scope(tid) as db:
            stmt = select(ScanSnapshotRow).where(ScanSnapshotRow.tenant_id==tid, ScanSnapshotRow.finalized_at.is_not(None)).order_by(ScanSnapshotRow.created_at.desc()).limit(max(1,min(limit,500)))
            rows = (await db.execute(stmt)).scalars().all()
            return [r.data for r in rows if r.data]

    async def snapshot_exists(self, scan_id: str) -> bool:
        tid=tenant_context.get() or "legacy"
        async with session_scope(tid) as db:
            row=await db.get(ScanSnapshotRow, scan_id)
            return bool(row and row.tenant_id == tid and row.finalized_at is not None)

history=UnifiedHistory()
