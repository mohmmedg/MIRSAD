from app.core.auth_context import tenant_context
from app.core.database import ScanRow, session_scope, utcnow
from app.schemas.platform import UnifiedScanResult
class UnifiedHistory:
    def save(self,scan):
        tid=tenant_context.get() or "legacy"; data=scan.model_dump(mode="json")
        with session_scope(tid) as db:
            row=db.get(ScanRow,scan.scan_id)
            if row is None: db.add(ScanRow(scan_id=scan.scan_id,tenant_id=tid,job_id=None,scan_kind="full",target=scan.target,status=scan.status,result=data,error_message=None,created_at=scan.started_at or utcnow(),finished_at=scan.finished_at))
            else: row.result=data; row.status=scan.status; row.finished_at=scan.finished_at
    def get(self,scan_id):
        tid=tenant_context.get() or "legacy"
        with session_scope(tid) as db:
            row=db.get(ScanRow,scan_id)
            if not row or row.tenant_id != tid:
                return None
            return UnifiedScanResult.model_validate(row.result) if row.result else None
    def list(self,limit=50):
        tid=tenant_context.get() or "legacy"
        with session_scope(tid) as db:
            rows=db.query(ScanRow).filter(ScanRow.tenant_id==tid).order_by(ScanRow.created_at.desc()).limit(max(1,min(limit,500))).all()
            return [r.result for r in rows if r.result]
history=UnifiedHistory()
