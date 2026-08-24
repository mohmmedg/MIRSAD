import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.core.config import settings
from app.core.auth_context import tenant_context
from app.core.database import AuditLogRow, session_scope, utcnow
def log_scan_request(*,scan_kind:str,target:str,scan_type:str|None=None,scope_check_result:str,client_host:str|None=None,extra:dict[str,Any]|None=None)->None:
    entry={"timestamp":datetime.now(timezone.utc).isoformat(),"scan_kind":scan_kind,"target":target,"scan_type":scan_type,"scope_check_result":scope_check_result,"client_host":client_host,"tenant_id":tenant_context.get()}; entry.update(extra or {})
    tid=tenant_context.get() or "legacy"
    try:
        with session_scope(tid) as db: db.add(AuditLogRow(id=str(uuid.uuid4()),tenant_id=tid,event=f"scan.{scan_kind}",target=target,data=entry,created_at=utcnow()))
    except Exception: return
def audit_log_path()->Path: return settings.DATA_DIR/"audit.log.jsonl"
