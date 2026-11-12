"""2.5 - POST endpoint accepting raw output from external tools and
normalizing it into MIRSAD findings.

Every imported finding goes through the exact same downstream risk-scoring
and persistence path as MIRSAD's own scanners (app.core.architecture.history
UnifiedHistory.save, same ScanRow/ScanSnapshotRow tables /platform/history
and /platform/scan-history already read from) - this endpoint only
translates format and assigns a risk score, it never bypasses assessment.
Imported findings are marked verification_status="DETECTED" (never
"VERIFIED") by the importers themselves, same as any other unverified
finding, so they're never silently treated as more certain than they are.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.core.security import require_analyst, verify_api_key
from app.core.architecture.history import UnifiedHistory
from app.modules.importers.nessus_xml import parse_nessus_xml
from app.modules.importers.nmap_xml import parse_nmap_xml
from app.modules.importers.nuclei_jsonl import parse_nuclei_jsonl
from app.modules.risk_engine.engine import assess, bundle
from app.schemas.platform import CorrelatedFinding, ScanCoverage, UnifiedScanResult

router = APIRouter(prefix="/import", tags=["import"], dependencies=[Depends(verify_api_key), Depends(require_analyst)])
_history = UnifiedHistory()

_PARSERS = {
    "nessus": lambda content, scan_id: parse_nessus_xml(content, scan_id),
    "nmap_xml": lambda content, scan_id: parse_nmap_xml(content, scan_id),
    "nuclei_jsonl": lambda content, scan_id: parse_nuclei_jsonl(content.decode("utf-8", errors="ignore"), scan_id),
}


@router.post("/findings", status_code=201)
async def import_findings(
    format: str = Form(..., description="nessus | nmap_xml | nuclei_jsonl"),
    target: str = Form(..., description="اسم/عنوان الهدف الذي تخص هذه النتائج (يُستخدم للعرض في السجل وتجميع درجة مرصاد)"),
    file: UploadFile = File(...),
):
    parser = _PARSERS.get(format)
    if parser is None:
        raise HTTPException(status_code=400, detail=f"صيغة غير مدعومة: {format}. المدعوم حاليًا: {list(_PARSERS)}")

    max_bytes = 25 * 1024 * 1024  # 25MB upload ceiling, same order of magnitude as other upload paths in the app
    # Read at most max_bytes+1 so an oversized upload is never fully buffered in memory.
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="حجم الملف يتجاوز الحد المسموح (25MB).")

    scan_id = f"import-{uuid.uuid4().hex[:20]}"
    try:
        findings = parser(content, scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception as exc:
        # Parser bugs on malformed-but-not-explicitly-rejected input should
        # surface as a clean 422, not a raw 500 with a stack trace to the client.
        raise HTTPException(status_code=422, detail="تعذّر تحليل الملف: الصيغة غير صالحة.") from None

    now = datetime.now(timezone.utc)
    correlated: list[CorrelatedFinding] = []
    for f in findings:
        risk = assess(f)
        correlated.append(CorrelatedFinding(**f.model_dump(), risk=risk))
    risk_score = bundle([c.risk.score for c in correlated if c.severity != "Info"])

    scan = UnifiedScanResult(
        scan_id=scan_id,
        target=target,
        status="completed",
        started_at=now,
        finished_at=now,
        findings=correlated,
        risk_score=risk_score,
        coverage=ScanCoverage(
            # An imported scan was NOT exercised by MIRSAD's own engines - marking
            # coverage this way keeps compliance.assess()'s NOT_ASSESSED-vs-PASS
            # distinction (see modules/compliance/__init__.py::_control_tested)
            # honest for imported data instead of implying MIRSAD verified it.
            capabilities={f"import:{format}": {"status": "COMPLETED"}},
        ),
        warnings=[f"مصدر هذه النتائج: استيراد خارجي بصيغة {format}, وليس فحصاً مباشراً من مرصاد."],
    )
    await _history.save(scan)

    return {
        "scan_id": scan_id,
        "target": target,
        "format": format,
        "imported_count": len(correlated),
        "risk_score": risk_score,
        "severity_breakdown": {
            sev: sum(1 for f in correlated if f.severity == sev)
            for sev in ("Critical", "High", "Medium", "Low", "Info")
        },
    }
