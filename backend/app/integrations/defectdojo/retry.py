from __future__ import annotations
import asyncio
import time
from datetime import datetime, timedelta, timezone
import uuid
from sqlalchemy import select, and_, or_
from app.core.config import settings
from app.core.database import session_scope_sync, ExternalSyncJobRow, DefectDojoMappingRow, ScanRow, utcnow
from app.integrations.defectdojo.client import DefectDojoClient, DefectDojoError
from app.integrations.defectdojo.mapper import to_finding, fingerprint


async def _find_existing_test(client, engagement_id: int, test_title: str):
    """Find the stable MIRSAD test before submitting a retry of the same scan."""
    data = await client.request(
        "GET", "/api/v2/tests/",
        params={"engagement": engagement_id, "title__contains": test_title},
    )
    rows = data.get("results") or []
    matches = []
    for item in rows:
        if str(item.get("title") or "") != test_title or not item.get("id"):
            continue
        item_engagement = item.get("engagement")
        if isinstance(item_engagement, dict):
            item_engagement = item_engagement.get("id")
        if item_engagement is not None and str(item_engagement) != str(engagement_id):
            continue
        matches.append(item)
    return max(matches, key=lambda item: int(item.get("id") or 0), default=None)


async def _wait_for_test_processed(client, test_id):
    """Do not mark an async DefectDojo import complete until its Test is processed."""
    timeout = max(1, int(getattr(settings, "DEFECTDOJO_IMPORT_WAIT_SECONDS", 900) or 900))
    deadline = time.monotonic() + timeout
    while True:
        test = await client.request("GET", f"/api/v2/tests/{test_id}/")
        status = str(test.get("status") or "").strip().casefold()
        if status == "processed":
            return test
        # DefectDojo 3.x Test objects expose no "status" field at all, only percent_complete.
        # Waiting for "processed" therefore always ran into IMPORT_TIMEOUT (900s) and blocked the sync.
        if "status" not in test and int(test.get("percent_complete") or 0) >= 100:
            return test
        if status == "failed":
            raise DefectDojoError(
                "IMPORT_FAILED", f"DefectDojo test {test_id} import failed", True
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DefectDojoError(
                "IMPORT_TIMEOUT",
                f"DefectDojo test {test_id} was not processed within {timeout}s",
                True,
            )
        await asyncio.sleep(min(3.0, remaining))


async def _get_or_import_test(client, *, product, engagement, scan_id: str, report: bytes):
    """Idempotently reuse a completed Test for this scan, or submit and await it."""
    test_title = f"MIRSAD Scan {scan_id}"
    existing = await _find_existing_test(client, engagement["id"], test_title)
    test_id = existing.get("id") if existing else None
    existing_status = str((existing or {}).get("status") or "").strip().casefold()

    if test_id and existing_status == "processed":
        return test_id
    if test_id and existing_status != "failed":
        await _wait_for_test_processed(client, test_id)
        return test_id

    data = {
        "scan_type": "SARIF",
        "test_title": test_title,
        "product_name": product["name"],
        "engagement_name": engagement["name"],
        "auto_create_context": "true",
        "active": "true",
        "verified": "false",
        "background_import": "true",
        "close_old_findings": "false",
        "deduplication_execution_mode": "async_wait",
    }
    response = await client.request(
        "POST", "/api/v2/reimport-scan/", data=data,
        files={"file": ("mirsad.sarif", report, "application/json")},
    )
    test_id = response.get("test_id") or (response.get("test") or {}).get("id")
    if not test_id:
        # A timeout or response-shape variation may hide the ID even though the
        # server created the stable Test. Look it up before allowing a retry POST.
        existing = await _find_existing_test(client, engagement["id"], test_title)
        test_id = existing.get("id") if existing else None
    if not test_id:
        raise DefectDojoError(
            "IMPORT_RESPONSE", "DefectDojo accepted no identifiable Test ID", True
        )
    await _wait_for_test_processed(client, test_id)
    return test_id

def next_retry(attempt:int):
    return datetime.now(timezone.utc)+timedelta(seconds=min(3600,2**max(0,attempt)))

async def process_due_job() -> bool:
    if not settings.DEFECTDOJO_ENABLED: return False
    with session_scope_sync() as db:
        now = utcnow()
        stale_before = now - timedelta(seconds=max(60, int(getattr(settings, "DEFECTDOJO_STALE_JOB_SECONDS", 1800))))
        due_or_abandoned = or_(
            and_(ExternalSyncJobRow.status.in_(["PENDING", "FAILED"]), ExternalSyncJobRow.next_retry_at <= now),
            and_(ExternalSyncJobRow.status == "RUNNING", ExternalSyncJobRow.updated_at <= stale_before),
        )
        row=db.execute(select(ExternalSyncJobRow).where(
            ExternalSyncJobRow.provider == "defectdojo", due_or_abandoned
        ).order_by(ExternalSyncJobRow.next_retry_at).limit(1).with_for_update(skip_locked=True)).scalar_one_or_none()
        if not row: return False
        row.status='RUNNING'; row.attempt_count += 1; row.updated_at=utcnow(); db.flush()
        scan=db.execute(select(ScanRow).where(ScanRow.tenant_id==row.tenant_id,ScanRow.scan_id==row.scan_id)).scalar_one_or_none()
        job={"job_id":row.job_id,"tenant_id":row.tenant_id,"scan_id":row.scan_id,"attempt_count":row.attempt_count}
        scan_data={"result":dict(scan.result or {}) if scan else {}}
    client=DefectDojoClient()
    try:
        from app.integrations.defectdojo.importer import DefectDojoImporter
        importer=DefectDojoImporter(client)
        product=await importer.ensure_product(f"{settings.DEFECTDOJO_PRODUCT_PREFIX} / {job['tenant_id']}","MIRSAD canonical security findings")
        engagement=await importer.ensure_engagement(product['id'],f"MIRSAD Scan {job['scan_id']}")
        findings=((scan_data.get('result') or {}).get('findings') or [])
        # One canonical report per scan; DefectDojo reimport is intentionally used for recurring runs.
        payload_lines=[]
        for raw in findings:
            class Obj: pass
            f=Obj()
            for k,v in raw.items(): setattr(f,k,v)
            for k,d in {'source_module':'mirsad','rule_id':'','affected_asset':None,'parameter':None,'title':'MIRSAD finding','severity':'Info','description':'','references':[],'cwe':None,'cve':None}.items():
                if not hasattr(f,k): setattr(f,k,d)
            fp=fingerprint(f)
            with session_scope_sync(tenant_id=job['tenant_id']) as db:
                exists=db.execute(select(DefectDojoMappingRow).where(DefectDojoMappingRow.tenant_id==job['tenant_id'],DefectDojoMappingRow.scan_id==job['scan_id'],DefectDojoMappingRow.fingerprint==fp,DefectDojoMappingRow.mapping_type=='finding')).scalar_one_or_none()
            if exists: continue
            dd=to_finding(f)
            payload_lines.append({"title":dd.title,"severity":dd.severity,"description":dd.description,"unique_id_from_tool":dd.unique_id_from_tool,"references":"\n".join(dd.references),"cve":dd.cve or ""})
        # DefectDojo's documented API accepts a report file for /reimport-scan.
        # MIRSAD emits a real SARIF 2.1.0 document so the destination parser is deterministic.
        import json
        rules={}
        rule_sev={} ; results=[]
        for raw in findings:
            class Obj: pass
            f=Obj()
            for k,v in raw.items(): setattr(f,k,v)
            for k,d in {'source_module':'mirsad','rule_id':'','affected_asset':None,'parameter':None,'title':'MIRSAD finding','severity':'Info','description':'','references':[],'cwe':None,'cve':None}.items():
                if not hasattr(f,k): setattr(f,k,d)
            fp=fingerprint(f); sev=str(f.severity)
            # DefectDojo reads "note" as Info and falls back to Medium for "none", which turned 8 Info findings into Medium.
            # Send an explicit numeric security-severity (cvss-like) and never use level "none".
            level={"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"note"}.get(sev,"note")
            score={"Critical":"9.5","High":"8.0","Medium":"5.0","Low":"2.0","Info":"0.0"}.get(sev,"0.0")
            rid=str(getattr(f,'rule_id','') or getattr(f,'finding_id',fp))
            if rid in rule_sev and rule_sev[rid]!=sev: rid=f"{rid}::{sev}"  # same rule, different severity -> separate SARIF rule
            rule_sev.setdefault(rid,sev)
            rules.setdefault(rid,{"id":rid,"name":f.title,"shortDescription":{"text":f.title},"help":{"text":getattr(f,'remediation','') or 'Review and remediate.'},"defaultConfiguration":{"level":level},"properties":{"security-severity":score}})
            results.append({"ruleId":rid,"level":level,"message":{"text":str(f.description or '')},"locations":[{"physicalLocation":{"artifactLocation":{"uri":str(getattr(f,'affected_asset',None) or job['scan_id'])}}}],"partialFingerprints":{"mirsadFindingId":str(getattr(f,'finding_id',fp)),"mirsadFingerprint":fp},"properties":{"verification":str(getattr(f,'verification_status','DETECTED')),"engine":str(getattr(f,'source_module','mirsad')),"security-severity":score,"mirsad-severity":sev}})
        sarif={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"MIRSAD","version":"canonical-v4","rules":list(rules.values())}},"results":results}]}
        report=json.dumps(sarif,ensure_ascii=False).encode()
        test_id = await _get_or_import_test(
            client, product=product, engagement=engagement,
            scan_id=job["scan_id"], report=report,
        )
        # Persist the canonical MIRSAD->DefectDojo mapping before marking the queue item complete.
        with session_scope_sync(tenant_id=job['tenant_id']) as db:
            for raw in findings:
                class Obj: pass
                f=Obj()
                for k,v in raw.items(): setattr(f,k,v)
                for k,d in {'source_module':'mirsad','rule_id':'','affected_asset':None,'parameter':None,'title':'MIRSAD finding','severity':'Info','description':'','references':[],'cwe':None,'cve':None}.items():
                    if not hasattr(f,k): setattr(f,k,d)
                fp=fingerprint(f); idem=f"finding:{job['scan_id']}:{getattr(f, 'finding_id', fp)}"
                exists=db.execute(select(DefectDojoMappingRow).where(DefectDojoMappingRow.tenant_id==job['tenant_id'],DefectDojoMappingRow.idempotency_key==idem)).scalar_one_or_none()
                if exists: continue
                db.add(DefectDojoMappingRow(mapping_id='ddmap_'+uuid.uuid4().hex,tenant_id=job['tenant_id'],scan_id=job['scan_id'],finding_id=getattr(f,'finding_id',None),test_id=test_id,fingerprint=fp,idempotency_key=idem,mapping_type='finding',created_at=utcnow(),updated_at=utcnow()))
        with session_scope_sync(tenant_id=job['tenant_id']) as db:
            row=db.get(ExternalSyncJobRow,job['job_id']); row.status='COMPLETED'; row.last_error_code=None; row.last_error_message=None; row.updated_at=utcnow(); row.payload={"test_id":test_id,"submitted_findings":len(payload_lines)}
        return True
    except DefectDojoError as exc:
        attempts=int(job['attempt_count']); dead=(not exc.retryable) or attempts>=int(settings.DEFECTDOJO_MAX_RETRIES)
        with session_scope_sync(tenant_id=job['tenant_id']) as db:
            row=db.get(ExternalSyncJobRow,job['job_id']); row.status='DEAD_LETTER' if dead else 'FAILED'; row.last_error_code=exc.code; row.last_error_message=str(exc)[:500]; row.next_retry_at=next_retry(attempts); row.updated_at=utcnow()
        return True
    except Exception as exc:
        attempts=int(job['attempt_count']); dead=attempts>=int(settings.DEFECTDOJO_MAX_RETRIES)
        with session_scope_sync(tenant_id=job['tenant_id']) as db:
            row=db.get(ExternalSyncJobRow,job['job_id']); row.status='DEAD_LETTER' if dead else 'FAILED'; row.last_error_code='INTERNAL'; row.last_error_message=type(exc).__name__; row.next_retry_at=next_retry(attempts); row.updated_at=utcnow()
        return True
