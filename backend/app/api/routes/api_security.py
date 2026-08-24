import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.audit_log import log_scan_request
from app.core.config import settings
from app.core.rate_limit import limiter, scan_rate_limit
from app.core.finding_pipeline import correlate_and_escalate
from app.core.auth_context import tenant_context
from app.core.security import verify_api_key, require_analyst, require_viewer, require_admin
from app.core.policy_enforcement import enforce_policy_rate_limit, scan_policy, scan_slot
from app.modules.api_security.scanner import APISecurityScanner
from app.schemas.api_security import APISecurityResult

router = APIRouter(prefix="/api-security", tags=["api-security"])
scanner = APISecurityScanner()


class APISecurityRequest(BaseModel):
    target: str
    spec_url: str | None = None
    auth_header: str | None = Field(default=None, description="Authorization value; never persisted in results")
    cookie: str | None = Field(default=None, description="Cookie header value; never persisted in results")
    enable_graphql_introspection: bool = True
    probe_write_methods: bool = False


@router.post("/scan", response_model=APISecurityResult, dependencies=[Depends(verify_api_key), Depends(require_analyst)])
@limiter.limit(scan_rate_limit())
async def run_api_security_scan(request: Request, body: APISecurityRequest) -> APISecurityResult:
    tenant_id = tenant_context.get() or "legacy"
    policy = scan_policy(tenant_id)
    await enforce_policy_rate_limit("scan", tenant_id, int(policy["rate_limit_per_minute"]))
    try:
        async with scan_slot(tenant_id):
            result = await __import__("asyncio").wait_for(
                scanner.scan(
                    target_url=body.target,
                    spec_url=body.spec_url,
                    auth_header=body.auth_header,
                    cookie=body.cookie,
                    enable_graphql_introspection=body.enable_graphql_introspection,
                    probe_write_methods=body.probe_write_methods,
                ),
                timeout=int(policy["max_scan_duration_minutes"]) * 60,
            )
            log_scan_request(scan_kind="api-security", target=body.target, scope_check_result="allowed", client_host=request.client.host if request.client else None)
            if tenant_context.get():
                await correlate_and_escalate(tenant_id=tenant_context.get(), result=result, run_gemini=bool(settings.GEMINI_API_KEY))
            return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/templates/reload", dependencies=[Depends(verify_api_key), Depends(require_admin)])
async def reload_api_templates() -> dict:
    return {"loaded": scanner.templates.reload(), "directory": str(scanner.templates.directory)}


class TemplatePackRequest(BaseModel):
    pack_id: str
    version: str = "1.0.0"
    templates: list[dict] = Field(default_factory=list)


@router.get("/templates", dependencies=[Depends(verify_api_key), Depends(require_viewer)])
async def list_api_templates() -> dict:
    return {"loaded": len(scanner.templates.templates), "templates": [t.get("id") for t in scanner.templates.templates]}


@router.post("/templates/import", dependencies=[Depends(verify_api_key), Depends(require_admin)])
async def import_api_template_pack(body: TemplatePackRequest) -> dict:
    safe_id = "".join(ch for ch in body.pack_id if ch.isalnum() or ch in {"-", "_"})[:80]
    if not safe_id or not body.templates:
        raise HTTPException(status_code=400, detail="Template pack must contain a valid pack_id and at least one template.")
    valid = [t for t in body.templates if isinstance(t, dict) and t.get("id") and isinstance(t.get("match"), dict)]
    if not valid:
        raise HTTPException(status_code=400, detail="No valid templates found in the pack.")
    path = scanner.templates.directory / f"{safe_id}.json"
    path.write_text(json.dumps({"pack_id": safe_id, "version": body.version, "templates": valid}, ensure_ascii=False, indent=2), encoding="utf-8")
    loaded = scanner.templates.reload()
    return {"pack_id": safe_id, "version": body.version, "accepted": len(valid), "loaded": loaded}
