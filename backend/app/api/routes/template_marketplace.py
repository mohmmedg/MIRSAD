"""3.2 - CRUD API for tenant-scoped custom web_scan templates. See
app/modules/web_scan/template_marketplace.py for validation/storage and
WebScanEngine._load_templates() for how these get evaluated during a scan."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.auth_context import tenant_context
from app.core.security import require_analyst, verify_api_key
from app.modules.web_scan.template_marketplace import (
    TemplateValidationError,
    delete_template,
    list_templates,
    submit_template,
)

router = APIRouter(prefix="/web-scan/templates", tags=["templates"], dependencies=[Depends(verify_api_key), Depends(require_analyst)])


class TemplateSubmission(BaseModel):
    id: str
    name: str
    path: str
    method: str = "GET"
    severity: str = "Info"
    tags: list[str] = Field(default_factory=list)
    status: list[int] | None = None
    body_regex: list[str] | None = None
    headers: dict[str, dict[str, bool | str]] | None = None


@router.get("")
async def list_custom_templates():
    tid = tenant_context.get() or "legacy"
    return {"templates": list_templates(tid)}


@router.post("", status_code=201)
async def create_or_update_custom_template(body: TemplateSubmission):
    tid = tenant_context.get() or "legacy"
    try:
        return submit_template(tid, body.model_dump(exclude_none=True))
    except TemplateValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{template_id}")
async def delete_custom_template(template_id: str):
    tid = tenant_context.get() or "legacy"
    if not delete_template(tid, template_id):
        raise HTTPException(status_code=404, detail="القالب غير موجود")
    return {"deleted": True, "id": template_id}
