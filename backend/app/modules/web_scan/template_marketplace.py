"""3.2 - template marketplace: lets a tenant submit their own web_scan
passive-detection templates (same JSON shape as web_scan/templates/*.json,
see scanner.py::_match_template) without touching the built-in template
files shared by every tenant.

Scope, deliberately kept narrow:
- Storage only, no code execution beyond what _match_template already does
  for built-in templates (status/body_regex/headers matching against an
  already-fetched response) - a submitted template cannot make MIRSAD do
  anything scanner.py doesn't already do for a built-in template.
- Tenant-isolated: templates live under
  DATA_DIR/custom_templates/<tenant_id>/<id>.json and are only ever loaded
  into that tenant's own scans (see WebScanEngine._load_templates below).
- No cross-tenant sharing/rating/marketplace-browsing yet - "marketplace" is
  scoped here to "bring your own templates safely", which is the
  prerequisite for any future sharing layer, not the sharing layer itself.

Validation exists specifically to keep a submitted template inside the same
non-destructive contract as the built-in ones:
- method restricted to GET/HEAD/OPTIONS (scanner.py already enforces this
  for the templates it runs; rejecting earlier here gives a clear error
  instead of a silently-skipped template).
- body_regex patterns are compiled and screened for classic catastrophic-
  backtracking shapes (nested quantifiers) before being accepted, since a
  malicious/careless regex here runs against every response body 500KB at
  a time on every future scan using this template.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.core.config import settings

ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
MAX_BODY_REGEX_LEN = 300
MAX_TEMPLATES_PER_TENANT = 200

# Nested-quantifier shapes that are the classic catastrophic-backtracking
# triggers (e.g. (a+)+, (.*)*, (\d+)+) - not exhaustive, but screens out the
# patterns most likely to hang a worker on adversarial input. This is a
# defense-in-depth heuristic, not a full ReDoS analyzer.
_CATASTROPHIC_SHAPES = [
    re.compile(r"\([^)]*[+*][^)]*\)[+*]"),
    re.compile(r"(\.\*){2,}"),
    # alternation inside a quantified group, e.g. (a|aa)+ or (x|x)*  -> exponential on overlap
    re.compile(r"\([^)]*\|[^)]*\)[+*]|\([^)]*\|[^)]*\)\{\d*,\d*\}"),
    # quantified group followed by another unbounded quantifier on the same class, e.g. \w+\w+\w+
    re.compile(r"(\\[wds]|\.)[+*]\1[+*]"),
]


class TemplateValidationError(ValueError):
    pass


def _custom_templates_dir(tenant_id: str) -> Path:
    # tenant_id comes from the auth context, but it still becomes a directory name:
    # refuse anything that could climb out of custom_templates/ (".." , separators).
    if not tenant_id or tenant_id in {".", ".."} or "/" in tenant_id or "\\" in tenant_id or "\0" in tenant_id:
        raise ValueError("invalid tenant id for template storage")
    d = settings.DATA_DIR / "custom_templates" / tenant_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def validate_template(template: dict[str, Any]) -> dict[str, Any]:
    """Raises TemplateValidationError with a human-readable reason, or
    returns a normalized copy of the template ready to persist."""
    tid = str(template.get("id", "")).strip()
    if not tid or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", tid):
        raise TemplateValidationError("id يجب أن يكون slug صالح (أحرف صغيرة/أرقام/شرطات، 3-64 حرفًا)")
    name = str(template.get("name", "")).strip()
    if not name:
        raise TemplateValidationError("name مطلوب")
    path = str(template.get("path", "")).strip()
    if not path.startswith("/"):
        raise TemplateValidationError("path يجب أن يبدأ بـ '/'")
    method = str(template.get("method", "GET")).upper()
    if method not in ALLOWED_METHODS:
        raise TemplateValidationError(f"method غير مدعوم: {method}. المسموح: {sorted(ALLOWED_METHODS)}")
    severity = str(template.get("severity", "Info"))
    if severity not in ALLOWED_SEVERITIES:
        raise TemplateValidationError(f"severity غير معروف: {severity}")

    normalized: dict[str, Any] = {
        "id": tid, "name": name[:200], "path": path, "method": method, "severity": severity,
        "tags": [str(t)[:40] for t in (template.get("tags") or [])][:10],
    }

    status = template.get("status")
    if status is not None:
        if not isinstance(status, list) or not all(isinstance(s, int) for s in status):
            raise TemplateValidationError("status يجب أن يكون قائمة أرقام صحيحة")
        normalized["status"] = status

    body_regex = template.get("body_regex")
    if body_regex is not None:
        if not isinstance(body_regex, list):
            raise TemplateValidationError("body_regex يجب أن يكون قائمة نصوص")
        checked = []
        for pattern in body_regex:
            pattern = str(pattern)
            if len(pattern) > MAX_BODY_REGEX_LEN:
                raise TemplateValidationError(f"نمط body_regex طويل جدًا (الحد {MAX_BODY_REGEX_LEN} حرفًا)")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise TemplateValidationError(f"نمط body_regex غير صالح: {exc}") from exc
            if any(shape.search(pattern) for shape in _CATASTROPHIC_SHAPES):
                raise TemplateValidationError("نمط body_regex قد يسبب catastrophic backtracking (تكرار متداخل) - أعد صياغته")
            checked.append(pattern)
        normalized["body_regex"] = checked

    headers = template.get("headers")
    if headers is not None:
        if not isinstance(headers, dict):
            raise TemplateValidationError("headers يجب أن يكون كائن (object)")
        clean_headers: dict[str, dict[str, Any]] = {}
        for header_name, rule in headers.items():
            if not isinstance(rule, dict) or not set(rule.keys()) <= {"exists", "absent", "contains"}:
                raise TemplateValidationError(f"قاعدة header غير صالحة لـ {header_name}: المفاتيح المسموحة exists/absent/contains فقط")
            clean_headers[str(header_name)[:100]] = rule
        normalized["headers"] = clean_headers

    if "status" not in normalized and "body_regex" not in normalized and "headers" not in normalized:
        raise TemplateValidationError("يجب تحديد شرط تطابق واحد على الأقل: status و/أو body_regex و/أو headers")
    return normalized


def submit_template(tenant_id: str, template: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_template(template)
    directory = _custom_templates_dir(tenant_id)
    existing = list(directory.glob("*.json"))
    is_update = (directory / f"{normalized['id']}.json").exists()
    if not is_update and len(existing) >= MAX_TEMPLATES_PER_TENANT:
        raise TemplateValidationError(f"تجاوزت الحد الأقصى لعدد القوالب المخصصة ({MAX_TEMPLATES_PER_TENANT})")
    (directory / f"{normalized['id']}.json").write_text(
        json.dumps(normalized, ensure_ascii=False, indent=None), encoding="utf-8"
    )
    return normalized


def list_templates(tenant_id: str) -> list[dict[str, Any]]:
    directory = _custom_templates_dir(tenant_id)
    out = []
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


_TEMPLATE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")


def delete_template(tenant_id: str, template_id: str) -> bool:
    # Same slug rule as validate_template(): never build a filesystem path from raw input.
    if not _TEMPLATE_ID_RE.fullmatch(str(template_id or "")):
        return False
    directory = _custom_templates_dir(tenant_id).resolve()
    path = (directory / f"{template_id}.json").resolve()
    if path.parent != directory:
        return False
    if path.exists():
        path.unlink()
        return True
    return False
