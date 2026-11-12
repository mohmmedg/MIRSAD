import json
import logging
import re
import shutil
from pathlib import Path
from typing import Any

from app.schemas.api_security import APITemplateMatch

logger = logging.getLogger(__name__)


class APITemplateEngine:
    def __init__(self, directory: Path):
        self.directory = directory
        self.templates: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> int:
        self.templates = []
        self.directory.mkdir(parents=True, exist_ok=True)
        if not list(self.directory.glob("*.json")):
            builtin = Path(__file__).with_name("builtin.json")
            if builtin.exists():
                try:
                    shutil.copy2(builtin, self.directory / "builtin.json")
                except OSError:
                    logger.warning("Failed to seed builtin API security templates into %s", self.directory, exc_info=True)
        for path in sorted(self.directory.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for item in data.get("templates", []):
                    if item.get("id") and item.get("match"):
                        self.templates.append(item)
            except (OSError, json.JSONDecodeError):
                continue
        return len(self.templates)

    def evaluate(
        self,
        endpoint_url: str,
        status_code: int | None,
        headers: dict[str, str],
        auth_present: bool,
        security_declared: bool = False,
        declared_methods: list[str] | None = None,
    ) -> list[APITemplateMatch]:
        """Evaluate templates against one observed response.

        Templates are deliberately declarative. Method-advertisement findings
        require an actually undeclared method in the Allow header; a normal
        405/Allow response is not itself a security finding.
        """
        out: list[APITemplateMatch] = []
        lower = {k.lower(): v for k, v in headers.items()}
        declared = {str(x).upper() for x in (declared_methods or [])}
        for t in self.templates:
            m = t.get("match", {})
            if "status_in" in m and status_code not in m["status_in"]:
                continue
            if m.get("security_declared") and not security_declared:
                continue
            if m.get("require_auth_header") and auth_present:
                continue
            if m.get("header_present") and m["header_present"].lower() not in lower:
                continue
            # 4.2: inverse of header_present - triggers when NONE of the listed
            # headers are present (e.g. detecting a missing rate-limit signal
            # on an LLM gateway endpoint). Unlike header_present (a single
            # name), this takes a list, since callers usually want to say
            # "none of these rate-limit header variants showed up" rather
            # than checking one exact header name.
            if m.get("header_absent"):
                if any(h.lower() in lower for h in m["header_absent"]):
                    continue
            # 4.2: path_regex restricts a template to endpoints whose URL
            # matches at least one pattern (e.g. known LLM/agent-framework
            # routes) - needed because this engine otherwise evaluates every
            # template against every endpoint uniformly regardless of path.
            if m.get("path_regex"):
                if not any(re.search(p, endpoint_url, re.IGNORECASE) for p in m["path_regex"]):
                    continue
            if m.get("content_type_contains"):
                if m["content_type_contains"].lower() not in lower.get("content-type", "").lower():
                    continue
            if m.get("allow_header_present") and "allow" not in lower:
                continue
            if m.get("allow_has_undeclared_method"):
                allow_methods = {x.strip().upper() for x in lower.get("allow", "").split(",") if x.strip()}
                if not (allow_methods - declared):
                    continue
            evidence = f"HTTP {status_code}" if status_code is not None else "No HTTP status"
            if "allow" in lower:
                evidence += f"; Allow: {lower['allow']}"
            if "server" in lower:
                evidence += f"; Server header present: {lower['server'][:120]}"
            out.append(APITemplateMatch(
                template_id=t["id"], title=t.get("title", t["id"]), severity=t.get("severity", "Info"),
                endpoint=endpoint_url, evidence=evidence, remediation=t.get("remediation", "Review the API behavior."),
            ))
        return out
