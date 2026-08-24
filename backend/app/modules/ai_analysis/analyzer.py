"""
modules/ai_analysis/analyzer.py

AIAnalyzer: يحلل نتائج network/web عبر Google Gemini API باستخدام
google-genai SDK. لا يُرسل أي طلب خارجي قبل توفر GEMINI_API_KEY.
"""

import json
import re
import uuid
import asyncio
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    class _Types:
        class GenerateContentConfig:
            def __init__(self, **kwargs): self.__dict__.update(kwargs)
    types = _Types()

from app.core.config import settings
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import ai_policy
from app.schemas.analysis import AnalysisReport, AnalyzedFinding, Severity
from app.schemas.network import NetworkScanResult
from app.schemas.web import WebScanResult
from app.schemas.api_security import APISecurityResult

SYSTEM_PROMPT_AR = """أنت محلل أمن سيبراني خبير. ستستقبل مصفوفة JSON من مرشّحين
(raw findings candidates) مستخرجين من فحص أمني تقني خام (network scan و/أو web scan).

مهمتك:
1. لكل عنصر، قرّر هل يستحق أن يكون finding أمني موثّق. تجاهل العناصر غير المهمة
   أمنياً مثل منفذ مفتوح شائع وسليم تماماً بدون مؤشر خطر حقيقي.
2. صنّف كل finding حسب الخطورة: Critical, High, Medium, Low, Info.
3. اكتب description بلغة واضحة يفهمها شخص غير تقني وتشرح المشكلة ولماذا تهم.
4. اكتب remediation محدداً وقابلاً للتنفيذ، وليس نصيحة عامة.
5. اكتب executive_summary فقرة واحدة من 3-5 جمل موجهة لجهة غير تقنية.

اكتب title وdescription وremediation وexecutive_summary بالعربية حصراً.
أعد JSON مطابقاً للمخطط الذي حدده النظام. إذا لم توجد evidence أو affected_asset، استخدم سلسلة نصية فارغة "". لا تستخدم null. لا تضف Markdown أو نصاً خارج JSON."""

SYSTEM_PROMPT_EN = """You are an expert cybersecurity analyst. You will receive a JSON
array of raw finding candidates extracted from a technical network and/or web scan.

For each candidate, decide whether it deserves documentation as a security finding.
Ignore benign items with no genuine security relevance. Classify findings as Critical,
High, Medium, Low, or Info. Write clear descriptions understandable by a non-technical
reader, specific actionable remediation, and a 3-5 sentence executive summary.
Write title, description, remediation, and executive_summary exclusively in English.
Return only JSON matching the requested schema. If evidence or affected_asset is unavailable, use an empty string "" (never null). Return no Markdown or extra text."""


def _system_prompt(language: str) -> str:
    return SYSTEM_PROMPT_EN if language == "en" else SYSTEM_PROMPT_AR


_SENSITIVE_KEYS = re.compile(
    r"(?:api[_-]?key|authorization|cookie|set-cookie|token|access[_-]?token|refresh[_-]?token|secret|password|passwd|session|jwt|credential)",
    re.I,
)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:"
    r"bearer\s+[^\s,;]+|"
    r"(?:api[_-]?key|authorization|cookie|set-cookie|token|password|secret)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
    r")"
)

def _sanitize_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value
        query = [(k, "[REDACTED]" if _SENSITIVE_KEYS.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        userinfo = ""
        if parts.username or parts.password:
            host = parts.hostname or ""
            port = f":{parts.port}" if parts.port else ""
            userinfo = f"{host}{port}"
        else:
            userinfo = parts.netloc
        return urlunsplit((parts.scheme, userinfo, parts.path, urlencode(query), parts.fragment))
    except Exception:
        return value

def _sanitize_for_ai(value: Any, key: str | None = None) -> Any:
    if key and _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _sanitize_for_ai(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_ai(v, key) for v in value]
    if isinstance(value, tuple):
        return [_sanitize_for_ai(v, key) for v in value]
    if isinstance(value, str):
        value = _sanitize_url(value) if value.startswith(("http://", "https://")) else value
        def _redact_match(match: re.Match[str]) -> str:
            text = match.group(0)
            if re.match(r"(?i)^bearer\s+", text):
                return "Bearer [REDACTED]"
            m = re.match(r"(?is)^(\s*(?:api[_-]?key|authorization|cookie|set-cookie|token|password|secret)\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+$", text)
            if m:
                prefix = m.group(1)
                return prefix + "[REDACTED]"
            return "[REDACTED]"
        value = _SENSITIVE_TEXT.sub(_redact_match, value)
        # Redact sensitive query values even when the URL is embedded in prose/evidence.
        def _redact_query(match: re.Match[str]) -> str:
            key, sep, _ = match.group(1), match.group(2), match.group(3)
            return f"{key}{sep}[REDACTED]"
        value = re.sub(
            r"(?i)([?&](?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|secret|password|session|jwt)=)([^&#\s]+)",
            lambda m: m.group(1) + "[REDACTED]",
            value,
        )
        return value
    return value


RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source_module": {"type": "string", "enum": ["network", "web", "api_security"]},
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    },
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "remediation": {"type": "string"},
                    "affected_asset": {"type": "string"},
                },
                "required": [
                    "source_module",
                    "title",
                    "severity",
                    "description",
                    "evidence",
                    "remediation",
                    "affected_asset",
                ],
            },
        },
    },
    "required": ["executive_summary", "findings"],
}


class AIAnalyzerConfigError(Exception):
    """يُرفع عندما يكون GEMINI_API_KEY غير مضبوط."""


class AIAnalyzerResponseError(Exception):
    """يُرفع عندما تفشل استجابة Gemini أو لا تكون JSON صالحة."""


class AIAnalyzer:
    def __init__(self) -> None:
        self._client = None
        if settings.GEMINI_API_KEY and genai is not None:
            self._client = genai.Client(api_key=settings.GEMINI_API_KEY)

    async def validate_findings(self, findings: list[Any], language: str = "ar") -> dict[str, Any]:
        """Validate normalized/correlated findings only; never performs discovery."""
        if not findings:
            return {"status":"skipped","reason":"no_findings","validated":[]}
        if self._client is None:
            raise AIAnalyzerConfigError("GEMINI_API_KEY غير مضبوط بملف .env.")
        payload=[]
        for f in findings[:100]:
            payload.append(_sanitize_for_ai({"finding_id":f.finding_id,"source_module":f.source_module,"title":f.title,"severity":f.severity,"confidence":f.confidence,"description":f.description,"evidence":[e.evidence for e in f.evidence[:5]],"asset":f.affected_asset,"references":f.references}))
        prompt=("Validate only these already-normalized security findings. Do not discover new issues. "
                "For each item return finding_id, verdict (confirmed|potential|unsupported), confidence, and reason. "
                "A finding without sufficient evidence must be potential or unsupported. Return JSON only.\n"+json.dumps(payload,ensure_ascii=False))
        try:
            response=await self._client.aio.models.generate_content(model=settings.GEMINI_MODEL,contents=prompt,config=types.GenerateContentConfig(response_mime_type="application/json",temperature=0.0,max_output_tokens=settings.GEMINI_MAX_OUTPUT_TOKENS))
            parsed=json.loads(response.text or "{}")
            return {"status":"completed","validated":parsed.get("validated", parsed.get("findings", [])),"model":settings.GEMINI_MODEL}
        except Exception as exc:
            raise AIAnalyzerResponseError(f"فشل Gemini validation: {exc}") from exc

    async def analyze(
        self,
        network_result: NetworkScanResult | None = None,
        web_result: WebScanResult | None = None,
        api_result: APISecurityResult | None = None,
        language: str = "ar",
    ) -> AnalysisReport:
        if network_result is None and web_result is None and api_result is None:
            raise ValueError("لازم توفّر network_result و/أو web_result على الأقل")

        if api_result is None and web_result is not None and getattr(web_result, "api_security", None) is not None:
            api_result = web_result.api_security
        candidates = self._build_candidates(network_result, web_result, api_result)
        if not candidates:
            note = (
                "Not enough scan data to analyze."
                if language == "en"
                else "لا توجد بيانات فحص كافية لتحليلها."
            )
            return self._empty_report(network_result, web_result, note=note)

        if self._client is None:
            raise AIAnalyzerConfigError(
                "GEMINI_API_KEY غير مضبوط بملف .env. أضفه قبل استخدام AI Analysis Layer."
            )

        response_text = await self._call_gemini(candidates, language)
        parsed = self._parse_json_response(response_text)
        return self._build_report(parsed, network_result, web_result)

    def _build_candidates(
        self,
        network_result: NetworkScanResult | None,
        web_result: WebScanResult | None,
        api_result: APISecurityResult | None = None,
    ) -> list[dict]:
        candidates: list[dict] = []

        if network_result and network_result.status.value == "completed":
            # Context وحده ليس evidence أمنياً؛ لا نرسل Gemini scan فارغاً
            # لمجرد أن الحالة completed. هذا يمنع false-positive/AI calls غير لازمة.
            if network_result.open_ports or network_result.os_matches or network_result.host_scripts:
                candidates.append({
                    "source_module": "network",
                    "raw_type": "scan_context",
                    "detail": {
                        "target": network_result.target,
                        "scan_type": network_result.scan_type,
                        "open_port_count": len(network_result.open_ports),
                        "os_match_count": len(network_result.os_matches),
                    },
                })
            for port in network_result.open_ports:
                candidates.append({
                    "source_module": "network",
                    "raw_type": "open_port",
                    "detail": port.model_dump(mode="json"),
                })
            for os_match in network_result.os_matches[:2]:
                candidates.append({
                    "source_module": "network",
                    "raw_type": "os_fingerprint",
                    "detail": os_match.model_dump(mode="json"),
                })
            for port in network_result.open_ports:
                for script in port.scripts:
                    candidates.append({"source_module": "network", "raw_type": "nse_script", "detail": {"port": port.port, "protocol": port.protocol, "service": port.service_name, "script_id": script.script_id, "output": script.output[:2500]}})
            for script in network_result.host_scripts:
                candidates.append({"source_module": "network", "raw_type": "host_nse_script", "detail": script.model_dump(mode="json")})

        if web_result and web_result.status.value == "completed":
            candidates.append({
                "source_module": "web",
                "raw_type": "scan_context",
                "detail": {
                    "target": web_result.target,
                    "final_url": web_result.final_url,
                    "status_code": web_result.status_code,
                    "content_type": web_result.content_type,
                    "server_header": web_result.server_header,
                },
            })
            if web_result.tls_info:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "tls_info",
                    "detail": web_result.tls_info.model_dump(mode="json"),
                })
            for header in web_result.security_headers:
                # غياب security header هو evidence صالح للتحليل، لكن لا نعامل
                # وجود header بحد ذاته كـ finding candidate.
                if not header.present:
                    candidates.append({
                        "source_module": "web",
                        "raw_type": "missing_security_header",
                        "detail": header.model_dump(mode="json"),
                    })
                else:
                    candidates.append({
                        "source_module": "web",
                        "raw_type": "security_header",
                        "detail": header.model_dump(mode="json"),
                    })
            for check in web_result.vulnerability_checks:
                if check.vulnerable:
                    candidates.append({
                        "source_module": "web",
                        "raw_type": "vulnerability_check",
                        "detail": check.model_dump(mode="json"),
                    })
            if web_result.server_header:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "server_header_disclosure",
                    "detail": {"value": web_result.server_header},
                })
            if web_result.discovered_urls:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "discovered_endpoints",
                    "detail": {
                        "count": len(web_result.discovered_urls),
                        "urls": web_result.discovered_urls[:80],
                        "forms_count": web_result.forms_count,
                        "profile": web_result.profile,
                        "endpoints_count": web_result.endpoints_count,
                        "parameters_count": web_result.parameters_count,
                        "js_assets_count": web_result.js_assets_count,
                    },
                })
            if web_result.endpoints:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "endpoint_inventory",
                    "detail": [x.model_dump(mode="json") for x in web_result.endpoints[:120]],
                })
            if web_result.forms:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "forms",
                    "detail": [x.model_dump(mode="json") for x in web_result.forms[:80]],
                })
            if web_result.api_candidates:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "api_candidates",
                    "detail": web_result.api_candidates[:100],
                })
            if web_result.template_findings:
                for item in web_result.template_findings[:100]:
                    candidates.append({
                        "source_module": "web",
                        "raw_type": "template_match",
                        "detail": item.model_dump(mode="json"),
                    })
            if web_result.passive_findings:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "passive_observation",
                    "detail": web_result.passive_findings,
                })
            if web_result.javascript_assets:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "javascript_assets",
                    "detail": web_result.javascript_assets[:80],
                })
            for item in web_result.cookie_checks:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "cookie_security",
                    "detail": {"finding": item},
                })
            for item in web_result.cors_findings:
                candidates.append({
                    "source_module": "web",
                    "raw_type": "cors_configuration",
                    "detail": {"finding": item},
                })
            if getattr(web_result, "api_security", None) is not None and api_result is None:
                candidates.append({
                    "source_module": "api_security",
                    "raw_type": "integrated_api_scan",
                    "detail": web_result.api_security.model_dump(mode="json"),
                })

        if api_result and api_result.status == "completed":
            candidates.append({
                "source_module": "api_security",
                "raw_type": "api_scan_context",
                "detail": {
                    "target": api_result.target,
                    "auth_mode": api_result.auth_mode,
                    "auth_present": api_result.auth_present,
                    "coverage": api_result.coverage,
                    "openapi": api_result.openapi.model_dump(mode="json"),
                    "graphql": api_result.graphql.model_dump(mode="json"),
                    "auth_findings": api_result.auth_findings,
                    "warnings": api_result.warnings,
                },
            })
            for endpoint in api_result.endpoints[:200]:
                candidates.append({
                    "source_module": "api_security",
                    "raw_type": "api_endpoint",
                    "detail": endpoint.model_dump(mode="json"),
                })
            for match in api_result.template_matches[:200]:
                candidates.append({
                    "source_module": "api_security",
                    "raw_type": "api_template_match",
                    "detail": match.model_dump(mode="json"),
                })

        return candidates

    async def _call_gemini(self, candidates: list[dict], language: str) -> str:
        if self._client is None:
            raise AIAnalyzerConfigError("GEMINI_API_KEY غير مضبوط.")

        sanitized_candidates = _sanitize_for_ai(candidates)
        user_content = json.dumps(sanitized_candidates, ensure_ascii=False, indent=2)
        tenant_id=tenant_context.get()
        policy=ai_policy(tenant_id) if tenant_id else {"timeout_seconds":30,"max_output_tokens":settings.GEMINI_MAX_OUTPUT_TOKENS,"redact_secrets":True,"enabled":True,"max_input_chars":200000}
        if len(user_content) > int(policy["max_input_chars"]):
            raise AIAnalyzerResponseError("AI input exceeds tenant policy limit")
        prompt = (
            f"{_system_prompt(language)}\n\n"
            f"مرشّحو الفحص / Scan candidates:\n{user_content}\n\n"
            "IMPORTANT: Base every finding only on the supplied scan evidence. "
            "Do not assume a vulnerability merely because a header is absent. "
            "Do not invent ports, versions, vulnerabilities, or evidence. "
            "If two targets have different evidence, reflect those differences in the report."
        )
        last_exc: Exception | None = None
        retry_delays = (0, 0.25, 0.5, 1.0)
        for attempt, delay in enumerate(retry_delays):
            if delay:
                await asyncio.sleep(delay)
            try:
                response = await asyncio.wait_for(self._client.aio.models.generate_content(
                    model=settings.GEMINI_MODEL,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=_system_prompt(language),
                        response_mime_type="application/json",
                        response_schema=RESPONSE_SCHEMA,
                        temperature=0.2,
                        max_output_tokens=min(settings.GEMINI_MAX_OUTPUT_TOKENS, int(policy["max_output_tokens"])),
                    ),
                ), timeout=int(policy["timeout_seconds"]))
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                msg = str(exc).lower()
                retryable = any(x in msg for x in ("503", "unavailable", "429", "resource exhausted", "temporarily"))
                if not retryable or attempt == 3:
                    raise AIAnalyzerResponseError(f"فشل الاتصال بـ Gemini API: {exc}") from exc
        if last_exc is not None:
            raise AIAnalyzerResponseError(f"فشل الاتصال بـ Gemini API: {last_exc}") from last_exc

        text = getattr(response, "text", None)
        if not text:
            raise AIAnalyzerResponseError("استجابة Gemini لا تحتوي على نص.")
        return text

    def _parse_json_response(self, text: str) -> dict:
        cleaned = re.sub(
            r"^```(?:json)?\s*|\s*```$",
            "",
            text.strip(),
            flags=re.MULTILINE,
        )
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise AIAnalyzerResponseError(
                f"استجابة Gemini ليست JSON صالح: {exc}. الاستجابة الخام: {text[:500]}"
            ) from exc

        if not isinstance(parsed, dict) or "executive_summary" not in parsed or "findings" not in parsed:
            raise AIAnalyzerResponseError(
                "استجابة Gemini ناقصة الحقول المطلوبة (executive_summary/findings)."
            )
        if not isinstance(parsed["findings"], list):
            raise AIAnalyzerResponseError("حقل findings في استجابة Gemini يجب أن يكون مصفوفة.")
        return parsed

    def _build_report(
        self,
        parsed: dict,
        network_result: NetworkScanResult | None,
        web_result: WebScanResult | None,
    ) -> AnalysisReport:
        findings: list[AnalyzedFinding] = []
        for raw_finding in parsed["findings"]:
            try:
                severity = Severity(raw_finding["severity"])
            except (KeyError, ValueError):
                severity = Severity.INFO

            findings.append(
                AnalyzedFinding(
                    finding_id=str(uuid.uuid4()),
                    source_module=raw_finding.get("source_module", "unknown"),
                    title=raw_finding.get("title", "Untitled Finding"),
                    severity=severity,
                    description=raw_finding.get("description", ""),
                    evidence=raw_finding.get("evidence") or None,
                    remediation=raw_finding.get("remediation", ""),
                    affected_asset=raw_finding.get("affected_asset") or None,
                )
            )

        severity_counts = dict(Counter(f.severity.value for f in findings))
        return AnalysisReport(
            report_id=str(uuid.uuid4()),
            engine="ai",
            generated_at=datetime.now(timezone.utc),
            target_network=network_result.target if network_result else None,
            target_web=web_result.target if web_result else None,
            executive_summary=parsed["executive_summary"],
            findings=findings,
            total_findings=len(findings),
            severity_counts=severity_counts,
            model_used=settings.GEMINI_MODEL,
            risk_score=round(min(100.0, sum({Severity.CRITICAL:10, Severity.HIGH:7, Severity.MEDIUM:4, Severity.LOW:2, Severity.INFO:0.5}.get(f.severity,0) for f in findings) * 4.0), 1),
            coverage=self._coverage(network_result, web_result),
            top_recommendations=[f.remediation for f in sorted(findings, key=lambda x: {Severity.CRITICAL:10, Severity.HIGH:7, Severity.MEDIUM:4, Severity.LOW:2, Severity.INFO:0}.get(x.severity,0), reverse=True)[:5]],
            limitations=["Coverage is limited to the selected scan profile and the evidence returned by the target.", "AI analysis does not replace manual validation of high-impact findings."],
        )

    @staticmethod
    def _coverage(network_result, web_result) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if network_result:
            out["network"] = network_result.coverage
        if web_result:
            out["web"] = {"profile": web_result.profile, "crawled_urls": web_result.crawled_urls_count, "forms": web_result.forms_count, "endpoints": web_result.endpoints_count, "parameters": web_result.parameters_count, "js_assets": web_result.js_assets_count, "template_matches": web_result.template_matches_count, "vulnerability_checks": len(web_result.vulnerability_checks), "headers_checked": len(web_result.security_headers)}
        return out

    def _empty_report(
        self,
        network_result: NetworkScanResult | None,
        web_result: WebScanResult | None,
        note: str,
    ) -> AnalysisReport:
        return AnalysisReport(
            report_id=str(uuid.uuid4()),
            engine="ai",
            generated_at=datetime.now(timezone.utc),
            target_network=network_result.target if network_result else None,
            target_web=web_result.target if web_result else None,
            executive_summary=note,
            findings=[],
            total_findings=0,
            severity_counts={},
            model_used=None,
        )
