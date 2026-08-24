"""
api/routes/analysis.py

Endpoints التحليل: AI (/run)، rule-based (/rule-based/run, /rule-based/report,
/rule-based/report/all)، المقارنة (/compare)، وبحث CVE حي (/cve-lookup).

كل الـ endpoints (عدا /cve-lookup) تدعم حقل `language` اختياري ("ar" افتراضياً،
أو "en") — يتحكم بلغة محتوى التقرير المُولَّد بالكامل (عناوين findings،
الشرح، remediation، executive summary، ورد Gemini نفسه لمحرّك AI). التصنيف
(severity) والمنطق لا يتأثران بتاتاً — فقط لغة النص.

كل الـ endpoints محمية بترويسة X-API-Key (راجع app/core/security.py).
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import verify_api_key, require_analyst
from app.core.auth_context import tenant_context
from app.core.policy_enforcement import ai_policy, enforce_ai_request, release_ai_request, enforce_policy_rate_limit
from app.modules.ai_analysis.analyzer import (
    AIAnalyzer,
    AIAnalyzerConfigError,
    AIAnalyzerResponseError,
)
from app.modules.rule_based_analysis.analyzer import RuleBasedAnalyzer
from app.modules.rule_based_analysis.nvd_client import NVDLookupError, lookup_cves
from app.modules.rule_based_analysis.report_formatter import ReportFormatter
from app.schemas.analysis import AnalysisReport, AudienceLevel, FormattedReport
from app.schemas.network import NetworkScanResult
from app.schemas.web import WebScanResult
from app.schemas.api_security import APISecurityResult

router = APIRouter(
    prefix="/analysis", tags=["analysis"], dependencies=[Depends(verify_api_key), Depends(require_analyst)]
)
ai_analyzer = AIAnalyzer()
rule_based_analyzer = RuleBasedAnalyzer()
report_formatter = ReportFormatter()

Language = Literal["ar", "en"]


class AnalysisRequest(BaseModel):
    network_scan: NetworkScanResult | None = None
    web_scan: WebScanResult | None = None
    api_scan: APISecurityResult | None = None
    language: Language = "ar"


class CompareAnalysisResponse(BaseModel):
    ai_report: AnalysisReport | None = None
    ai_error: str | None = None
    rule_based_report: AnalysisReport


def _require_at_least_one_scan(request: AnalysisRequest) -> None:
    if request.network_scan is None and request.web_scan is None and request.api_scan is None:
        raise HTTPException(
            status_code=400, detail="لازم توفّر network_scan و/أو web_scan على الأقل"
        )


def _estimate_ai_input(request: AnalysisRequest) -> int:
    # Serialize the already validated Pydantic payload; this bounds prompt size
    # before any external provider call is made.
    return len(request.model_dump_json())


async def _prepare_ai(request: AnalysisRequest) -> tuple[str, dict]:
    tenant_id=tenant_context.get()
    if not tenant_id:
        raise HTTPException(401, "Tenant context is missing")
    policy=ai_policy(tenant_id)
    estimated_input=_estimate_ai_input(request)
    reserved=await enforce_ai_request(tenant_id, estimated_input, int(policy["max_output_tokens"]))
    return tenant_id, reserved


@router.post("/run", response_model=AnalysisReport)
async def run_analysis(request: AnalysisRequest) -> AnalysisReport:
    """تحليل عبر Gemini API (AI Analysis Layer). يدعم language لتغيير لغة رد Gemini بالكامل."""
    _require_at_least_one_scan(request)
    tenant_id,_policy=await _prepare_ai(request)
    try:
        return await ai_analyzer.analyze(
            network_result=request.network_scan,
            web_result=request.web_scan,
            api_result=request.api_scan,
            language=request.language,
        )
    except AIAnalyzerConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except AIAnalyzerResponseError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        await release_ai_request(tenant_id)


@router.post("/rule-based/run", response_model=AnalysisReport)
async def run_rule_based_analysis(request: AnalysisRequest) -> AnalysisReport:
    """
    تحليل عبر خوارزمية ثابتة محلية (rule-based) — بدون أي استدعاء API خارجي،
    بدون حاجة لـ GEMINI_API_KEY، ونتيجته حتمية (deterministic) دائماً.
    يرجّع الـ findings الخام (machine-readable) — لتقرير جاهز للعرض حسب
    جمهور معيّن استخدم /rule-based/report بدلاً منه.
    """
    _require_at_least_one_scan(request)
    return rule_based_analyzer.analyze(
        network_result=request.network_scan,
        web_result=request.web_scan,
        api_result=request.api_scan,
        language=request.language,
    )


class RuleBasedReportRequest(AnalysisRequest):
    audience: AudienceLevel = AudienceLevel.TECHNICAL


@router.post("/rule-based/report", response_model=FormattedReport)
async def generate_rule_based_report(request: RuleBasedReportRequest) -> FormattedReport:
    """
    تقرير جاهز للعرض من محرّك rule-based، بصياغة تناسب جمهوراً محدداً:
    - technical: كل التفاصيل التقنية والدليل، لفريق تقني/أمني
    - managerial: أولويات وتأثير على العمل، بدون تفاصيل تقنية، لصاحب قرار
    - non_technical: لغة يومية مبسّطة جداً، بدون أي مصطلحات، لشخص غير تقني
    نفس الـ findings بالضبط بكل الحالات — يختلف فقط العرض والصياغة واللغة.
    """
    _require_at_least_one_scan(request)
    report = rule_based_analyzer.analyze(
        network_result=request.network_scan,
        web_result=request.web_scan,
        api_result=request.api_scan,
        language=request.language,
    )
    return report_formatter.format_report(report, request.audience, request.language)


@router.post("/rule-based/report/all", response_model=dict[str, FormattedReport])
async def generate_all_rule_based_reports(request: AnalysisRequest) -> dict[str, FormattedReport]:
    """
    يولّد التقارير الثلاثة معاً (technical, managerial, non_technical) بضربة
    واحدة — مفيد لعرضها جنب بعض بالـ Dashboard، وبما إنه rule-based بدون
    تكلفة API، تشغيل الثلاثة سوا لا يكلّف شيء إضافي.
    """
    _require_at_least_one_scan(request)
    report = rule_based_analyzer.analyze(
        network_result=request.network_scan,
        web_result=request.web_scan,
        api_result=request.api_scan,
        language=request.language,
    )
    return {
        level.value: report_formatter.format_report(report, level, request.language)
        for level in AudienceLevel
    }


@router.post("/compare", response_model=CompareAnalysisResponse)
async def compare_analysis(request: AnalysisRequest) -> CompareAnalysisResponse:
    """
    يشغّل المحرّكين معاً على نفس بيانات الفحص ويرجّع التقريرين جنب بعض
    للمقارنة المباشرة، بنفس اللغة المطلوبة. لو AI فشل (مثلاً مفتاح API غير
    مضبوط)، لا يفشل الطلب كامل — rule_based_report يرجع دائماً، وai_error
    يوضّح السبب.
    """
    _require_at_least_one_scan(request)
    tenant_id,_policy=await _prepare_ai(request)

    rule_based_report = rule_based_analyzer.analyze(
        network_result=request.network_scan,
        web_result=request.web_scan,
        api_result=request.api_scan,
        language=request.language,
    )

    ai_report = None
    ai_error = None
    try:
        try:
            ai_report = await ai_analyzer.analyze(
                network_result=request.network_scan,
                web_result=request.web_scan,
                api_result=request.api_scan,
                language=request.language,
            )
        except AIAnalyzerConfigError as exc:
            ai_error = str(exc)
        except AIAnalyzerResponseError as exc:
            ai_error = str(exc)
    finally:
        await release_ai_request(tenant_id)
    return CompareAnalysisResponse(
        ai_report=ai_report, ai_error=ai_error, rule_based_report=rule_based_report
    )


class CVELookupRequest(BaseModel):
    product: str
    version: str


class CVELookupResult(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None = None
    severity: str | None = None
    published: str | None = None


class CVELookupResponse(BaseModel):
    product: str
    version: str
    results: list[CVELookupResult]
    source: str = "NVD (National Vulnerability Database)"


@router.post("/cve-lookup", response_model=CVELookupResponse)
async def cve_lookup(request: CVELookupRequest) -> CVELookupResponse:
    await enforce_policy_rate_limit("cve", tenant_context.get() or "legacy", int(ai_policy(tenant_context.get() or "legacy")["rate_limit_per_minute"]))
    """
    بحث CVE حي عبر NVD API الرسمي (https://nvd.nist.gov)، مع كاش محلي
    (أسبوع) لتقليل الطلبات المتكررة.

    ملاحظة مهمة: هذا **منفصل** عن الجدول اليدوي KNOWN_VULNERABLE_VERSIONS
    المستخدم بمحرك rule-based الحتمي (/rule-based/run) — ذاك الجدول صغير
    ومُعَدّ يدوياً لأغراض العرض التوضيحي فقط (راجع قسم Security
    Considerations بالـ README). هذا الـ endpoint هو المصدر الشامل الفعلي
    لو احتجت بحث CVE حقيقي لمنتج/إصدار معيّن.
    """
    try:
        raw_results = await lookup_cves(request.product, request.version)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except NVDLookupError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return CVELookupResponse(
        product=request.product,
        version=request.version,
        results=[CVELookupResult(**r) for r in raw_results],
    )

class AuthCompareProfile(BaseModel):
    name: str
    auth_type: Literal["none","bearer","jwt","cookie","basic","custom"] = "none"
    value: str | None = None
    headers: dict[str, str] = {}

class AuthCompareRequest(BaseModel):
    endpoint: str
    profiles: list[AuthCompareProfile] = Field(min_length=1, max_length=4)

@router.post("/auth-compare")
async def auth_compare(request: AuthCompareRequest):
    await enforce_policy_rate_limit("auth-compare", tenant_context.get() or "legacy", int(ai_policy(tenant_context.get() or "legacy")["rate_limit_per_minute"]))
    """Compare explicit test identities only; credentials are never persisted or returned."""
    from app.core.config import verify_target_in_scope, ScopeViolationError, SSRFRiskError
    from urllib.parse import urlparse
    parsed = urlparse(request.endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="endpoint must be a valid http/https URL")
    try:
        verify_target_in_scope(parsed.hostname)
    except (ScopeViolationError, SSRFRiskError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    from app.modules.auth_session.engine import AuthProfile, compare_endpoint
    profiles=[]
    for p in request.profiles:
        typ="bearer" if p.auth_type=="jwt" else p.auth_type
        profiles.append(AuthProfile.from_input(p.name, typ, p.value, p.headers))
    try:
        result=await compare_endpoint(request.endpoint, profiles)
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"endpoint":result.endpoint,"unauthenticated":result.unauthenticated,"profiles":result.profiles,"differences":result.differences,"note":"Only explicitly supplied test profiles were compared; no privilege guessing was performed."}
