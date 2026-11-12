"""
schemas/analysis.py

النماذج الموحّدة لمخرجات AI Analysis Layer.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AudienceLevel(str, Enum):
    """
    مستوى الجمهور المستهدف بعرض التقرير.
    """

    TECHNICAL = "technical"
    MANAGERIAL = "managerial"
    NON_TECHNICAL = "non_technical"


class AnalyzedFinding(BaseModel):
    """
    finding واحد بعد تحليل AI — موحّد بغض النظر عن مصدره.

    ملاحظة مهمة:
    حقلا evidence و affected_asset ما زالا يقبلان None داخل Pydantic،
    لكن هذا الملف لا يُستخدم مباشرة كـ response_schema لـ Gemini.
    عند إرسال Schema إلى Gemini يجب استخدام Schema متوافق مع Gemini
    (STRING بدل ["string", "null"]).
    """

    finding_id: str
    source_module: str = Field(description="network أو web")
    title: str
    severity: Severity
    description: str = Field(
        description="شرح الثغرة بلغة مفهومة لغير المتخصص"
    )

    evidence: str | None = Field(
        default=None,
        description="الدليل التقني المستخرج من الفحص الخام"
    )

    remediation: str = Field(
        description="إجراء المعالجة المقترح"
    )

    affected_asset: str | None = Field(
        default=None,
        description="مثلاً 'port 22/tcp' أو 'header: X-Frame-Options'"
    )

    plain_summary: str | None = Field(
        default=None,
        description="شرح بلغة يومية بسيطة جداً، بدون أي مصطلحات تقنية"
    )

    business_impact: str | None = Field(
        default=None,
        description="صياغة موجّهة لصاحب قرار: التأثير على العمل/المخاطرة"
    )


class AnalysisReport(BaseModel):
    """
    التقرير النهائي.

    engine يوضّح مصدر التحليل:
    ai أو rule_based.
    """

    report_id: str
    engine: str = Field(description="ai أو rule_based")
    generated_at: datetime
    target_network: str | None = None
    target_web: str | None = None

    executive_summary: str = Field(
        description="ملخّص تنفيذي للجهات غير التقنية"
    )

    findings: list[AnalyzedFinding] = Field(default_factory=list)

    total_findings: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)

    model_used: str | None = None
    risk_score: float = 0.0
    coverage: dict[str, Any] = Field(default_factory=dict)
    top_recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class FormattedReport(BaseModel):
    """
    تقرير مُنسّق جاهز للعرض/التصدير.
    """

    report_id: str = Field(
        description="نفس report_id تبع AnalysisReport المصدر"
    )
    engine: str
    audience: AudienceLevel
    generated_at: datetime
    title: str

    body_markdown: str = Field(
        description="محتوى التقرير كامل، جاهز للعرض مباشرة أو التحويل لـ PDF/HTML"
    )

    total_findings: int
    severity_counts: dict[str, int] = Field(default_factory=dict)