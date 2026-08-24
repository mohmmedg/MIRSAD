from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class FindingEvidence(BaseModel):
    source: str
    asset: str
    evidence: str
    confidence: float = 0.5
    reference: str | None = None

class NormalizedFinding(BaseModel):
    finding_id: str
    source_module: str
    title: str
    severity: str = "Info"
    confidence: float = 0.5
    description: str = ""
    evidence: list[FindingEvidence] = Field(default_factory=list)
    affected_asset: str | None = None
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

class RiskAssessment(BaseModel):
    score: float = 0.0
    severity: str = "Info"
    confidence: float = 0.0
    factors: dict[str, float] = Field(default_factory=dict)

class CorrelatedFinding(NormalizedFinding):
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    related_finding_ids: list[str] = Field(default_factory=list)
    duplicate_count: int = 1

class ScanCoverage(BaseModel):
    network: dict[str, Any] = Field(default_factory=dict)
    web: dict[str, Any] = Field(default_factory=dict)
    api: dict[str, Any] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    assets: int = 0

class UnifiedScanResult(BaseModel):
    scan_id: str
    target: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    network_scan: Any | None = None
    web_scan: Any | None = None
    api_scan: Any | None = None
    findings: list[CorrelatedFinding] = Field(default_factory=list)
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    risk_score: float = 0.0
    technologies: list[str] = Field(default_factory=list)
    assets: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    dns: dict[str, Any] = Field(default_factory=dict)
    tls: dict[str, Any] = Field(default_factory=dict)
    javascript_intelligence: dict[str, Any] = Field(default_factory=dict)
    ai_validation: dict[str, Any] = Field(default_factory=dict)

class FullScanRequest(BaseModel):
    target: str
    network: bool = True
    web: bool = True
    api: bool = True
    network_profile: str = "balanced"
    network_ports: str | None = None
    network_timing: int | None = None
    web_profile: str = "deep"
    max_pages: int = 80
    max_depth: int = 4
    api_spec_url: str | None = None
    auth_header: str | None = None
    cookie: str | None = None
    graphql_introspection: bool = True
    probe_write_methods: bool = False
    run_gemini: bool = False
    language: str = "ar"

class ScanComparison(BaseModel):
    baseline_id: str
    current_id: str
    new_findings: list[CorrelatedFinding] = Field(default_factory=list)
    fixed_finding_ids: list[str] = Field(default_factory=list)
    unchanged_finding_ids: list[str] = Field(default_factory=list)
    severity_changes: list[dict[str, Any]] = Field(default_factory=list)
    score_delta: float = 0.0
