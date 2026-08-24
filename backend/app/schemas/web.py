"""Structured raw output for the Web Security Engine."""
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field
from app.schemas.network import ScanStatus
from app.schemas.api_security import APISecurityResult

class TLSInfo(BaseModel):
    enabled: bool
    protocol_version: str | None = None
    cipher_suite: str | None = None
    certificate_valid: bool | None = None
    certificate_expires_at: datetime | None = None
    days_until_expiry: int | None = None
    issuer: str | None = None
    error: str | None = None

class HeaderCheck(BaseModel):
    header_name: str
    present: bool
    value: str | None = None

class VulnerabilityCheck(BaseModel):
    check_name: str
    tested_parameter: str | None = None
    payload_used: str | None = None
    vulnerable: bool
    evidence: str | None = None
    url: str | None = None
    method: str = "GET"
    confidence: str = "low"

class WebEndpoint(BaseModel):
    url: str
    method: str = "GET"
    source: str = "crawler"
    status_code: int | None = None
    content_type: str | None = None
    parameters: list[str] = Field(default_factory=list)

class FormInfo(BaseModel):
    action: str
    method: str = "GET"
    inputs: list[str] = Field(default_factory=list)
    input_types: dict[str, str] = Field(default_factory=dict)

class TemplateFinding(BaseModel):
    template_id: str
    name: str
    severity_hint: str
    url: str
    method: str
    status_code: int | None = None
    evidence: str | None = None
    matched: bool = False
    tags: list[str] = Field(default_factory=list)

class WebScanResult(BaseModel):
    scan_id: str
    module: str = "web"
    target: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float | None = None

    profile: str = "balanced"
    status_code: int | None = None
    final_url: str | None = None
    content_type: str | None = None
    server_header: str | None = None
    tls_info: TLSInfo | None = None
    security_headers: list[HeaderCheck] = Field(default_factory=list)
    vulnerability_checks: list[VulnerabilityCheck] = Field(default_factory=list)

    discovered_urls: list[str] = Field(default_factory=list)
    endpoints: list[WebEndpoint] = Field(default_factory=list)
    forms: list[FormInfo] = Field(default_factory=list)
    javascript_assets: list[str] = Field(default_factory=list)
    discovered_parameters: dict[str, list[str]] = Field(default_factory=dict)
    api_candidates: list[str] = Field(default_factory=list)
    robots_urls: list[str] = Field(default_factory=list)
    sitemap_urls: list[str] = Field(default_factory=list)
    template_findings: list[TemplateFinding] = Field(default_factory=list)

    crawled_urls_count: int = 0
    forms_count: int = 0
    endpoints_count: int = 0
    parameters_count: int = 0
    js_assets_count: int = 0
    template_checks_count: int = 0
    template_matches_count: int = 0

    cookie_checks: list[str] = Field(default_factory=list)
    cors_findings: list[str] = Field(default_factory=list)
    passive_findings: list[str] = Field(default_factory=list)
    scan_warnings: list[str] = Field(default_factory=list)
    api_security: APISecurityResult | None = None
    javascript_intelligence: dict[str, Any] = Field(default_factory=dict)
    api_integration: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
