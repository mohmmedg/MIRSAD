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
    # Per-protocol-version handshake results: {"TLSv1": {"status": "ENABLED"|"NOT_SUPPORTED"|"NOT_TESTED", "reason": "..."}}
    # Deliberately separate from protocol_version (the version actually negotiated by
    # the default handshake) so the scanner never claims a protocol was tested when the
    # local TLS stack could not attempt it.
    protocol_support: dict[str, dict[str, str]] = Field(default_factory=dict)
    weak_protocols_enabled: list[str] = Field(default_factory=list)
    weak_cipher: bool = False
    weak_cipher_detail: str | None = None

class HeaderCheck(BaseModel):
    header_name: str
    present: bool
    value: str | None = None
    analysis: str | None = None

class VulnerabilityCheck(BaseModel):
    check_name: str
    tested_parameter: str | None = None
    payload_used: str | None = None
    vulnerable: bool
    evidence: str | None = None
    url: str | None = None
    method: str = "GET"
    confidence: str = "low"
    # Proof of Concept: the actual raw request/response exchange that
    # produced this result, truncated to a safe size. Report readers (and
    # anyone manually re-verifying a finding) get exact reproduction steps
    # instead of just a one-line description of what was tested.
    poc_request: str | None = None
    poc_response: str | None = None

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
    # 2.2: whether the match was confirmed by a second, independent
    # non-destructive request (see web_scan/scanner.py::_run_templates).
    # None = no verification attempted (e.g. HEAD-only template); True/False
    # = the repeat request did/did not reproduce the same match.
    verified: bool | None = None

class LoginResult(BaseModel):
    attempted: bool = False
    succeeded: bool = False
    login_url: str | None = None
    reason: str | None = None
    # Full localStorage snapshot captured right after a successful
    # browser-based login (see _perform_login_via_browser). Needed because a
    # browser-rendered login and the later browser-rendered crawl pass each
    # run in their own throwaway browser instance — without replaying this,
    # an SPA that keeps its session token in localStorage (not a cookie,
    # e.g. OWASP Juice Shop) would look logged-out again for the crawl pass
    # even though login itself succeeded.
    local_storage: dict[str, str] | None = None

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
    login_result: LoginResult | None = None
    # Authentication protection inventory: endpoint discovery, CAPTCHA/rate-limit evidence,
    # and explicit non-verification states for controls that require credentialed active tests.
    auth_protection: dict[str, Any] = Field(default_factory=dict)
    # Populated by manager.py when differential authorization testing runs
    # for a web-only scan (no API module enabled) — mirrors
    # APISecurityResult.authorization_testing so normalizer.py can pick it
    # up from either module without caring which one actually ran the test.
    authorization_testing: dict | None = None
    # Out-of-band injection probes sent (see FullScanRequest.oob_callback_domain).
    # Each entry: {correlation_id, parameter, url, sent_at}. Never
    # auto-confirmed — see the field docstring on oob_callback_domain for why.
    oob_probes: list[dict] = Field(default_factory=list)
    template_findings: list[TemplateFinding] = Field(default_factory=list)

    crawled_urls_count: int = 0
    forms_count: int = 0
    endpoints_count: int = 0
    parameters_count: int = 0
    js_assets_count: int = 0
    template_checks_count: int = 0
    template_matches_count: int = 0
    browser_pages_rendered: int = 0
    forced_browsing_checks: int = 0
    request_budget: dict[str, Any] = Field(default_factory=dict)

    cookie_checks: list[str] = Field(default_factory=list)
    cors_findings: list[str] = Field(default_factory=list)
    cors_verification: dict[str, Any] = Field(default_factory=dict)
    cookie_details: list[dict[str, Any]] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)
    passive_findings: list[str] = Field(default_factory=list)
    scan_warnings: list[str] = Field(default_factory=list)
    # Session cookie obtained by the built-in login step, handed to external engines.
    # exclude=True: never serialized, persisted or exported.
    session_cookie: str | None = Field(default=None, exclude=True)
    api_security: APISecurityResult | None = None
    javascript_intelligence: dict[str, Any] = Field(default_factory=dict)
    # Native passive source intelligence is an enrichment layer: HTML/DOM/JS/source-map
    # observations, technology correlation, redacted secret candidates and bounded findings.
    source_intelligence: dict[str, Any] = Field(default_factory=dict)
    # Optional external detectors attached to this web result by the orchestrator/worker.
    # They are normalized later; unavailable engines are recorded in scan metadata.
    external_scanners: dict[str, Any] = Field(default_factory=dict)
    api_integration: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
