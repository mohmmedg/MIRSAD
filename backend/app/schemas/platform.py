from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class RawObservation(BaseModel):
    observation_id: str
    scan_id: str | None = None
    source: str
    asset: str
    observed_at: datetime | None = None
    data: dict[str, Any] = Field(default_factory=dict)

class FindingEvidence(BaseModel):
    evidence_id: str | None = None
    observation_id: str | None = None
    source: str
    asset: str
    evidence: str
    confidence: float = 0.5
    reference: str | None = None

class NormalizedFinding(BaseModel):
    finding_id: str
    scan_id: str | None = None
    observation_ids: list[str] = Field(default_factory=list)
    endpoint_id: str | None = None
    location: str | None = None
    source_module: str
    rule_id: str = ""
    title: str
    severity: str = "Info"
    confidence: float = 0.5
    tool_version: str | None = None
    scanner_confidence: float | None = None
    ai_confidence: float | None = None
    status: str = "OPEN"
    verification_status: str = "UNVERIFIED"
    execution_id: str | None = None
    engine_result_id: str | None = None
    raw_artifact_id: str | None = None
    raw_locator: str | None = None
    # A pointer is not evidence integrity: the canonical encrypted artifact must
    # have a verifiable sha256 digest, stored independently of any display text.
    raw_artifact_sha256: str | None = None
    verification_replay: str | None = None
    security_impact: str | None = None
    independent_verification: str | None = None
    cve: str | None = None
    cvss: float | None = None
    epss: float | None = None
    kev: bool | None = None
    category: str = "security"
    parameter: str | None = None
    method: str | None = None
    request: str | None = None
    response: str | None = None
    payload: str | None = None
    fingerprint: str = ""
    risk_contribution: float = 0.0
    description: str = ""
    evidence: list[FindingEvidence] = Field(default_factory=list)
    affected_asset: str | None = None
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    observation_count: int = 0
    evidence_count: int = 0
    risk_context: dict[str, float] = Field(default_factory=dict)
    last_seen: datetime | None = None
    # Reference-layer enrichment (static, free, no API key required):
    # CWE = the weakness class (https://cwe.mitre.org), MITRE ATT&CK = the
    # adversary tactic/technique this weakness class enables
    # (https://attack.mitre.org). Populated by
    # app.modules.threat_intel.enrichment; left empty when no confident
    # mapping exists (e.g. purely informational findings).
    cwe: dict[str, str] | None = None
    mitre_attack: list[dict[str, str]] = Field(default_factory=list)
    # OWASP Top 10 (2021) category this finding falls under — same
    # static/free keyword-matched enrichment as cwe/mitre_attack above.
    owasp: dict[str, str] | None = None
    # Real CVE records from the NIST NVD API (app.modules.rule_based_analysis
    # .nvd_client), auto-attached when a network finding has a matched
    # product+version. Empty when no product/version was identifiable or NVD
    # was unreachable — never fabricated.
    cve_matches: list[dict[str, Any]] = Field(default_factory=list)
    # Optional external threat-intel context (Shodan/VirusTotal/AbuseIPDB),
    # only populated when the operator configured the corresponding API key.
    # See app.modules.threat_intel.external_clients.
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    # How the scanner discovered this result. Optional for legacy snapshots.
    discovery_method: str | None = None
    discovery_command: str | None = None
    exploitability: str | None = None
    impact: str | None = None
    root_cause: str | None = None
    priority: str = "P3"
    verification_reason: str | None = None
    verification_id: str | None = None
    verification_method: str | None = None
    verification_timestamp: str | None = None
    # Confirmation is a reporting contract layered on top of verifier status.
    # A finding may be detected/verified operationally yet remain a candidate
    # until its evidence is complete and provenance is available.
    confirmation_state: str = "CANDIDATE"
    assessment_state: str = "INCONCLUSIVE"  # CONFIRMED / LIKELY / INCONCLUSIVE / FALSE_POSITIVE / NOT_TESTED
    confirmation_reason: str | None = None
    affected_assets: list[str] = Field(default_factory=list)

class RiskAssessment(BaseModel):
    score: float = 0.0
    severity: str = "Info"
    confidence: float = 0.0
    factors: dict[str, float] = Field(default_factory=dict)

class CorrelatedFinding(NormalizedFinding):
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    related_finding_ids: list[str] = Field(default_factory=list)
    duplicate_count: int = 1
    source_engines: list[str] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

class ScanCoverage(BaseModel):
    network: dict[str, Any] = Field(default_factory=dict)
    web: dict[str, Any] = Field(default_factory=dict)
    api: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    # Endpoint-level disclosure distinguishes discovery from actual testing.
    endpoint_matrix: list[dict[str, Any]] = Field(default_factory=list)
    tested: int = 0
    partial: int = 0
    not_tested: int = 0
    not_configured: int = 0
    failed: int = 0
    numerator: int = 0
    denominator: int = 0
    percentage: float = 0.0
    technologies: list[str] = Field(default_factory=list)
    assets: int = 0

class ScanSnapshotMetadata(BaseModel):
    scan_id: str
    target: str
    normalized_target: str
    scope: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=list)
    authentication_state: str = "anonymous"
    configuration: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    duration_seconds: float | None = None

class UnifiedScanResult(BaseModel):
    scan_id: str
    target: str
    normalized_target: str | None = None
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
    # Subdomains discovered during the scan. Each entry keeps the discovery method/evidence.
    subdomains: list[dict[str, Any]] = Field(default_factory=list)
    subdomain_scans: list[dict[str, Any]] = Field(default_factory=list)
    tls: dict[str, Any] = Field(default_factory=dict)
    javascript_intelligence: dict[str, Any] = Field(default_factory=dict)
    ai_validation: dict[str, Any] = Field(default_factory=dict)
    pipeline: dict[str, Any] = Field(default_factory=dict)
    snapshot_version: str = "2"
    verification_summary: dict[str, Any] = Field(default_factory=dict)
    snapshot_metadata: ScanSnapshotMetadata | None = None
    limitations: list[str] = Field(default_factory=list)
    compliance: dict[str, Any] = Field(default_factory=dict)
    report_metadata: dict[str, Any] = Field(default_factory=dict)
    scanner_version: str = "1.0"
    ruleset_version: str = "1.0"
    risk_engine_version: str = "1.0"
    # Trend tracking against the most recent completed scan of this exact
    # target: which findings are brand new, which ones from last time are
    # gone (fixed — or just no longer detected, see note below), and how
    # many persist unchanged. None when this is the first scan of a target
    # (nothing to diff against yet). See correlator.compute_scan_diff.
    scan_diff: dict[str, Any] | None = None
    # Optional external threat-intel context for the target as a whole
    # (Shodan/VirusTotal/AbuseIPDB) — see
    # app.modules.threat_intel.external_clients. Empty unless the operator
    # configured at least one provider's API key.
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    assessment_intelligence: dict[str, Any] = Field(default_factory=dict)
    external_scanners: dict[str, Any] = Field(default_factory=dict)
    advanced_security: dict[str, Any] = Field(default_factory=dict)
    canonical_artifacts: list[dict[str, Any]] = Field(default_factory=list)

class FullScanRequest(BaseModel):
    target: str
    network: bool = True
    web: bool = True
    api: bool = True
    network_profile: str = "balanced"
    network_ports: str | None = None
    network_timing: int | None = None
    web_profile: str = "deep"
    max_pages: int = Field(default=500, ge=1, le=10000)
    max_depth: int = Field(default=8, ge=0, le=32)
    api_spec_url: str | None = None
    auth_header: str | None = None
    cookie: str | None = None
    # Automatic pre-crawl login: if all three are supplied, the web scanner
    # submits these credentials to the login form at login_url before
    # crawling, and reuses whatever session cookie that login produces for
    # the rest of the scan — instead of requiring the operator to already
    # hold a valid session cookie/token by hand (the previous only option,
    # via auth_header/cookie above).
    login_url: str | None = None
    login_username: str | None = None
    login_password: str | None = None
    # Out-of-band callback domain the operator controls (Interactsh,
    # Burp Collaborator, or a self-hosted DNS/HTTP canary). If set, the
    # scanner injects unique-per-parameter callback URLs into
    # SSRF/webhook-shaped parameters and records exactly what was sent and
    # where, so the operator can check their OOB dashboard for interactions
    # within the scan window. This does NOT poll or auto-confirm anything —
    # doing that correctly requires the OOB provider's own crypto protocol
    # (session registration + encrypted polling), which this scanner does
    # not implement; treat every entry here as "needs manual verification",
    # never as a confirmed finding on its own.
    oob_callback_domain: str | None = None
    graphql_introspection: bool = True
    probe_write_methods: bool = False
    # Backend-authoritative safety policy. The UI may request a mode, but the
    # server derives allowed HTTP methods from this value so a stale/malicious
    # client cannot silently upgrade a safe scan.
    destructive_confirmation: bool = False
    run_gemini: bool = False
    language: str = "ar"
    # Optional differential authorization test identities. Never persisted in scan snapshots.
    authorization_urls: list[str] = Field(default_factory=list)
    authorized_auth_header: str | None = None
    authorized_cookie: str | None = None
    unauthorized_auth_header: str | None = None
    unauthorized_cookie: str | None = None
    # Discovered subdomains are scanned only after the parent target passes
    # scope/SSRF validation. When ENFORCE_TARGET_SCOPE=true, use an explicit
    # wildcard entry such as *.example.com in ALLOWED_TARGETS to authorize them.
    scan_discovered_subdomains: bool = True
    subdomain_max_pages: int = Field(default=20, ge=1, le=100)
    subdomain_max_depth: int = Field(default=2, ge=0, le=8)
    subdomain_max_hosts: int = Field(default=50, ge=1, le=500)
    # V5-V7 assessment controls. These are persisted in scan metadata but
    # credentials are still excluded from snapshots.
    scan_profile: str = "standard"
    safe_mode: str = "safe"
    max_requests: int = Field(default=30000, ge=100, le=1000000)
    requests_per_second: int = Field(default=10, ge=1, le=100)
    max_concurrency: int = Field(default=8, ge=1, le=64)
    crawl_forms: bool = True
    enable_incremental_diff: bool = True
    enable_asset_change_detection: bool = True
    enable_finding_lifecycle: bool = True
    # Full Assessment controls: discovery is independent from testing.
    # This lets an operator discover subdomains without automatically scanning them.
    subdomain_discovery: bool = True
    subdomain_dns_verification: bool = True
    subdomain_network_scan: bool = True
    subdomain_web_scan: bool = True
    subdomain_api_security: bool = True
    # 2026-10-10: was False, which silently dropped Low/Info WEB-HEADER-CONFIG-*
    # findings from the authoritative Findings list (see manager.py) before they
    # ever reached the report or the DefectDojo export — a real filter on real
    # scan output, not a UI-only grouping. Defaulting to True so every finding
    # the engines actually produced reaches the report/DefectDojo unfiltered;
    # set this back to False per-request if a noise-reduced view is wanted for
    # a specific scan.
    include_hardening_findings: bool = True

class ScanComparison(BaseModel):
    baseline_id: str
    current_id: str
    new_findings: list[CorrelatedFinding] = Field(default_factory=list)
    fixed_finding_ids: list[str] = Field(default_factory=list)
    unchanged_finding_ids: list[str] = Field(default_factory=list)
    severity_changes: list[dict[str, Any]] = Field(default_factory=list)
    score_delta: float = 0.0
