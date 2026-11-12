// types/api.ts
//
// يعكس schemas/{network,web,analysis}.py بالـ backend حرفياً. أي تعديل هناك
// لازم ينعكس هون يدوياً (ما في codegen آلي بهاي المرحلة).

// ---- Network ----

export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type PortState = "open" | "closed" | "filtered";

export interface PortInfo {
  port: number;
  protocol: string;
  state: PortState;
  service_name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  cpe?: string[];
  scripts?: ScriptResult[];
}

export interface OSMatch {
  name: string;
  accuracy: number;
}

export interface ScriptResult {
  script_id: string;
  output: string;
}

export interface NetworkScanResult {
  scan_id: string;
  module: "network";
  target: string;
  scan_type: string;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  duration_seconds: number | null;
  host_up: boolean | null;
  addresses: string[];
  hostnames: string[];
  open_ports: PortInfo[];
  filtered_ports_count: number;
  closed_ports_count: number;
  os_matches: OSMatch[];
  host_scripts: ScriptResult[];
  traceroute: Array<Record<string, string | null>>;
  scan_warnings: string[];
  coverage: Record<string, unknown>;
  error_message: string | null;
  raw_nmap_command: string | null;
}

// ---- Web ----

export interface TLSInfo {
  enabled: boolean;
  protocol_version: string | null;
  cipher_suite: string | null;
  certificate_valid: boolean | null;
  certificate_expires_at: string | null;
  days_until_expiry: number | null;
  issuer: string | null;
  error: string | null;
  // Per-protocol-version handshake results, e.g. { "TLSv1": { status: "ENABLED" } }.
  // NOT_TESTED (with a reason) means the local scanner couldn't verify that
  // protocol — never conflate it with NOT_SUPPORTED (a real server rejection).
  protocol_support: Record<string, { status: "ENABLED" | "NOT_SUPPORTED" | "NOT_TESTED"; reason?: string }>;
  weak_protocols_enabled: string[];
  weak_cipher: boolean;
  weak_cipher_detail: string | null;
}

export interface HeaderCheck {
  header_name: string;
  present: boolean;
  value: string | null;
  analysis?: string | null;
}

export interface VulnerabilityCheck {
  check_name: string;
  tested_parameter: string | null;
  payload_used: string | null;
  vulnerable: boolean;
  evidence: string | null;
}

export interface WebScanResult {
  scan_id: string;
  module: string;
  target: string;
  status: string;
  started_at: string;
  finished_at?: string | null;
  duration_seconds?: number | null;
  profile: string;
  status_code?: number | null;
  final_url?: string | null;
  content_type?: string | null;
  server_header?: string | null;
  tls_info?: TLSInfo | null;
  security_headers: Array<{ header_name: string; present: boolean; value?: string | null }>;
  vulnerability_checks: Array<{ check_name: string; tested_parameter?: string | null; payload_used?: string | null; vulnerable: boolean; evidence?: string | null; url?: string | null; method?: string; confidence?: string }>;
  discovered_urls: string[];
  endpoints: Array<{ url: string; method: string; source: string; status_code?: number | null; content_type?: string | null; parameters: string[] }>;
  forms: Array<{ action: string; method: string; inputs: string[]; input_types: Record<string, string> }>;
  javascript_assets: string[];
  discovered_parameters: Record<string, string[]>;
  api_candidates: string[];
  robots_urls: string[];
  sitemap_urls: string[];
  template_findings: Array<{ template_id: string; name: string; severity_hint: string; url: string; method: string; status_code?: number | null; evidence?: string | null; matched: boolean; tags: string[] }>;
  crawled_urls_count: number;
  forms_count: number;
  endpoints_count: number;
  parameters_count: number;
  js_assets_count: number;
  template_checks_count: number;
  template_matches_count: number;
  cookie_checks: string[];
  cors_findings: string[];
  passive_findings: string[];
  scan_warnings: string[];
  error_message?: string | null;
  api_security?: APISecurityResult | null;
  api_integration?: Record<string, unknown>;
  source_intelligence?: {
    status?: string;
    enabled?: boolean;
    html?: Record<string, unknown>;
    javascript?: Record<string, unknown>;
    source_maps?: Record<string, unknown>;
    technologies?: Array<{ name: string; confidence?: number; evidence?: string[] }>;
    findings?: Array<{ title: string; severity?: string; confidence?: number; evidence_redacted?: string; category?: string; source?: string }>;
    detectors?: Record<string, { status?: string; findings?: unknown[] } | unknown>;
    coverage?: Record<string, number>;
    warnings?: string[];
  };
  external_scanners?: Record<string, { status?: string; findings?: unknown[]; reason?: string }>;
}


// ---- API Security ----

export interface APIMethodObservation {
  method: string;
  status_code: number | null;
  allow_header: string | null;
  content_type: string | null;
  authenticated_status: number | null;
  auth_status_delta: string | null;
  skipped: boolean;
  note: string | null;
}

export interface APIEndpoint {
  path: string;
  url: string;
  methods: string[];
  source: string;
  security: string[];
  observations: APIMethodObservation[];
}

export interface OpenAPIParameter {
  name: string; location: string; required: boolean; schema_type: string | null; format: string | null; example_present: boolean;
}
export interface SchemaValidation {
  endpoint: string; method: string; direction: string; status_code: number | null; valid: boolean | null; errors: string[];
}
export interface GraphQLOperation { operation_type: string; type_name: string; fields: string[]; }
export interface JWTClaimsAnalysis { present: boolean; algorithm: string | null; token_type: string | null; issuer_present: boolean; audience_present: boolean; expiry_present: boolean; expiry_status: string | null; not_before_present: boolean; sensitive_claims: string[]; warnings: string[]; }

export interface OpenAPISummary {
  discovered: boolean;
  source_url: string | null;
  version: string | null;
  title: string | null;
  server_urls: string[];
  endpoint_count: number;
  security_schemes: string[];
  global_security: boolean;
  parse_error: string | null;
  parameters: OpenAPIParameter[];
  schema_validation: SchemaValidation[];
}

export interface GraphQLInfo {
  discovered: boolean;
  endpoint: string | null;
  introspection_attempted: boolean;
  introspection_enabled: boolean;
  introspection_status: number | null;
  query_type: string | null;
  mutation_type: string | null;
  subscription_type: string | null;
  type_count: number;
  field_count: number;
  introspection_error: string | null;
  operations: GraphQLOperation[];
  sensitive_field_hints: string[];
}

export interface APITemplateMatch {
  template_id: string;
  title: string;
  severity: string;
  endpoint: string;
  evidence: string;
  remediation: string;
}

export interface WebSocketEndpoint {
  url: string;
  source: string;
  handshake_attempted: boolean;
  handshake_status: number | null;
  handshake_accepted: boolean;
  origin_test_attempted: boolean;
  origin_test_status: number | null;
  origin_reflected: boolean;
  error: string | null;
}

export interface APISecurityResult {
  scan_id: string;
  module: "api_security";
  target: string;
  status: ScanStatus | string;
  started_at: string;
  finished_at: string | null;
  duration_seconds: number | null;
  openapi: OpenAPISummary;
  graphql: GraphQLInfo;
  websockets: WebSocketEndpoint[];
  endpoints: APIEndpoint[];
  template_matches: APITemplateMatch[];
  auth_mode: string;
  auth_present: boolean;
  auth_findings: string[];
  jwt_analysis: JWTClaimsAnalysis;
  openapi_parameters: OpenAPIParameter[];
  schema_validations: SchemaValidation[];
  coverage: Record<string, unknown>;
  warnings: string[];
  error_message: string | null;
}

// ---- Analysis ----

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type AudienceLevel = "technical" | "managerial" | "non_technical";
export type AnalysisEngine = "ai" | "rule_based";
export type Language = "ar" | "en";

export interface AnalyzedFinding {
  finding_id: string;
    scan_id?: string;
  source_module: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string | null;
  remediation: string;
  affected_asset: string | null;
  plain_summary: string | null;
  business_impact: string | null;
}

export interface AnalysisReport {
  report_id: string;
  engine: AnalysisEngine;
  generated_at: string;
  target_network: string | null;
  target_web: string | null;
  executive_summary: string;
  findings: AnalyzedFinding[];
  total_findings: number;
  severity_counts: Partial<Record<Severity, number>>;
  model_used: string | null;
  risk_score: number;
  coverage: Record<string, unknown>;
  top_recommendations: string[];
  limitations: string[];
}

export interface FormattedReport {
  report_id: string;
  engine: AnalysisEngine;
  audience: AudienceLevel;
  generated_at: string;
  title: string;
  body_markdown: string;
  total_findings: number;
  severity_counts: Partial<Record<Severity, number>>;
}

export interface CompareAnalysisResponse {
  ai_report: AnalysisReport | null;
  ai_error: string | null;
  rule_based_report: AnalysisReport;
}

export const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export interface ExternalScannerExecution {
  version: string | null;
  command: string[];
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  exit_code: number | null;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "PARTIAL" | "FAILED" | "SKIPPED" | "UNAVAILABLE";
  reason?: string | null;
  findings_count?: number;
  execution_id?: string | null;
  artifacts?: Array<{ artifact_id: string; kind: string; sha256: string; size_bytes: number; raw_locator?: string | null }>;
}

export interface CanonicalArtifactRef {
  artifact_id: string;
  scan_id: string;
  execution_id?: string | null;
  engine?: string | null;
  tool?: string | null;
  kind: "stdout" | "stderr" | "report" | "jsonl" | "json" | "output" | "raw" | "part";
  sha256: string;
  size_bytes: number;
  encoding?: string | null;
  part_index?: number | null;
  parent_artifact_id?: string | null;
}

export interface UnifiedScanResult {
  scan_id:string; target:string; status:string; started_at:string; finished_at?:string;
  network_scan?:NetworkScanResult|null; web_scan?:WebScanResult|null; api_scan?:APISecurityResult|null;
  findings:Array<{finding_id:string;scan_id?:string;source_module:string;rule_id?:string;title:string;severity:string;confidence:number;status?:string;verification_status?:string;category?:string;parameter?:string|null;method?:string|null;request?:string|null;response?:string|null;payload?:string|null;fingerprint?:string;risk_contribution?:number;description:string;evidence:Array<{source:string;asset:string;evidence:string}>;affected_asset?:string;remediation?:string;tags:string[];risk:{score:number;severity:string;confidence:number};discovery_method?:string;discovery_command?:string;exploitability?:string;impact?:string;cwe?:{id:string;name:string;url:string}|null;mitre_attack?:Array<{id:string;name:string;tactic:string;url:string}>;cve_matches?:Array<{cve_id:string;description:string;cvss_score:number|null;severity:string|null;published:string|null}>;cve?:string|null;cvss?:number|null;epss?:number|null;kev?:boolean|null;scanner_confidence?:number|null;ai_confidence?:number|null;execution_id?:string|null;engine_result_id?:string|null;raw_artifact_id?:string|null;raw_locator?:string|null;source_engines?:string[];sources?:Array<Record<string,unknown>>;observations?:Array<Record<string,unknown>>}>;
  coverage:{capabilities?:Record<string,string>;tested?:number;partial?:number;not_tested?:number;not_configured?:number;failed?:number;numerator?:number;denominator?:number;percentage?:number;[key:string]:unknown};
  risk_score:number; technologies:string[]; assets:Array<Record<string,unknown>>; warnings:string[]; dns:Record<string,unknown>; subdomains:Array<{hostname:string;method:string;source:string;evidence:string}>; subdomain_scans?:Array<Record<string,unknown>>; tls:Record<string,unknown>; javascript_intelligence:Record<string,unknown>; threat_intel?:Record<string,unknown>;
  pipeline?:Record<string,unknown>; snapshot_version?:string; scanner_version?:string; ruleset_version?:string; risk_engine_version?:string;
  external_scanners?: Record<string, ExternalScannerExecution>;
  canonical_artifacts?: CanonicalArtifactRef[];
  /** Gemini's explanatory validation verdicts only — never authoritative for severity/status/risk. */
  ai_validation?:Record<string,unknown>;
  assessment_intelligence?:Record<string,unknown>;
}
