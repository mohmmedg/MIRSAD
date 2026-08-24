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
}

export interface HeaderCheck {
  header_name: string;
  present: boolean;
  value: string | null;
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
  tls_info?: unknown;
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

export interface UnifiedScanResult { scan_id:string; target:string; status:string; started_at:string; finished_at?:string; network_scan?:NetworkScanResult|null; web_scan?:WebScanResult|null; api_scan?:APISecurityResult|null; findings:Array<{finding_id:string;source_module:string;title:string;severity:string;confidence:number;description:string;evidence:Array<{source:string;asset:string;evidence:string}>;affected_asset?:string;remediation?:string;tags:string[];risk:{score:number;severity:string;confidence:number}}>; risk_score:number; technologies:string[]; assets:Array<Record<string,unknown>>; warnings:string[]; dns:Record<string,unknown>; tls:Record<string,unknown>; javascript_intelligence:Record<string,unknown>; }
