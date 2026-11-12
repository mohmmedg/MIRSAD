// api/client.ts
//
// طبقة واحدة لكل نداءات الـ backend. كل الفحوصات حالياً synchronous من
// جهة الـ HTTP request (الـ backend نفسه async داخلياً) — يعني fetch()
// بيضل معلّق لحد ما الفحص يخلص. لفحص "full" هذا ممكن ياخد دقائق، فالواجهة
// لازم تُظهر حالة تحميل واضحة (ScanControlPanel يتكفّل بهذا).
//
// كل دوال التحليل تاخد `language` — يتحكم بلغة محتوى التقرير المُولَّد
// بالكامل (بما فيه رد Gemini نفسه لمحرّك AI)، مش بس واجهة الموقع.

import { getAccessToken, refreshSession } from "../auth/supabase";
import { httpStatusMessage, safeDiagnosticText } from "../utils/security";
import type {
  AnalysisReport,
  AudienceLevel,
  CompareAnalysisResponse,
  FormattedReport,
  Language,
  NetworkScanResult,
  WebScanResult,
  APISecurityResult,
  UnifiedScanResult,
} from "../types/api";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? (import.meta.env.PROD ? "" : "http://127.0.0.1:8000");
const API_V1 = `${API_BASE_URL}/api/v1`;

// Optional legacy X-API-Key (only relevant when the backend runs with ENABLE_LEGACY_API_KEY).
// 2026-10-17 hardening: the key is NEVER baked into the bundle any more (every VITE_* variable
// is public JavaScript) and is kept in sessionStorage only, so it disappears when the tab closes
// instead of living in localStorage forever. Any value an older build left in localStorage is
// removed on first read.
const API_KEY_STORAGE = "security_scanner_api_key";

export function getApiKey(): string {
  try {
    try { localStorage.removeItem(API_KEY_STORAGE); } catch { /* ignore */ }
    return sessionStorage.getItem(API_KEY_STORAGE)?.trim() || "";
  } catch {
    return "";
  }
}

export function setApiKey(value: string): void {
  try {
    const trimmed = value.trim();
    if (trimmed) sessionStorage.setItem(API_KEY_STORAGE, trimmed);
    else sessionStorage.removeItem(API_KEY_STORAGE);
  } catch {
    // Storage may be unavailable (private mode); the UI must keep working.
  }
}

export class ApiError extends Error {
  status: number;
  // *** إضافة ***: الجسم الكامل لاستجابة الخطأ (مهم لـ409 حيث يرجّع
  // السيرفر حالة السجل الحالية لاستخدامها بحل التعارض محليًا).
  body?: Record<string, unknown>;
  constructor(status: number, message: string, body?: Record<string, unknown>) {
    super(status > 0 ? httpStatusMessage(status) : safeDiagnosticText(message, "The request could not be completed."));
    this.status = status;
    this.name = "ApiError";
    this.body = body;
  }
}

async function putJson<TResponse>(path:string,body:unknown):Promise<TResponse>{
  const response=await fetch(`${API_V1}${path}`,{method:"PUT",headers:{"Content-Type":"application/json",...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`}:{})},body:JSON.stringify(body)});
  if(!response.ok){throw new ApiError(response.status, httpStatusMessage(response.status))}
  return await response.json() as TResponse;
}

async function postJson<TResponse>(path: string, body: unknown): Promise<TResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_V1}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}),
        ...(getApiKey() ? { "X-API-Key": getApiKey() } : {}),
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the backend.");
  }

  if (!response.ok) {
    throw new ApiError(response.status, httpStatusMessage(response.status));
  }

  return (await response.json()) as TResponse;
}

export function runNetworkScan(
  target: string,
  scanType: string,
  ports?: string,
  timing?: number
): Promise<NetworkScanResult> {
  return postJson<NetworkScanResult>("/network/scan", { target, scan_type: scanType, ports: ports || undefined, timing });
}

export function runWebScan(
  target: string,
  profile: string = "balanced",
  maxPages?: number,
  maxDepth?: number
): Promise<WebScanResult> {
  return postJson<WebScanResult>("/web/scan", {
    target,
    profile,
    max_pages: maxPages || undefined,
    max_depth: maxDepth || undefined,
  });
}

export function runAPISecurityScan(body: {
  target: string;
  spec_url?: string;
  auth_header?: string;
  cookie?: string;
  enable_graphql_introspection?: boolean;
  probe_write_methods?: boolean;
}): Promise<APISecurityResult> {
  return postJson<APISecurityResult>("/api-security/scan", body);
}

interface ScanBundle {
  network_scan?: NetworkScanResult | null;
  web_scan?: WebScanResult | null;
  api_scan?: APISecurityResult | null;
}

export function runAiAnalysis(bundle: ScanBundle, language: Language): Promise<AnalysisReport> {
  return postJson<AnalysisReport>("/analysis/run", { ...bundle, language });
}

export function runRuleBasedAnalysis(bundle: ScanBundle, language: Language): Promise<AnalysisReport> {
  return postJson<AnalysisReport>("/analysis/rule-based/run", { ...bundle, language });
}

export function generateRuleBasedReport(
  bundle: ScanBundle,
  audience: AudienceLevel,
  language: Language
): Promise<FormattedReport> {
  return postJson<FormattedReport>("/analysis/rule-based/report", { ...bundle, audience, language });
}

export function generateAllRuleBasedReports(
  bundle: ScanBundle,
  language: Language
): Promise<Record<AudienceLevel, FormattedReport>> {
  return postJson<Record<AudienceLevel, FormattedReport>>("/analysis/rule-based/report/all", {
    ...bundle,
    language,
  });
}

export function compareAnalysis(
  bundle: ScanBundle,
  language: Language
): Promise<CompareAnalysisResponse> {
  return postJson<CompareAnalysisResponse>("/analysis/compare", { ...bundle, language });
}

// خام synchronous — الواجهة ما تستخدمه بعد 2026-09-13 (استبدلته runFullScanAsync
// بالثلاثة ضوابط الفردية). أُبقي عليه هنا لأي استخدام مباشر/برمجي مستقبلي؛
// الباك اند نفسه صار يطبّق مهلة max_scan_duration_minutes عليه أيضاً (504 عند
// التجاوز) لكن الطلب يبقى HTTP واحد طويل بلا مهلة من جهة المتصفح.
export function runFullScan(body: Record<string, unknown>): Promise<import("../types/api").UnifiedScanResult> { return postJson<import("../types/api").UnifiedScanResult>("/platform/scan", body); }
// audience لم تكن مُمرَّرة سابقاً رغم أن الـ backend يدعمها (technical/managerial/non_technical) —
// كانت النتيجة أن أي طلب من هنا يعود دائماً بتقرير "technical" بغض النظر عمّا يختاره المستخدم.
export function generatePlatformReport(scanId: string, language="ar", format="pdf", audience="technical"): Promise<{format:string;content:unknown;content_base64?:string;scan_id?:string}> { return getJson(`/platform/scans/${encodeURIComponent(scanId)}/report?language=${encodeURIComponent(language)}&format=${encodeURIComponent(format)}&audience=${encodeURIComponent(audience)}`); }
export function listAssets(): Promise<{assets:Array<Record<string,unknown>>}> { return getJson("/platform/assets"); }

// 2.3: MIRSAD Score — organization-wide weighted risk aggregate (see
// app/api/routes/platform.py::organization_score and
// app/modules/risk_engine/engine.py::organization_score).
export interface OrganizationScoreAsset { target: string; scan_id?: string | null; score: number; weight: number; finding_count: number; }
export interface OrganizationScoreResponse { score: number; assets: OrganizationScoreAsset[]; asset_count: number; generated_at: string | null; }
export function getOrganizationScore(limit = 200): Promise<OrganizationScoreResponse> {
  return getJson(`/platform/organization-score?limit=${encodeURIComponent(String(limit))}`);
}

// 4.3: advisory-only remediation suggestion for one finding (see
// app/modules/ai_analysis/analyzer.py::AIAnalyzer.suggest_remediation and
// app/api/routes/analysis.py POST /analysis/remediate). Never executes
// anything - text + a confidence/source label only.
export interface RemediationSuggestion { text: string; source: "ai" | "template" | "none"; confidence: "HIGH" | "MEDIUM" | "LOW"; model?: string | null; }
export function suggestRemediation(finding: { title: string; description?: string; severity?: string; affected_asset?: string | null; tags?: string[] }, language: "ar" | "en" = "ar"): Promise<RemediationSuggestion> {
  return postJson("/analysis/remediate", {
    title: finding.title,
    description: finding.description ?? "",
    severity: finding.severity ?? "Medium",
    affected_asset: finding.affected_asset ?? null,
    tags: finding.tags ?? [],
    language,
  });
}
export interface ScanHistoryRecord {
  scan_id:string; job_id?:string|null; target:string; status:string; created_at?:string|null; started_at?:string|null; finished_at?:string|null;
  risk_score?:number|null; findings_count:number; result:import("../types/api").UnifiedScanResult|null; error_message?:string|null;
  result_quality?: {
    status:string;
    issues:Array<{code:string;severity?:string;message:string;asset?:string}>;
    signals:Array<Record<string,unknown>>;
    warning_count:number;
    active_check_count:number;
  } | null;
  scan_kind?:string|null;
}
export function getScanHistory(limit = 50): Promise<{ scans: import("../types/api").UnifiedScanResult[] }> {
  return getJson(`/platform/history?limit=${encodeURIComponent(String(limit))}`);
}
export interface ScanHistoryQuery {
  limit?: number; offset?: number; q?: string; status?: string;
}
export function getScanHistoryRecords(query: ScanHistoryQuery = {}): Promise<{ scans: ScanHistoryRecord[]; total: number; limit: number; offset: number }> {
  const params = new URLSearchParams();
  params.set("limit", String(Math.max(1, Math.min(200, Number(query.limit ?? 50)))));
  params.set("offset", String(Math.max(0, Number(query.offset ?? 0))));
  if (query.q?.trim()) params.set("q", query.q.trim());
  if (query.status && query.status !== "all") params.set("status", query.status);
  return getJson(`/platform/scan-history?${params.toString()}`);
}

function readableApiError(_value: unknown, fallback: string): string {
  return fallback;
}
// 2026-09-15 fix: getJson() had zero timeout and zero retry, unlike getAuthMe()/
// useSetupStatus() in auth/supabase.ts which already use an AbortController. When
// a request hit the backend's transient Supabase/Postgres disconnect (SSL EOF —
// see with_db_retry's docstring in backend/app/core/database.py), the fetch()
// promise could sit unsettled far longer than the ~1-3s these list endpoints
// normally take, with no client-side signal to fall back to an error state —
// this is what "Checking your session..." / an empty scan-history page hanging
// for 5+ minutes with no error actually was.
const GET_JSON_TIMEOUT_MS = 30_000;

function isTransientFailure(err: unknown, status?: number): boolean {
  if (status !== undefined) return status >= 500; // server-side error, not e.g. 401/404
  if (err instanceof DOMException && err.name === "AbortError") return true; // our own timeout
  return true; // fetch() itself threw -> network-level failure (offline, connection reset, DNS, ...)
}

async function getJsonOnce<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), GET_JSON_TIMEOUT_MS);
  let r: Response;
  try {
    r = await fetch(`${API_V1}${path}`, {
      signal: controller.signal,
      headers: {
        ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}),
        ...(getApiKey() ? { "X-API-Key": getApiKey() } : {}),
      },
    });
  } catch (err) {
    throw new ApiError(0, "Cannot reach backend", { transient: isTransientFailure(err) } as Record<string, unknown>);
  } finally {
    window.clearTimeout(timer);
  }
  if (!r.ok) {
    let d = r.statusText;
    try { const b = await r.json(); d = readableApiError(b?.detail ?? b, d); } catch {}
    throw new ApiError(r.status, httpStatusMessage(r.status), { transient: isTransientFailure(undefined, r.status) } as Record<string, unknown>);
  }
  return r.json() as Promise<T>;
}

// Serializes concurrent 401s onto a single in-flight refresh instead of firing
// one refreshSession() per failed request (ScanProgressPage alone can have a
// WS reconnect and an HTTP poll land 401 within the same tick).
let pendingRefresh: ReturnType<typeof refreshSession> | null = null;
function refreshSessionOnce() {
  if (!pendingRefresh) {
    pendingRefresh = refreshSession().finally(() => { pendingRefresh = null; });
  }
  return pendingRefresh;
}

async function getJson<T>(path: string): Promise<T> {
  try {
    return await getJsonOnce<T>(path);
  } catch (err) {
    // A 401 on a long-running scan (these can run for many hours — see
    // ScanProgressPage's poll loop) almost always means the access token
    // expired while the tab was backgrounded/suspended and AuthGate's 30s
    // proactive-refresh timer was throttled by the browser rather than any
    // real auth problem. Previously this was treated as non-transient and
    // surfaced straight to the operator as "تعذر تحديث حالة الفحص" even
    // though a token refresh+retry would have silently fixed it.
    if (err instanceof ApiError && err.status === 401) {
      const refreshed = await refreshSessionOnce().catch(() => null);
      if (refreshed?.access_token) {
        try {
          return await getJsonOnce<T>(path);
        } catch (retryErr) {
          throw retryErr;
        }
      }
      throw err;
    }
    // One retry only, and only for a transient/network/5xx failure — never
    // for other 4xx (not-found, validation), where retrying is pointless.
    if (err instanceof ApiError && (err.body as { transient?: boolean } | undefined)?.transient) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      return getJsonOnce<T>(path);
    }
    throw err;
  }
}

export interface JobStage {
  id:string; label:string; status:string; progress:number;
  started_at:string|null; finished_at:string|null; message:string; tool?:string;
}
export interface JobSnapshot {
  job_id:string; job_type:string; target:string; status:string; progress:number;
  current_engine:string|null; logs:string[]; created_at:string; started_at:string|null;
  finished_at:string|null; duration_seconds:number|null; error_message:string|null; result:unknown|null;
  stages:JobStage[]; elapsed_seconds:number; eta_seconds:number|null; current_eta_seconds:number|null; eta_finish_at:string|null; current_eta_finish_at:string|null; execution_config:Record<string,unknown>;
  completed_tasks:number; total_tasks:number; task_breakdown?:Record<string,number>; execution_id:string|null;
}
export interface ExecutionSummary {
  execution_id:string; scan_id:string; job_id:string; attempt:number; job_type:string; target:string; status:string;
  current_engine:string|null; metadata:Record<string,unknown>; started_at:string; finished_at:string|null; event_count:number;
}
export interface ExecutionEvent {
  event_id:string; execution_id:string; scan_id:string; operation_id:string|null; sequence:number; event_type:string;
  stage:string|null; tool:string|null; message:string; payload:Record<string,unknown>; created_at:string;
}
export function startFullScanAsync(body: Record<string,unknown>):Promise<{job_id:string;scan_id:string;status:string}>{return postJson('/platform/scan/async',body)}
export function getJob(jobId:string):Promise<JobSnapshot>{return getJson(`/jobs/${encodeURIComponent(jobId)}`)}
// Per-job memo: the live result can be hundreds of KB. We send the `updated_at` we already hold and the
// server answers {unchanged:true} (a few bytes) when nothing changed, so polling costs almost nothing.
const liveResultMemo=new Map<string,Record<string,unknown>>()
export async function getLiveScanResult(jobId:string):Promise<Record<string,unknown>>{
  const cached=liveResultMemo.get(jobId)
  const since=typeof cached?.updated_at==='string'?cached.updated_at:''
  const url=`/jobs/${encodeURIComponent(jobId)}/live-result${since?`?since=${encodeURIComponent(since)}`:''}`
  const data=await getJson<Record<string,unknown>>(url)
  if(data&&data.unchanged===true&&cached) return cached
  if(data&&data.unchanged!==true){
    if(liveResultMemo.size>20) liveResultMemo.delete(liveResultMemo.keys().next().value as string)
    liveResultMemo.set(jobId,data)
  }
  return data
}
export function getActiveJobs():Promise<JobSnapshot[]>{return getJson("/jobs/active")}
export interface ToolStatus {
  key: string;
  name: string;
  kind: "binary" | "native" | "service";
  enabled: boolean;
  installed: boolean;
  status: "UP" | "DOWN";
  binary?: string;
  url?: string;
  health?: string;
  worker_count?: number;
  heartbeat_age_seconds?: number | null;
  status_reason?: string | null;
}
export function getToolStatus(): Promise<{tools: ToolStatus[]; all_defaults_enabled: boolean}> {
  return getJson("/platform/tools/status");
}
/** Present when the request was scoped to one MIRSAD scan. `synced:false` = the scan has not reached DefectDojo (yet). */
export interface DefectDojoScanScope { scan_id: string; synced: boolean; engagement_id: number | null }
export interface DefectDojoDashboard {
  enabled: boolean;
  health: string;
  url: string;
  products: number;
  engagements: number;
  tests: number;
  findings: number;
  findings_by_severity: Record<string, number>;
  native_surfaces: Array<{key:string; label:string; path:string}>;
  scan_scope?: DefectDojoScanScope | null;
  error: string | null;
}
export function getDefectDojoDashboard(scanId?: string | null): Promise<DefectDojoDashboard> {
  const q = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
  return getJson(`/platform/defectdojo/dashboard${q}`);
}
export interface DefectDojoFinding {
  id: number; title: string; severity: string; date: string | null;
  active: boolean; verified: boolean; false_p: boolean; duplicate: boolean;
  risk_accepted: boolean; mitigated: string | null;
  cwe: number | null; cve: string | null; component: string | null;
  test: string | null; engagement: string | null; product: string | null; product_id?: number | null;
}
export interface DefectDojoFindingsPage {
  enabled: boolean; health: string | null; total: number; limit: number; offset: number;
  findings: DefectDojoFinding[]; error: string | null;
  products?: Array<{ id: number; name: string }>;
  scan_scope?: DefectDojoScanScope | null;
}
export interface DefectDojoFindingDetail {
  id: number; title: string; severity: string;
  description: string | null; mitigation: string | null; impact: string | null;
  references: string | null; steps_to_reproduce: string | null;
  cvss_score: number | null; cvss_vector: string | null; epss_score: number | null;
  cwe: number | null; cve_ids: string[];
  file_path: string | null; line: number | null;
  component: string | null; component_version: string | null;
  date: string | null; age_days: number | null; sla_days_remaining: number | null;
  active: boolean; verified: boolean; tags: string[];
}
export interface DefectDojoFindingsQuery {
  limit?: number; offset?: number; severity?: string; q?: string; active?: boolean;
  product?: number; order?: "severity" | "newest" | "oldest"; scanId?: string | null;
}
export function getDefectDojoFindings(query: DefectDojoFindingsQuery = {}): Promise<DefectDojoFindingsPage> {
  const p = new URLSearchParams();
  p.set("limit", String(Math.max(1, Math.min(200, query.limit ?? 25))));
  p.set("offset", String(Math.max(0, query.offset ?? 0)));
  if (query.severity) p.set("severity", query.severity);
  if (query.q?.trim()) p.set("q", query.q.trim());
  if (query.active !== undefined) p.set("active", String(query.active));
  if (query.product !== undefined) p.set("product", String(query.product));
  if (query.order) p.set("order", query.order);
  if (query.scanId) p.set("scan_id", query.scanId);
  return getJson(`/platform/defectdojo/findings?${p.toString()}`);
}
export function getDefectDojoFinding(findingId: number): Promise<DefectDojoFindingDetail> {
  return getJson(`/platform/defectdojo/findings/${encodeURIComponent(String(findingId))}`);
}
/** Sync state of one scan towards DefectDojo (mappings + queued/failed sync jobs). */
export interface DefectDojoScanSyncStatus {
  health: string;
  mappings: Array<Record<string, unknown>>;
  jobs: Array<{ status: string; attempt_count?: number; next_retry_at?: string | null; last_error_code?: string | null; last_error_message?: string | null }>;
}
export function getScanDefectDojoStatus(scanId: string): Promise<DefectDojoScanSyncStatus> {
  return getJson(`/platform/scans/${encodeURIComponent(scanId)}/defectdojo`);
}
export function resyncScanToDefectDojo(scanId: string): Promise<{ status: string }> {
  return postJson(`/platform/scans/${encodeURIComponent(scanId)}/defectdojo/resync`, {});
}
export function getJobExecutions(jobId:string):Promise<ExecutionSummary[]>{return getJson(`/jobs/${encodeURIComponent(jobId)}/executions`)}
export function getExecutionEvents(jobId:string, executionId:string, limit=2000, offset=0, afterSequence?:number):Promise<ExecutionEvent[]>{const q=`limit=${Math.min(5000,Math.max(1,limit))}&offset=${Math.max(0,offset)}${afterSequence!=null?`&after_sequence=${Math.max(0,Math.floor(afterSequence))}`:""}`;return getJson(`/jobs/${encodeURIComponent(jobId)}/executions/${encodeURIComponent(executionId)}/events?${q}`)}
export interface ExecutionEventQuery {limit?:number; afterSequence?:number; beforeSequence?:number; stage?:string; eventTypes?:string[]; newestFirst?:boolean}
export function queryExecutionEvents(jobId:string, executionId:string, o:ExecutionEventQuery={}):Promise<ExecutionEvent[]>{
  const p=new URLSearchParams(); p.set("limit",String(Math.min(5000,Math.max(1,o.limit??1000))));
  if(o.afterSequence!=null)p.set("after_sequence",String(Math.max(0,Math.floor(o.afterSequence))));
  if(o.beforeSequence!=null)p.set("before_sequence",String(Math.floor(o.beforeSequence)));
  if(o.stage)p.set("stage",o.stage); if(o.eventTypes?.length)p.set("event_type",o.eventTypes.join(","));
  if(o.newestFirst)p.set("newest_first","true");
  return getJson(`/jobs/${encodeURIComponent(jobId)}/executions/${encodeURIComponent(executionId)}/events?${p.toString()}`)
}
export interface ExecutionBuckets {req:number; ok:number; redir:number; c4:number; c5:number; fail:number; cmds:number; errs:number}
export interface ExecutionEventsSummary {total:number; last_sequence:number; stages:Record<string,Record<string,number>>; buckets?:Record<string,ExecutionBuckets>}
export function getExecutionEventsSummary(jobId:string, executionId:string):Promise<ExecutionEventsSummary>{return getJson(`/jobs/${encodeURIComponent(jobId)}/executions/${encodeURIComponent(executionId)}/events-summary`)}
export function pauseJob(jobId:string):Promise<JobSnapshot>{return postJson(`/jobs/${encodeURIComponent(jobId)}/pause`,{})}
export function resumeJob(jobId:string):Promise<JobSnapshot>{return postJson(`/jobs/${encodeURIComponent(jobId)}/resume`,{})}
export function cancelJob(jobId:string):Promise<JobSnapshot>{return postJson(`/jobs/${encodeURIComponent(jobId)}/cancel`,{})}

// 2026-09-13: الضوابط الفردية (Network/Web/API) كانت تستدعي runFullScan()
// المتزامن مباشرة وتنتظر الـ fetch() لحد ما يخلص — بلا أي مهلة من جهة
// العميل، وحتى لما أُضيفت مهلة بالباك اند (asyncio.wait_for) يبقى المتصفح
// معلّق على طلب HTTP واحد طويل عرضة لانقطاع أي وسيط بالمنتصف (proxy، نوم
// الجهاز، إلخ). هذي تستبدل ذلك بنفس مسار /platform/scan/async المُتحقَّق
// منه أصلاً (يستخدمه FullScanControl)، مع polling دوري بدل انتظار طلب واحد.
export async function runFullScanAsync(
  body: Record<string, unknown>,
  opts?: { intervalMs?: number; signal?: AbortSignal },
): Promise<UnifiedScanResult> {
  const { job_id } = await startFullScanAsync(body);
  const intervalMs = opts?.intervalMs ?? 2000;
  for (;;) {
    if (opts?.signal?.aborted) throw new ApiError(0, "Cancelled");
    const snap = await getJob(job_id);
    if (snap.status === "completed" || snap.status === "partial") {
      return snap.result as UnifiedScanResult;
    }
    if (snap.status === "failed" || snap.status === "cancelled") {
      throw new ApiError(0, "Scan failed.");
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
export function listContinuousSchedules(tenantId?:string):Promise<{schedules:Array<Record<string,unknown>>}>{return getJson(`/continuous/schedules${adminTenantQuery(tenantId)}`)}
export function createContinuousSchedule(request:Record<string,unknown>, interval_seconds=3600, tenantId?:string):Promise<Record<string,unknown>>{return postJson('/continuous/schedules',{request,interval_seconds,...(tenantId?{tenant_id:tenantId}:{})})}
export function deleteContinuousSchedule(id:string,tenantId?:string):Promise<{deleted:string}>{return fetch(`${API_V1}/continuous/schedules/${encodeURIComponent(id)}${adminTenantQuery(tenantId)}`,{method:'DELETE',headers:{...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`} : {}),...(getApiKey()?{'X-API-Key':getApiKey()}: {})}}).then(async r=>{if(!r.ok)throw new ApiError(r.status,httpStatusMessage(r.status));return r.json()})}

export interface AdminTenant { tenant_id:string; name:string; created_at:string }
export function listAdminTenants():Promise<{tenants:AdminTenant[]}>{return getJson('/admin/tenants')}
function adminTenantQuery(tenantId?:string):string{return tenantId?`?tenant_id=${encodeURIComponent(tenantId)}`:""}

export interface AdminUser {
  user_id: string;
  email: string;
  role: "viewer" | "analyst" | "admin" | "owner";
  is_active: boolean;
  created_at: string;
  tenant_id: string;
  tenant_name: string;
}
export interface AdminOverview {
  tenant_id: string;
  actor: { user_id: string; tenant_id: string; role: string; email: string };
  users: { total: number; active: number; admins: number };
  api_keys: number;
  active_sessions: number;
  active_jobs: number;
  supabase_admin_sync: boolean;
  environment?: string;
}
export function getAdminOverview(tenantId?:string): Promise<AdminOverview> { return getJson(`/admin/overview${adminTenantQuery(tenantId)}`); }
export function listAdminUsers(search = "", tenantId?: string): Promise<{ users: AdminUser[]; total: number }> {
  const q = new URLSearchParams();
  if (search) q.set("search", search);
  if (tenantId) q.set("tenant_id", tenantId);
  return getJson(`/admin/users${q.toString() ? `?${q.toString()}` : ""}`);
}
export function createAdminUser(email: string, password: string, tenantId?:string): Promise<AdminUser> {
  return postJson("/admin/users", { email, password, ...(tenantId?{tenant_id:tenantId}:{}) });
}
export function updateAdminUser(userId: string, body: { role?: AdminUser["role"]; is_active?: boolean }, tenantId?: string): Promise<AdminUser> {
  return patchJson(`/admin/users/${encodeURIComponent(userId)}${adminTenantQuery(tenantId)}`, body);
}
export function resetAdminUserPassword(userId: string, newPassword?: string, tenantId?: string): Promise<{ ok: boolean; user_id: string; email: string; new_password: string }> {
  return postJson(`/admin/users/${encodeURIComponent(userId)}/reset-password${adminTenantQuery(tenantId)}`, newPassword ? { new_password: newPassword } : {});
}
export function deleteAdminUser(userId: string, tenantId?: string): Promise<{ ok: boolean; user_id: string }> {
  return fetch(`${API_V1}/admin/users/${encodeURIComponent(userId)}${adminTenantQuery(tenantId)}`, {
    method: "DELETE",
    headers: {
      ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}),
      ...(getApiKey() ? { "X-API-Key": getApiKey() } : {}),
    },
  }).then(async (r) => {
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, httpStatusMessage(r.status));
    return d as { ok: boolean; user_id: string };
  });
}
export function listAdminAudit(limit = 100, tenantId?:string): Promise<{ events: Array<Record<string, unknown>> }> {
  const q=new URLSearchParams({limit:String(limit)}); if(tenantId) q.set("tenant_id",tenantId);
  return getJson(`/admin/audit?${q.toString()}`);
}
export async function deleteScan(scanId: string): Promise<{ deleted: string }> {
  const r = await fetch(`${API_V1}/platform/scan-history/${encodeURIComponent(scanId)}`, {
    method: "DELETE",
    headers: { ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}), ...(getApiKey() ? { "X-API-Key": getApiKey() } : {}) },
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, r.status === 409 && typeof d?.detail === "string" ? d.detail : httpStatusMessage(r.status));
  return d as { deleted: string };
}
async function patchJson<TResponse>(path: string, body: unknown): Promise<TResponse> {
  try {
    const r = await fetch(`${API_V1}${path}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}), ...(getApiKey() ? { "X-API-Key": getApiKey() } : {}) },
      body: JSON.stringify(body),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, httpStatusMessage(r.status));
    return d as TResponse;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, "Cannot reach backend");
  }
}

export interface AdminPolicies { security:Record<string,unknown>; scan:Record<string,unknown>; ai:Record<string,unknown>; notifications:Record<string,unknown>; updated_at:string }
export interface AdminFeatureFlags { [key:string]: boolean }
export interface AdminApiKey { key_id:string; name:string; user_id:string; scopes:string[]; expires_at:string|null; last_used_at:string|null; revoked:boolean; created_at:string }
export interface AdminSession { id:string; user_id:string; created_at:string; expires_at:string; revoked:boolean }
export function getAdminPolicies(tenantId?:string):Promise<AdminPolicies>{return getJson(`/admin/policies${adminTenantQuery(tenantId)}`)}
export function updateAdminPolicy(kind:'security'|'scan'|'ai'|'notifications',values:Record<string,unknown>,tenantId?:string):Promise<Record<string,unknown>>{return putJson(`/admin/policies/${kind}`,{values,...(tenantId?{tenant_id:tenantId}:{})})}
export function getAdminFeatures(tenantId?:string):Promise<AdminFeatureFlags>{return getJson(`/admin/features${adminTenantQuery(tenantId)}`)}
export function updateAdminFeatures(flags:AdminFeatureFlags,tenantId?:string):Promise<AdminFeatureFlags>{return putJson('/admin/features',{flags,...(tenantId?{tenant_id:tenantId}:{})})}
export function getAdminPermissions():Promise<{permissions:string[];role_matrix:Record<string,string[]>}>{return getJson('/admin/permissions')}
export function listAdminSessions(tenantId?:string):Promise<{sessions:AdminSession[]}>{return getJson(`/admin/sessions${adminTenantQuery(tenantId)}`)}
export function revokeAdminSession(id:string,tenantId?:string):Promise<{ok:boolean}>{return postJson(`/admin/sessions/${encodeURIComponent(id)}/revoke${adminTenantQuery(tenantId)}`,{})}
export function revokeAllAdminSessions(tenantId?:string):Promise<{revoked:number}>{return postJson(`/admin/sessions/revoke-all${adminTenantQuery(tenantId)}`,{})}
export function listAdminApiKeys(tenantId?:string):Promise<{keys:AdminApiKey[]}>{return getJson(`/admin/api-keys${adminTenantQuery(tenantId)}`)}
export function createAdminApiKey(body:{name:string;scopes?:string[];expires_in_days?:number},tenantId?:string):Promise<{key_id:string;secret:string;name:string;scopes:string[];expires_at:string|null;warning:string}>{return postJson('/admin/api-keys',{...body,...(tenantId?{tenant_id:tenantId}:{})})}
export function revokeAdminApiKey(id:string,tenantId?:string):Promise<{ok:boolean}>{return postJson(`/admin/api-keys/${encodeURIComponent(id)}/revoke${adminTenantQuery(tenantId)}`,{})}
export function getAdminHealth(tenantId?:string):Promise<{checks:Record<string,string>;environment:string;target_scope_enforced:boolean}>{return getJson(`/admin/health${adminTenantQuery(tenantId)}`)}
export function getAdminBackupStatus():Promise<{status:string;note:string;application_triggered_backup:boolean}>{return getJson('/admin/backup')}

export interface SecurityEvent { event_id:string; event_type:string; severity:string; actor_user_id:string|null; target:string|null; data:Record<string,unknown>; risk_score:number; detected:boolean; created_at:string }
export interface SecurityAlert { alert_id:string; event_id:string|null; title:string; severity:string; status:string; risk_score:number; data:Record<string,unknown>; created_at:string; acknowledged_at:string|null }
export interface SecurityIncident { incident_id:string; title:string; description:string; severity:string; status:string; assignee_user_id:string|null; sla_due_at:string|null; related_asset_id:string|null; related_scan_id:string|null; related_finding_id:string|null; related_user_id:string|null; evidence:Array<Record<string,unknown>>; timeline:Array<Record<string,unknown>>; ai_explanation:string|null; created_at:string; updated_at:string }
export function getSecuritySummary(tenantId?:string):Promise<{open_alerts:number;critical_alerts:number;open_incidents:number;events_24h:number}>{return getJson(`/admin/security/summary${adminTenantQuery(tenantId)}`)}
export function listSecurityEvents(limit=100,tenantId?:string):Promise<{events:SecurityEvent[]}>{const q=new URLSearchParams({limit:String(limit)});if(tenantId)q.set("tenant_id",tenantId);return getJson(`/admin/security/events?${q.toString()}`)}
export function listSecurityAlerts(limit=100,tenantId?:string):Promise<{alerts:SecurityAlert[]}>{const q=new URLSearchParams({limit:String(limit)});if(tenantId)q.set("tenant_id",tenantId);return getJson(`/admin/security/alerts?${q.toString()}`)}
export function updateSecurityAlert(id:string,status:"open"|"acknowledged"|"resolved",tenantId?:string):Promise<{ok:boolean;status:string}>{return patchJson(`/admin/security/alerts/${encodeURIComponent(id)}${adminTenantQuery(tenantId)}`,{status})}
export function listSecurityIncidents(limit=100,tenantId?:string):Promise<{incidents:SecurityIncident[]}>{const q=new URLSearchParams({limit:String(limit)});if(tenantId)q.set("tenant_id",tenantId);return getJson(`/admin/incidents?${q.toString()}`)}
export function createSecurityIncident(body:{title:string;description?:string;severity?:string;tenant_id?:string}):Promise<{incident_id:string}>{return postJson('/admin/incidents',body)}
export function updateSecurityIncident(id:string,body:Record<string,unknown>,tenantId?:string):Promise<{ok:boolean;incident_id:string;status:string}>{return patchJson(`/admin/incidents/${encodeURIComponent(id)}${adminTenantQuery(tenantId)}`,body)}

export interface ComplianceControl { control_id:string; framework:string; title:string; description:string; tags:string[]; max_severity:string; enabled:boolean }
export interface ComplianceAssessment { assessment_id?:string; framework:string; score:number; passed:number; failed:number; controls:Array<Record<string,unknown>>; generated_at?:string }
export interface CIPolicy { critical_fail:number; high_fail:number; medium_fail:number; enabled:boolean }
export function getComplianceControls(framework?:string):Promise<{controls:ComplianceControl[]}>{return getJson(`/compliance/controls${framework?`?framework=${encodeURIComponent(framework)}`:""}`)}
export function assessCompliance(findings:Array<Record<string,unknown>>,framework?:string,coverage?:Record<string,unknown>):Promise<ComplianceAssessment>{return postJson('/compliance/assess',{findings,framework,coverage})}
export function getCIPolicy():Promise<CIPolicy>{return getJson('/compliance/ci-policy')}
export function updateCIPolicy(policy:CIPolicy):Promise<CIPolicy>{return putJson('/compliance/ci-policy',policy)}
export function securityGateSarif(findings:Array<Record<string,unknown>>):Promise<Record<string,unknown>>{return postJson('/compliance/sarif',{findings})}
// أُضيف "sarif" ليتطابق مع صيغ الباك اند الفعلية (راجع رسالة الخطأ في
// backend/app/api/routes/platform.py: "format must be pdf, markdown, json, csv,
// html, or sarif") — كان هذا النوع يفتقدها رغم أن نص واجهة صفحة Reports كان
// يعد المستخدم بها فعلاً ("Executive · Technical · JSON · SARIF · HTML") بينما
// لم يكن هناك زر واحد لأي منهما.
export type ReportFormat = "pdf" | "json" | "csv" | "html" | "sarif";
export type ReportAudience = "technical" | "managerial" | "non_technical";
export async function downloadScanReport(scanId: string, format: ReportFormat, language = "ar", audience: ReportAudience = "technical"): Promise<{format:string;content?:unknown;content_base64?:string}> {
  return getJson(`/platform/scans/${encodeURIComponent(scanId)}/report?format=${format}&language=${encodeURIComponent(language)}&audience=${audience}`);
}


export interface AssessmentProfiles { profiles: Record<string, Record<string, unknown>>; safe_modes: string[] }
export function getAssessmentProfiles(): Promise<AssessmentProfiles> { return getJson('/assessment/profiles'); }
export function replayAssessmentRequest(body:{url:string;method?:string;headers?:Record<string,string>;body?:string;timeout_seconds?:number;allow_mutation?:boolean}):Promise<Record<string,unknown>> { return postJson('/assessment/replay',body); }
// *** إضافة ***: `version` بات جزءًا من الاستجابة (راجع assessment_lifecycle.py)
// حتى يقدر الـ local-first layer يحسب baseVersion الصحيح للتعديل القادم.
export function getFindingLifecycle(scanId:string):Promise<{scan_id:string;items:Array<{finding_id:string;status:string;note:string;updated_at:string;version:number}>}> { return getJson(`/assessment/scans/${encodeURIComponent(scanId)}/lifecycle`); }
// *** إضافة (اختيارية ومتوافقة للخلف) ***: baseVersion وidempotencyKey
// معاملان اختياريان جديدان. أي استدعاء قديم بـ 3-4 معاملات (مثل
// FindingDrawer.tsx الحالي) يستمر بالعمل بلا أي تغيير — لو لم يُمرَّرا لا
// يُضافان لطلب الشبكة إطلاقًا، والسيرفر يتصرف بالضبط كما كان (بدون فحص نسخة).
export function updateFindingLifecycle(scanId:string,findingId:string,status:string,note='',baseVersion?:number,idempotencyKey?:string):Promise<Record<string,unknown>> {
  const params=new URLSearchParams({status,note});
  if (baseVersion!==undefined) params.set('base_version',String(baseVersion));
  if (idempotencyKey) params.set('idempotency_key',idempotencyKey);
  return fetch(`${API_V1}/assessment/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/lifecycle?${params.toString()}`,{method:'PATCH',headers:{'Content-Type':'application/json',...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`}:{})}}).then(async r=>{
    const d=await r.json().catch(()=>({}));
    if(!r.ok){
      // *** ملاحظة ***: FastAPI يغلّف أي HTTPException(status, detail) بشكل
      // {"detail": <detail>}. لـ409 نمرّر detail ككائن (current_status/
      // current_note/current_version/current_updated_at) بدل نص، فنفكّه هون
      // ونمرّره كـ body لـApiError حتى sync.ts يقرأه مباشرة (body.current_status
      // وليس body.detail.current_status). لأي خطأ آخر (نص عادي بـdetail) السلوك
      // يبقى تمامًا كما كان.
      const detail=(d as {detail?:unknown}).detail;
      const isStructured = detail !== null && typeof detail === 'object';
      throw new ApiError(r.status, httpStatusMessage(r.status), isStructured ? (detail as Record<string,unknown>) : undefined);
    }
    return d;
  })
}
export function getAttackSurface(scanId:string):Promise<Record<string,unknown>> { return getJson(`/assessment/scans/${encodeURIComponent(scanId)}/surface`); }

export interface AttackGraphNode { id:string; type:string; label:string; value:string; details:Record<string,unknown>; severity:string|null; degree:number }
export interface AttackGraphEdge { id:string; source:string; target:string; relation:string; evidence:string }
export interface AttackSurfaceGraph { scan_id:string; target:string; generated_from:string; nodes:AttackGraphNode[]; edges:AttackGraphEdge[]; counts:Record<string,number> }
export function getAttackSurfaceGraph(scanId:string):Promise<AttackSurfaceGraph>{return getJson(`/assessment/scans/${encodeURIComponent(scanId)}/intelligence-graph`)}
export function exportAttackSurfaceGraph(scanId:string,format:"json"|"csv"|"dot"):Promise<Response>{
  return fetch(`${API_V1}/assessment/scans/${encodeURIComponent(scanId)}/intelligence-graph/export?format=${format}`,{headers:{...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`} : {}),...(getApiKey()?{"X-API-Key":getApiKey()}: {})}})
}
