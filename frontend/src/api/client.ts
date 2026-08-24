// api/client.ts
//
// طبقة واحدة لكل نداءات الـ backend. كل الفحوصات حالياً synchronous من
// جهة الـ HTTP request (الـ backend نفسه async داخلياً) — يعني fetch()
// بيضل معلّق لحد ما الفحص يخلص. لفحص "full" هذا ممكن ياخد دقائق، فالواجهة
// لازم تُظهر حالة تحميل واضحة (ScanControlPanel يتكفّل بهذا).
//
// كل دوال التحليل تاخد `language` — يتحكم بلغة محتوى التقرير المُولَّد
// بالكامل (بما فيه رد Gemini نفسه لمحرّك AI)، مش بس واجهة الموقع.

import { getAccessToken } from "../auth/supabase";
import type {
  AnalysisReport,
  AudienceLevel,
  CompareAnalysisResponse,
  FormattedReport,
  Language,
  NetworkScanResult,
  WebScanResult,
  APISecurityResult,
} from "../types/api";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const API_V1 = `${API_BASE_URL}/api/v1`;

// مطابق لـ backend/app/core/security.py: لو الـ backend شغّال بـ API_KEY
// مضبوط (موصى به حتى بالتطوير)، لازم نرسل نفس القيمة هون بترويسة X-API-Key
// وإلا كل الطلبات ترجع 401. لو الـ backend بدون API_KEY (تطوير محلي فقط)،
// هذا المتغير يبقى فاضي ولا يُرسَل شيء — الـ backend يتجاهل غياب الترويسة.
const ENV_API_KEY = import.meta.env.VITE_API_KEY as string | undefined;
const API_KEY_STORAGE = "security_scanner_api_key";

export function getApiKey(): string {
  try {
    return sessionStorage.getItem(API_KEY_STORAGE)?.trim() || ENV_API_KEY?.trim() || "";
  } catch {
    return ENV_API_KEY?.trim() || "";
  }
}

export function setApiKey(value: string): void {
  try {
    const trimmed = value.trim();
    if (trimmed) sessionStorage.setItem(API_KEY_STORAGE, trimmed);
    else sessionStorage.removeItem(API_KEY_STORAGE);
  } catch {
    // sessionStorage قد لا يكون متاحاً في بعض البيئات؛ لا نفشل الواجهة.
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function putJson<TResponse>(path:string,body:unknown):Promise<TResponse>{
  const response=await fetch(`${API_V1}${path}`,{method:"PUT",headers:{"Content-Type":"application/json",...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`}:{})},body:JSON.stringify(body)});
  if(!response.ok){let detail=response.statusText;try{detail=(await response.json()).detail??detail}catch{}throw new ApiError(response.status,detail)}
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
    throw new ApiError(0, "Cannot reach the backend. Make sure uvicorn is running on " + API_BASE_URL);
  }

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const errorBody = await response.json();
      detail = errorBody.detail ?? detail;
    } catch {
      // تجاهل — استخدم statusText
    }
    throw new ApiError(response.status, detail);
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

export function runFullScan(body: Record<string, unknown>): Promise<import("../types/api").UnifiedScanResult> { return postJson<import("../types/api").UnifiedScanResult>("/platform/scan", body); }
export function generatePlatformReport(scan: import("../types/api").UnifiedScanResult, language="ar"): Promise<{format:string;content:unknown}> { return postJson<{format:string;content:unknown}>("/platform/report?language="+encodeURIComponent(language), scan); }
export function listAssets(): Promise<{assets:Array<Record<string,unknown>>}> { return getJson("/platform/assets"); }

async function getJson<T>(path:string):Promise<T>{let r:Response;try{r=await fetch(`${API_V1}${path}`,{headers:{...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`} : {}),...(getApiKey()?{"X-API-Key":getApiKey()}: {})}})}catch{throw new ApiError(0,"Cannot reach backend")};if(!r.ok){let d=r.statusText;try{const b=await r.json();d=b.detail??d}catch{}throw new ApiError(r.status,d)}return r.json() as Promise<T>}

export interface JobSnapshot { job_id:string; job_type:string; target:string; status:string; progress:number; current_engine:string|null; logs:string[]; created_at:string; started_at:string|null; finished_at:string|null; duration_seconds:number|null; error_message:string|null; result:unknown|null }
export function startFullScanAsync(body: Record<string,unknown>):Promise<{job_id:string;scan_id:string;status:string}>{return postJson('/platform/scan/async',body)}
export function getJob(jobId:string):Promise<JobSnapshot>{return getJson(`/jobs/${encodeURIComponent(jobId)}`)}
export function pauseJob(jobId:string):Promise<JobSnapshot>{return postJson(`/jobs/${encodeURIComponent(jobId)}/pause`,{})}
export function resumeJob(jobId:string):Promise<JobSnapshot>{return postJson(`/jobs/${encodeURIComponent(jobId)}/resume`,{})}
export function cancelJob(jobId:string):Promise<JobSnapshot>{return postJson(`/jobs/${encodeURIComponent(jobId)}/cancel`,{})}
export function listContinuousSchedules():Promise<{schedules:Array<Record<string,unknown>>}>{return getJson('/continuous/schedules')}
export function createContinuousSchedule(request:Record<string,unknown>, interval_seconds=3600):Promise<Record<string,unknown>>{return postJson('/continuous/schedules',{request,interval_seconds})}
export function deleteContinuousSchedule(id:string):Promise<{deleted:string}>{return fetch(`${API_V1}/continuous/schedules/${encodeURIComponent(id)}`,{method:'DELETE',headers:{...(getAccessToken()?{Authorization:`Bearer ${getAccessToken()}`} : {}),...(getApiKey()?{'X-API-Key':getApiKey()}: {})}}).then(async r=>{if(!r.ok)throw new ApiError(r.status,r.statusText);return r.json()})}

export interface AdminUser {
  user_id: string;
  email: string;
  role: "viewer" | "analyst" | "admin" | "owner";
  is_active: boolean;
  created_at: string;
}
export interface AdminOverview {
  tenant_id: string;
  actor: { user_id: string; tenant_id: string; role: string; email: string };
  users: { total: number; active: number; admins: number };
  supabase_admin_sync: boolean;
}
export function getAdminOverview(): Promise<AdminOverview> { return getJson("/admin/overview"); }
export function listAdminUsers(search = ""): Promise<{ users: AdminUser[]; total: number }> {
  return getJson(`/admin/users${search ? `?search=${encodeURIComponent(search)}` : ""}`);
}
export function updateAdminUser(userId: string, body: { role?: AdminUser["role"]; is_active?: boolean }): Promise<AdminUser> {
  return patchJson(`/admin/users/${encodeURIComponent(userId)}`, body);
}
export function listAdminAudit(limit = 100): Promise<{ events: Array<Record<string, unknown>> }> {
  return getJson(`/admin/audit?limit=${limit}`);
}
async function patchJson<TResponse>(path: string, body: unknown): Promise<TResponse> {
  try {
    const r = await fetch(`${API_V1}${path}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}), ...(getApiKey() ? { "X-API-Key": getApiKey() } : {}) },
      body: JSON.stringify(body),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiError(r.status, d.detail ?? r.statusText);
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
export function getAdminPolicies():Promise<AdminPolicies>{return getJson('/admin/policies')}
export function updateAdminPolicy(kind:'security'|'scan'|'ai'|'notifications',values:Record<string,unknown>):Promise<Record<string,unknown>>{return putJson(`/admin/policies/${kind}`,{values})}
export function getAdminFeatures():Promise<AdminFeatureFlags>{return getJson('/admin/features')}
export function updateAdminFeatures(flags:AdminFeatureFlags):Promise<AdminFeatureFlags>{return putJson('/admin/features',{flags})}
export function getAdminPermissions():Promise<{permissions:string[];role_matrix:Record<string,string[]>}>{return getJson('/admin/permissions')}
export function listAdminSessions():Promise<{sessions:AdminSession[]}>{return getJson('/admin/sessions')}
export function revokeAdminSession(id:string):Promise<{ok:boolean}>{return postJson(`/admin/sessions/${encodeURIComponent(id)}/revoke`,{})}
export function revokeAllAdminSessions():Promise<{revoked:number}>{return postJson('/admin/sessions/revoke-all',{})}
export function listAdminApiKeys():Promise<{keys:AdminApiKey[]}>{return getJson('/admin/api-keys')}
export function createAdminApiKey(body:{name:string;scopes?:string[];expires_in_days?:number}):Promise<{key_id:string;secret:string;name:string;scopes:string[];expires_at:string|null;warning:string}>{return postJson('/admin/api-keys',body)}
export function revokeAdminApiKey(id:string):Promise<{ok:boolean}>{return postJson(`/admin/api-keys/${encodeURIComponent(id)}/revoke`,{})}
export function getAdminHealth():Promise<{checks:Record<string,string>;environment:string;target_scope_enforced:boolean}>{return getJson('/admin/health')}
export function getAdminBackupStatus():Promise<{status:string;note:string;application_triggered_backup:boolean}>{return getJson('/admin/backup')}

export interface SecurityEvent { event_id:string; event_type:string; severity:string; actor_user_id:string|null; target:string|null; data:Record<string,unknown>; risk_score:number; detected:boolean; created_at:string }
export interface SecurityAlert { alert_id:string; event_id:string|null; title:string; severity:string; status:string; risk_score:number; data:Record<string,unknown>; created_at:string; acknowledged_at:string|null }
export interface SecurityIncident { incident_id:string; title:string; description:string; severity:string; status:string; assignee_user_id:string|null; sla_due_at:string|null; related_asset_id:string|null; related_scan_id:string|null; related_finding_id:string|null; related_user_id:string|null; evidence:Array<Record<string,unknown>>; timeline:Array<Record<string,unknown>>; ai_explanation:string|null; created_at:string; updated_at:string }
export function getSecuritySummary():Promise<{open_alerts:number;critical_alerts:number;open_incidents:number;events_24h:number}>{return getJson('/admin/security/summary')}
export function listSecurityEvents(limit=100):Promise<{events:SecurityEvent[]}>{return getJson(`/admin/security/events?limit=${limit}`)}
export function listSecurityAlerts(limit=100):Promise<{alerts:SecurityAlert[]}>{return getJson(`/admin/security/alerts?limit=${limit}`)}
export function updateSecurityAlert(id:string,status:"open"|"acknowledged"|"resolved"):Promise<{ok:boolean;status:string}>{return patchJson(`/admin/security/alerts/${encodeURIComponent(id)}`,{status})}
export function listSecurityIncidents(limit=100):Promise<{incidents:SecurityIncident[]}>{return getJson(`/admin/incidents?limit=${limit}`)}
export function createSecurityIncident(body:{title:string;description?:string;severity?:string}):Promise<{incident_id:string}>{return postJson('/admin/incidents',body)}
export function updateSecurityIncident(id:string,body:Record<string,unknown>):Promise<{ok:boolean;incident_id:string;status:string}>{return patchJson(`/admin/incidents/${encodeURIComponent(id)}`,body)}

export interface ComplianceControl { control_id:string; framework:string; title:string; description:string; tags:string[]; max_severity:string; enabled:boolean }
export interface ComplianceAssessment { assessment_id?:string; framework:string; score:number; passed:number; failed:number; controls:Array<Record<string,unknown>>; generated_at?:string }
export interface CIPolicy { critical_fail:number; high_fail:number; medium_fail:number; enabled:boolean }
export function getComplianceControls(framework?:string):Promise<{controls:ComplianceControl[]}>{return getJson(`/compliance/controls${framework?`?framework=${encodeURIComponent(framework)}`:""}`)}
export function assessCompliance(findings:Array<Record<string,unknown>>,framework?:string):Promise<ComplianceAssessment>{return postJson('/compliance/assess',{findings,framework})}
export function getCIPolicy():Promise<CIPolicy>{return getJson('/compliance/ci-policy')}
export function updateCIPolicy(policy:CIPolicy):Promise<CIPolicy>{return putJson('/compliance/ci-policy',policy)}
export function securityGateSarif(findings:Array<Record<string,unknown>>):Promise<Record<string,unknown>>{return postJson('/compliance/sarif',{findings})}
