import { safeUserError, httpStatusMessage } from "../utils/security";
export interface SupabaseSession {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
  user: { id: string; email?: string | null };
}

export type AppRole = "viewer" | "analyst" | "admin" | "owner";
export type AAL = "aal1" | "aal2";

export interface SupabaseMfaFactor {
  id: string;
  factor_type?: string;
  type?: string;
  friendly_name?: string | null;
  status: "verified" | "unverified" | string;
  created_at?: string;
  updated_at?: string;
}

export interface SupabaseMfaFactors {
  all: SupabaseMfaFactor[];
  totp: SupabaseMfaFactor[];
  phone: SupabaseMfaFactor[];
}

export interface MfaEnrollment {
  id: string;
  type?: string;
  factor_type?: string;
  friendly_name?: string;
  totp: {
    qr_code: string;
    secret: string;
    uri: string;
  };
}

export interface AuthMe {
  user_id: string;
  tenant_id: string;
  tenant_name: string;
  email: string;
  role: AppRole;
  aal: AAL;
  amr: string[];
  auth_provider: string;
  mfa_required: boolean;
}

const URL = (import.meta.env.VITE_SUPABASE_URL as string | undefined)?.replace(/\/$/, "");
const ANON = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const KEY = "mirsad_supabase_session";
const LEGACY_KEY = KEY;
const ROLE_KEY = "mirsad_app_role";
// *** إضافة (دعم Local-First) ***: نفس نمط ROLE_KEY بالضبط — الـ backend هو
// المصدر الموثوق لـtenant_id (من /auth/me)، ونخزّنه محليًا هون بشكل متزامن
// حتى تقدر src/offline/outbox.ts تقرأه فورًا بدل انتظار طلب شبكة إضافي في
// كل عملية كتابة متفائلة.
const TENANT_KEY = "mirsad_tenant_id";

if (!URL || !ANON) {
  // eslint-disable-next-line no-console
  console.error("VITE_SUPABASE_URL/VITE_SUPABASE_ANON_KEY غير مضبوطَين — المصادقة لن تعمل.");
}

// 2026-09-18 fix: كل fetch في مسار المصادقة كان يرمي استثناء المتصفح الخام
// عند انتهاء المهلة، و AuthGate يعرض err.message كما هو — فيظهر للمستخدم
// "signal is aborted without reason" وهي رسالة DOMException الافتراضية في
// Chrome عند استدعاء controller.abort() بدون reason. الرسالة لا تقول شيئاً
// عن السبب الحقيقي (الـ backend أو Supabase لم يردّ خلال المهلة). هذا
// المساعد يوحّد المهلة ويترجم الفشل إلى رسالة تشخيصية تذكر العنوان والمهلة.
const AUTH_TIMEOUT_MS = 15_000;

function describeNetworkFailure(error: unknown, _target: string, timeoutMs: number): Error {
  if (error instanceof DOMException && error.name === "AbortError") return new Error("انتهت مهلة الاتصال بخدمة المصادقة.");
  if (error instanceof TypeError) return new Error("تعذر الاتصال بخدمة المصادقة.");
  return new Error(safeUserError(error, `تعذر الاتصال بخدمة المصادقة بعد ${Math.round(timeoutMs / 1000)} ثانية.`));
}

function originOf(url: string): string {
  try {
    return new window.URL(url, window.location.href).origin;
  } catch {
    return url;
  }
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = AUTH_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (error) {
    throw describeNetworkFailure(error, originOf(url), timeoutMs);
  } finally {
    window.clearTimeout(timer);
  }
}

const publicHeaders = () => ({
  apikey: ANON ?? "",
  "Content-Type": "application/json",
});

const authHeaders = () => ({
  ...publicHeaders(),
  ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}),
});

function save(s: SupabaseSession | null) {
  try {
    if (s) {
      // Cross-tab session continuity is intentional for MIRSAD: a second tab
      // must stay on the same authenticated tenant/account.
      localStorage.setItem(KEY, JSON.stringify(s));
      sessionStorage.removeItem(KEY);
      sessionStorage.removeItem(ROLE_KEY);
      sessionStorage.removeItem(TENANT_KEY);
    } else {
      localStorage.removeItem(KEY);
      localStorage.removeItem(ROLE_KEY);
      localStorage.removeItem(TENANT_KEY);
      sessionStorage.removeItem(KEY);
      sessionStorage.removeItem(ROLE_KEY);
      sessionStorage.removeItem(TENANT_KEY);
    }
  } catch {
    // Ignore storage failures; the in-memory auth response still works.
  }
}

function saveRole(role: AppRole) {
  try {
    localStorage.setItem(ROLE_KEY, role);
  } catch {
    // Ignore storage failures.
  }
}

export function getSession(): SupabaseSession | null {
  try {
    const raw = localStorage.getItem(LEGACY_KEY);
    return raw ? (JSON.parse(raw) as SupabaseSession) : null;
  } catch {
    return null;
  }
}

export function getAccessToken() {
  return getSession()?.access_token ?? "";
}

async function supabaseRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!URL || !ANON) throw new Error("خدمة المصادقة غير مهيأة");

  // كان هذا الاستدعاء بلا مهلة إطلاقاً: لو تأخّر GoTrue أو انقطعت الشبكة،
  // يبقى زر "تسجيل الدخول" في حالة busy إلى ما لا نهاية بلا أي رسالة.
  const response = await fetchWithTimeout(`${URL}/auth/v1${path}`, {
    ...init,
    headers: {
      ...authHeaders(),
      ...(init.headers ?? {}),
    },
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    // Keep the user-facing text generic (never echo server messages), but carry
    // the HTTP status and GoTrue's machine-readable error_code so callers can
    // tell "wrong code" from "TOTP verify disabled" from "rate limited".
    const err = new Error(httpStatusMessage(response.status, "ar")) as Error & { status?: number; code?: string };
    err.status = response.status;
    const rawCode = (data as { error_code?: unknown; code?: unknown } | null)?.error_code;
    if (typeof rawCode === "string" && /^[a-z0-9_]{1,64}$/i.test(rawCode)) err.code = rawCode;
    throw err;
  }

  return data as T;
}

async function request(path: string, body: unknown) {
  const data = await supabaseRequest<SupabaseSession>(path, {
    method: "POST",
    headers: publicHeaders(),
    body: JSON.stringify(body),
  });

  if (data.access_token) {
    data.expires_at = Math.floor(Date.now() / 1000) + Number(data.expires_in ?? 3600);
    save(data);

    // save() swallows storage exceptions internally (private browsing,
    // blocked sessionStorage, etc.). Read the session back immediately and
    // fail loudly if it did not actually persist — otherwise the caller
    // walks away believing sign-in succeeded while resolveAuthenticatedState()
    // silently finds no session and bounces back to the login screen with
    // no visible error at all.
    if (getSession()?.access_token !== data.access_token) {
      throw new Error(
        "تعذّر حفظ جلسة الدخول في هذا المتصفح. تأكد من أن localStorage غير مُعطّل (وضع التصفح الخاص أو إعدادات الخصوصية قد تمنعه) ثم أعد المحاولة."
      );
    }
  }
  return data;
}

export function signIn(email: string, password: string) {
  return request("/token?grant_type=password", { email, password });
}

export async function signUp(email: string, password: string, tenantName: string) {
  const s = await request("/signup", { email, password, data: { tenant_name: tenantName } });
  return s.access_token ? s : null;
}

export async function refreshSession() {
  const s = getSession();
  if (!s?.refresh_token) return null;

  try {
    const next = await request("/token?grant_type=refresh_token", {
      refresh_token: s.refresh_token,
    });
    return next;
  } catch {
    // Keep the cached session on transient network/backend failures. AuthGate
    // will retry; storage is cleared only by an explicit sign-out or when the
    // server definitively rejects the session.
    return s;
  }
}

export async function signOut() {
  const s = getSession();
  // 2026-09-16: ask the backend to cancel any scan still running for this
  // tenant BEFORE invalidating the session below — a scan the person
  // started previously used to keep running against the target indefinitely
  // in the background after they signed out, with no way left to tell it
  // was still going. Best-effort and silent: signing out must never fail or
  // hang because this call did.
  try {
    if (s?.access_token) {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 5_000);
      try {
        await fetch(`${API_BASE_URL}/api/v1/jobs/cancel-active`, {
          method: "POST",
          signal: controller.signal,
          headers: { Authorization: `Bearer ${s.access_token}` },
        });
      } finally {
        window.clearTimeout(timer);
      }
    }
  } catch {
    // Cancelling the running scan is a courtesy, not a precondition for
    // signing out — never block or fail signOut() because of it.
  }
  try {
    if (URL && ANON && s?.access_token) {
      await fetch(`${URL}/auth/v1/logout`, {
        method: "POST",
        headers: { ...publicHeaders(), Authorization: `Bearer ${s.access_token}` },
      });
    }
  } finally {
    save(null);
    // *** إضافة (دعم Local-First) ***: مسح IndexedDB الخاص بطبقة
    // Local-First عند تسجيل الخروج — حتى لا تبقى بيانات فحوصات مستأجر
    // سابق داخل المتصفح على جهاز مشترك (راجع db.ts::wipeLocalFirstStorage).
    // استيراد ديناميكي حتى لا يُحمَّل Dexie إطلاقًا لو كانت الميزة معطّلة
    // أو الاستيراد فشل لأي سبب — تسجيل الخروج نفسه يجب ألا يتأثر أبدًا.
    try {
      const { wipeLocalFirstStorage } = await import("../offline/db");
      await wipeLocalFirstStorage();
    } catch {
      // فشل مسح IndexedDB لا يجب أن يمنع تسجيل الخروج أو يظهر خطأً للمستخدم.
    }
  }
}

export function shouldRefresh(s: SupabaseSession | null) {
  return Boolean(s?.expires_at && s.expires_at - Math.floor(Date.now() / 1000) < 60);
}

function decodeAccessToken(): Record<string, unknown> {
  const token = getAccessToken();
  try {
    const encoded = token.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/");
    if (!encoded) return {};
    return JSON.parse(atob(encoded + "=".repeat((4 - (encoded.length % 4)) % 4))) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function getAal(): AAL {
  return decodeAccessToken().aal === "aal2" ? "aal2" : "aal1";
}

/**
 * The application role is authoritative in MIRSAD's public.users table, not
 * in Supabase's standard JWT `role` claim (which normally remains
 * `authenticated`). AuthGate calls setRoleFromServer() after authentication.
 */
export function getRole(): AppRole {
  try {
    const cached = localStorage.getItem(ROLE_KEY);
    if (cached && ["viewer", "analyst", "admin", "owner"].includes(cached)) {
      return cached as AppRole;
    }
  } catch {
    // Fall through to a conservative default.
  }
  return "viewer";
}

export function setRoleFromServer(role: AppRole) {
  saveRole(role);
}

/**
 * *** إضافة (دعم Local-First) ***: مكافئ متزامن لـ getAccessToken()، لكن
 * لـ tenant_id بدل التوكن. يبقى فارغًا لحد أول getAuthMe() ناجحة بعد تسجيل
 * الدخول (تمامًا كـ getRole() قبل أول setRoleFromServer). أي كود يستخدمه
 * (مثال: enqueueFindingLifecycleUpdate) يجب أن يتوقع قيمة فارغة محتملة أول
 * لحظة تحميل الصفحة، ويتجنّب الكتابة المتفائلة عندها.
 */
export function getTenantId(): string {
  try {
    return localStorage.getItem(TENANT_KEY) ?? "";
  } catch {
    return "";
  }
}

function setTenantFromServer(tenantId: string) {
  try {
    if (tenantId) localStorage.setItem(TENANT_KEY, tenantId);
  } catch {
    // Ignore storage failures — نفس منطق saveRole.
  }
}

export async function getAuthMe(): Promise<AuthMe> {
  const token = getAccessToken();
  if (!token) throw new Error("Authentication required");

  // 2026-09-18: المهلة كانت 10 ثوانٍ، وهي أقصر من مهلة اتصال قاعدة البيانات
  // في الـ backend (DB_CONNECT_TIMEOUT_SECONDS = 15)، فكان العميل يقطع الطلب
  // قبل أن يتمكّن الخادم أصلاً من إرجاع خطأ مفهوم. الآن 20 ثانية: أطول من
  // أي مهلة داخلية في الخادم، فيصل الخطأ الحقيقي بدل انقطاع أعمى.
  const response = await fetchWithTimeout(
    `${API_BASE_URL}/api/v1/auth/me`,
    { headers: { Authorization: `Bearer ${token}` } },
    20_000
  );
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(httpStatusMessage(response.status, "ar"));
  }

  const me = data as AuthMe;
  setRoleFromServer(me.role);
  setTenantFromServer(me.tenant_id);
  return me;
}

export async function listMfaFactors(): Promise<SupabaseMfaFactors> {
  // GoTrue does not expose GET /auth/v1/factors — that path only accepts
  // POST (enrollment). A session's current MFA factors are returned as
  // part of the user object at GET /auth/v1/user instead.
  const data = await supabaseRequest<{ factors?: SupabaseMfaFactor[] }>("/user", { method: "GET" });
  const all = Array.isArray(data.factors) ? data.factors : [];
  return {
    all,
    totp: all.filter((item) => (item.factor_type ?? item.type) === "totp"),
    phone: all.filter((item) => (item.factor_type ?? item.type) === "phone"),
  };
}

export async function enrollTotp(friendlyName = "MIRSAD Admin Authenticator"): Promise<MfaEnrollment> {
  // Supabase keeps an unverified factor while enrollment is in progress. Remove
  // stale TOTP factors first so repeated setup attempts cannot accumulate them.
  const factors = await listMfaFactors();
  for (const factor of factors.totp.filter((item) => item.status === "unverified")) {
    await unenrollMfa(factor.id);
  }

  return supabaseRequest<MfaEnrollment>("/factors", {
    method: "POST",
    body: JSON.stringify({ factor_type: "totp", friendly_name: friendlyName }),
  });
}

export async function challengeMfa(factorId: string): Promise<{ id: string }> {
  return supabaseRequest<{ id: string }>(`/factors/${encodeURIComponent(factorId)}/challenge`, {
    method: "POST",
  });
}

export async function verifyMfa(factorId: string, challengeId: string, code: string): Promise<void> {
  // Supabase returns the elevated session from /verify. Persist that session
  // immediately instead of relying only on a refresh-token round trip; this is
  // important because the access token returned here contains the AAL2 claim.
  const data = await supabaseRequest<Partial<SupabaseSession>>(`/factors/${encodeURIComponent(factorId)}/verify`, {
    method: "POST",
    body: JSON.stringify({ challenge_id: challengeId, code }),
  });

  if (data.access_token && data.refresh_token && data.user) {
    data.expires_at =
      Math.floor(Date.now() / 1000) + Number(data.expires_in ?? 3600);
    save(data as SupabaseSession);
  }

  // Normally the verify response is already AAL2. If a response did not carry
  // the session, refresh once using the current refresh token. Never consider
  // MFA complete until the stored access token itself decodes to AAL2.
  if (getAal() !== "aal2") {
    const refreshed = await refreshSession();
    if (!refreshed || getAal() !== "aal2") {
      throw new Error("MFA verified, but the AAL2 session could not be established");
    }
  }
}

export async function unenrollMfa(factorId: string): Promise<void> {
  await supabaseRequest<Record<string, unknown>>(`/factors/${encodeURIComponent(factorId)}`, {
    method: "DELETE",
  });
}

/**
 * Self-service password change via Supabase's GoTrue `/user` endpoint. Uses
 * the caller's own bearer token, so this can only ever change the current
 * account's password — never any other user's.
 */
export async function updatePassword(newPassword: string): Promise<void> {
  await supabaseRequest<Record<string, unknown>>("/user", {
    method: "PUT",
    body: JSON.stringify({ password: newPassword }),
  });
}