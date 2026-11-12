/**
 * Frontend security helpers.
 *
 * These are presentation/UX controls only. The backend remains the trust
 * boundary and MUST repeat target validation, authorization, tenant isolation,
 * SSRF/scope enforcement and input limits.
 */

export const INPUT_LIMITS = {
  webTarget: 2048,
  apiTarget: 2048,
  apiSpec: 2048,
  authorization: 8192,
  cookie: 8192,
  networkPorts: 2048,
  loginUrl: 2048,
  username: 512,
  password: 4096,
  oobDomain: 2048,
  scanQuery: 256,
  maxPages: 10000,
  maxDepth: 32,
  maxRequests: 30000,
  requestsPerSecond: 10,
} as const;

const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

/** Message of the first failed validation result (or ""), typed so callers need no union narrowing. */
export function firstFailureMessage(...results: Array<{ ok: true } | { ok: false; message: string }>): string {
  for (const r of results) if (!r.ok && "message" in r) return r.message;
  return "";
}

export function containsUnsafeControlChars(value: string): boolean {
  return CONTROL_CHARS.test(value);
}

export function safeDiagnosticText(value: unknown, fallback = "An unexpected error occurred."): string {
  if (typeof value !== "string" || !value.trim()) return fallback;
  let text = value
    .replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "[REDACTED]")
    .replace(/((?:access_token|refresh_token|api[_-]?key|authorization|cookie|password|secret))\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/(?:[A-Za-z]:\\|\\\\|\/)(?:[^\s:*?"<>|]+[\\\/])*[^\s:*?"<>|]*/g, "[PATH]")
    .replace(/\b(?:Traceback \(most recent call last\)|File \"[^"]+\", line \d+|psycopg(?:2)?|sqlite3|sqlalchemy|postgres(?:ql)?|postgresql|sqlite|OperationalError|ProgrammingError)\b[^\n]*/gi, "[REDACTED DIAGNOSTIC]")
    .replace(/\s+/g, " ")
    .trim();
  if (!text || text.includes(" at ") && /\b(?:Error|Exception)\b/i.test(text)) return fallback;
  return text.slice(0, 1000) || fallback;
}

export function safeErrorMessage(status: number, language: "ar" | "en" = "en"): string {
  return httpStatusMessage(Number.isFinite(status) ? status : 0, language);
}

export function safeUserError(_value: unknown, fallback = "The request could not be completed."): string {
  return fallback;
}

/**
 * Safe, *specific* message for a failed API request.
 * safeUserError() above always returns its fallback (by design, to avoid leaking
 * diagnostics), which made the UI show the same generic text twice, e.g.
 * "فشل الفحص: فشل الفحص". ApiError only carries a numeric HTTP status, so we can
 * safely map that status to a fixed, localized sentence without exposing any
 * server-side detail. Network failures (status 0 / non-ApiError) use the fallback.
 */
export function describeRequestError(value: unknown, language: "ar" | "en", fallback: string): string {
  const status = (value as { status?: unknown } | null)?.status;
  if (typeof status === "number" && Number.isFinite(status) && status > 0) {
    return `${httpStatusMessage(status, language)} (HTTP ${status})`;
  }
  return fallback;
}

export function httpStatusMessage(status: number, language: "ar" | "en" = "en"): string {
  if (language === "ar") {
    if (status === 400) return "الطلب غير صالح.";
    if (status === 401) return "انتهت جلسة المصادقة أو يلزم تسجيل الدخول.";
    if (status === 403) return "ليس لديك صلاحية لتنفيذ هذا الإجراء.";
    if (status === 404) return "العنصر المطلوب غير موجود.";
    if (status === 408 || status === 504) return "انتهت مهلة الطلب.";
    if (status === 409) return "تعذر إكمال العملية بسبب تعارض في الحالة الحالية.";
    if (status === 413) return "المدخلات كبيرة جدًا.";
    if (status === 422) return "تحقق من المدخلات وحاول مرة أخرى.";
    if (status === 429) return "تم تجاوز الحد المسموح للطلبات. حاول لاحقًا.";
    if (status >= 500) return "حدث خطأ داخلي في الخادم. حاول لاحقًا.";
    return "تعذر إكمال الطلب.";
  }
  if (status === 400) return "The request is invalid.";
  if (status === 401) return "Your session has expired or sign-in is required.";
  if (status === 403) return "You are not authorized to perform this action.";
  if (status === 404) return "The requested resource was not found.";
  if (status === 408 || status === 504) return "The request timed out.";
  if (status === 409) return "The operation conflicts with the current state.";
  if (status === 413) return "The submitted input is too large.";
  if (status === 422) return "Check the submitted values and try again.";
  if (status === 429) return "Too many requests. Please try again later.";
  if (status >= 500) return "The server could not complete the request. Please try again later.";
  return "The request could not be completed.";
}

export function validateTarget(
  value: string,
  options: { maxLength?: number; requireHttpUrl?: boolean } = {},
): { ok: true; value: string } | { ok: false; message: string } {
  const maxLength = options.maxLength ?? INPUT_LIMITS.webTarget;
  const valueTrimmed = value.trim();
  if (!valueTrimmed) return { ok: false, message: "A target is required." };
  if (valueTrimmed.length > maxLength) return { ok: false, message: `Target must be ${maxLength} characters or fewer.` };
  if (containsUnsafeControlChars(valueTrimmed)) return { ok: false, message: "Target contains unsupported control characters." };

  if (options.requireHttpUrl) {
    try {
      const url = new URL(valueTrimmed);
      if (!["http:", "https:"].includes(url.protocol)) return { ok: false, message: "Only HTTP(S) targets are supported." };
      if (url.username || url.password) return { ok: false, message: "Targets must not contain embedded credentials." };
      if (url.href.length > maxLength) return { ok: false, message: `Target must be ${maxLength} characters or fewer.` };
    } catch {
      return { ok: false, message: "Enter a valid HTTP(S) target." };
    }
  }
  return { ok: true, value: valueTrimmed };
}


export function validateHttpUrl(value: string, maxLength = INPUT_LIMITS.webTarget): { ok: true; value: string } | { ok: false; message: string } {
  return validateTarget(value, { maxLength, requireHttpUrl: true });
}

export function validateApiSpecUrl(value: string): { ok: true; value: string } | { ok: false; message: string } {
  const trimmed = value.trim();
  if (!trimmed) return { ok: true, value: "" };
  if (trimmed.length > INPUT_LIMITS.apiSpec || containsUnsafeControlChars(trimmed)) return { ok: false, message: "OpenAPI URL is invalid or too long." };
  if (trimmed.startsWith('/')) return { ok: true, value: trimmed };
  return validateTarget(trimmed, { maxLength: INPUT_LIMITS.apiSpec, requireHttpUrl: true });
}

export function validateIntegerRange(value: number, min: number, max: number, label = "Value"): { ok: true; value: number } | { ok: false; message: string } {
  if (!Number.isInteger(value) || value < min || value > max) return { ok: false, message: `${label} must be between ${min} and ${max}.` };
  return { ok: true, value };
}

export function validateBoundedInput(value: string, maxLength: number, label = "Input"):
  { ok: true; value: string } | { ok: false; message: string } {
  const trimmed = value.trim();
  if (trimmed.length > maxLength) return { ok: false, message: `${label} must be ${maxLength} characters or fewer.` };
  if (containsUnsafeControlChars(trimmed)) return { ok: false, message: `${label} contains unsupported control characters.` };
  return { ok: true, value: trimmed };
}
