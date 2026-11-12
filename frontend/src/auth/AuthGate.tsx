import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { safeUserError } from "../utils/security";
import { KeyRound, LogIn, LogOut, ShieldCheck, Smartphone, UserPlus } from "lucide-react";
import { useLocation } from "react-router-dom";
import { MirsadMark } from "../components/MirsadMark";
import {
  challengeMfa,
  enrollTotp,
  getAal,
  getAuthMe,
  getSession,
  listMfaFactors,
  refreshSession,
  setRoleFromServer,
  shouldRefresh,
  signIn,
  signUp,
  signOut as supabaseSignOut,
  verifyMfa,
  type AuthMe,
  type SupabaseMfaFactor,
  type MfaEnrollment,
} from "./supabase";
import styles from "./AuthGate.module.css";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? (import.meta.env.PROD ? "" : "http://127.0.0.1:8000");

type SetupStatus = { self_service_signup_enabled: boolean };
type AuthState = "loading" | "login" | "ready" | "mfa-enroll" | "mfa-challenge";

function useSetupStatus(): SetupStatus | "loading" {
  const [status, setStatus] = useState<SetupStatus | "loading">("loading");
  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 8_000);
    fetch(`${API_BASE_URL}/api/v1/auth/setup-status`, { signal: controller.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("bad status"))))
      .then((d: SetupStatus) => {
        if (!cancelled) setStatus(d);
      })
      .catch(() => {
        if (!cancelled) setStatus({ self_service_signup_enabled: false });
      });
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, []);
  return status;
}

function friendlyMfaError(error: unknown): string {
  // safeUserError() deliberately discards the raw message, so matching regexes
  // against it made EVERY failure look like "TOTP verification is disabled".
  // Decide from the structured GoTrue error_code / HTTP status instead.
  const { code, status } = (error ?? {}) as { code?: string; status?: number };
  if (code === "mfa_verification_failed" || code === "mfa_challenge_expired") {
    return "The authentication code is invalid or expired. Try again with the current code.";
  }
  if (code === "mfa_totp_verify_not_enabled") {
    return "TOTP verification is disabled in your authentication provider's settings. Enable it, then try again.";
  }
  if (code === "over_request_rate_limit" || code === "over_email_send_rate_limit" || status === 429) {
    return "Too many attempts. Wait a minute, then try again.";
  }
  if (status === 401) return "Your sign-in session expired. Sign in again.";
  if (error instanceof Error && /AAL2/.test(error.message)) return error.message;
  return safeUserError(error, "Could not complete multi-factor verification.");
}

// The platform-admin area is now a set of nested routes (/admin, /admin/users, ...). The
// privilege re-check and its 15 s poll must cover every one of them, not just "/admin".
const isPlatformAdminPath = (pathname: string) => pathname === "/admin" || pathname.startsWith("/admin/");

export function AuthGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>("loading");
  const [register, setRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [me, setMe] = useState<AuthMe | null>(null);
  const [factor, setFactor] = useState<SupabaseMfaFactor | null>(null);
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [otp, setOtp] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const location = useLocation();
  const inFlightResolveRef = useRef<Promise<void> | null>(null);
  const setupStatus = useSetupStatus();

  async function resolveAuthenticatedState(): Promise<void> {
    // 2026-09-18 fix: كان الحارس يعيد فوراً (return صامت) لو كان هناك استدعاء
    // جارٍ. المشكلة: performAuth() تستدعيها مباشرة بعد نجاح signIn، وفي تلك
    // اللحظة قد يكون مؤقّت التحديث (tick كل 30 ثانية) أو boot() ما زال جارياً
    // — فتُرجَع فوراً بلا عمل، وتبقى الشاشة على نموذج الدخول بعد تسجيل دخول
    // ناجح وبلا أي خطأ ظاهر. الآن نشارك الوعد الجاري بدل تجاهله.
    if (inFlightResolveRef.current) {
      await inFlightResolveRef.current;
      return;
    }
    const run = doResolveAuthenticatedState();
    inFlightResolveRef.current = run;
    try {
      await run;
    } finally {
      inFlightResolveRef.current = null;
    }
  }

  async function doResolveAuthenticatedState(): Promise<void> {
    {
      const session = getSession();
    if (!session?.access_token) {
      setState("login");
      return;
    }

    const account = await getAuthMe();
    setMe(account);
    setRoleFromServer(account.role);

    const privileged = account.role === "admin" || account.role === "owner";

    // The backend is authoritative for the current RBAC/MFA decision.
    // Do not unlock the application for an administrator merely because a
    // locally decoded JWT happens to look like AAL2; /auth/me tells us whether
    // this exact session still requires MFA.
    const currentAal = account.aal === "aal2" ? "aal2" : getAal();
    if (!privileged || !account.mfa_required || currentAal === "aal2") {
      setState("ready");
      return;
    }

    const factors = await listMfaFactors();
    const verifiedTotp = factors.totp.find((item) => item.status === "verified");

    if (verifiedTotp) {
      setFactor(verifiedTotp);
      setEnrollment(null);
      setOtp("");
      setState("mfa-challenge");
      return;
    }

    setFactor(null);
    setEnrollment(null);
    setOtp("");
    setState("mfa-enroll");
    }
  }
  useEffect(() => {
    let cancelled = false;
    const boot = async () => {
      // A missing in-memory/storage session during the first paint is not the
      // same thing as an unauthenticated user. Give the browser/Supabase
      // session a chance to hydrate before showing the sign-in screen.
      let session = getSession();
      if (session && shouldRefresh(session)) {
        try { session = await refreshSession(); } catch { /* retry below */ }
      }
      if (!session?.access_token) {
        if (!cancelled) setState("login");
        return;
      }
      for (let attempt = 0; attempt < 3 && !cancelled; attempt += 1) {
        try {
          await resolveAuthenticatedState();
          return;
        } catch (err) {
          if (attempt === 2) {
            if (!cancelled) {
              setError(safeUserError(err, "تعذر التحقق من الجلسة"));
              setState("login");
            }
          } else {
            await new Promise((resolve) => window.setTimeout(resolve, 500 * (attempt + 1)));
          }
        }
      }
    };
    void boot();
    return () => { cancelled = true; };
  }, []);

  // Keep authentication synchronized across browser tabs. The session is
  // intentionally stored in localStorage so a new MIRSAD tab inherits the
  // same account; logout/login changes are propagated through the browser
  // storage event without copying tokens into URLs or query parameters.
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== "mirsad_supabase_session") return;
      if (!event.newValue) {
        setMe(null);
        setFactor(null);
        setEnrollment(null);
        setOtp("");
        setState("login");
        setError(null);
        return;
      }
      void resolveAuthenticatedState().catch((err) => {
        setError(safeUserError(err, "تعذر مزامنة جلسة الدخول بين التبويبات"));
      });
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Re-check the server-authoritative auth state whenever the admin route is
  // entered. This closes the gap where an already-mounted UI can remain on
  // /admin while the backend has downgraded the current session to AAL1.
  useEffect(() => {
    if (state === "login" || state === "loading" || !isPlatformAdminPath(location.pathname)) return;
    void resolveAuthenticatedState().catch((err) => {
      setError(safeUserError(err, "تعذر التحقق من صلاحية الإدارة"));
    });
  }, [location.pathname, state]);

  // While the admin panel is open, periodically re-check AAL/RBAC without
  // waiting for JWT expiry. The backend remains the final enforcement point.
  useEffect(() => {
    if (state !== "ready" || !isPlatformAdminPath(location.pathname)) return;
    const timer = window.setInterval(() => {
      void resolveAuthenticatedState().catch((err) => {
        setError(safeUserError(err, "تعذر التحقق من صلاحية الإدارة"));
      });
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [location.pathname, state]);

  // Refresh the Supabase session before expiry. For privileged users we also
  // re-evaluate AAL after refresh so an expired AAL2 claim cannot silently keep
  // the admin UI unlocked.
  useEffect(() => {
    if (state === "login" || state === "loading") return;
    let cancelled = false;
    const tick = async () => {
      if (!shouldRefresh(getSession())) return;
      const refreshed = await refreshSession();
      // The effect that started this tick() may have been cleaned up while we
      // were awaiting the network (e.g. the user signed out). Acting on the
      // result at this point would resurrect a session or call the backend
      // with a token that no longer matches the UI's "login" state.
      if (cancelled) return;
      if (!refreshed) {
        // A transient refresh failure must not destroy a still-valid UI session.
        // The next tick will retry; only an explicit sign-out clears storage.
        return;
      }
      try {
        await resolveAuthenticatedState();
      } catch (err) {
        if (cancelled) return;
        setError(safeUserError(err, "تعذر تحديث جلسة المصادقة"));
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [state]);

  // Core sign-in/sign-up logic, deliberately independent of any DOM event.
  // Both the mouse click (via the form's onSubmit) and the Enter key (via
  // each input's onKeyDown, below) call this directly, so neither path
  // depends on the browser's implicit form-submission behavior — which can
  // silently fail to fire when the submit button is momentarily disabled
  // (e.g. while setup-status is still loading).
  async function performAuth() {
    if (busy || loading) return;
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const next = register
        ? await signUp(email.trim(), password, tenantName.trim())
        : await signIn(email.trim(), password);
      if (!next) {
        setInfo("Account created. Check your email, then sign in.");
      } else if (!next.access_token) {
        // Defensive: a 200 response without a token must never be treated as
        // a successful sign-in — otherwise resolveAuthenticatedState() finds
        // no session and silently reverts to the login screen with no error.
        throw new Error("The server didn't return a valid session. Please try again.");
      } else {
        await resolveAuthenticatedState();
      }
    } catch (err) {
      setError(safeUserError(err, "Authentication failed."));
      setState("login");
    } finally {
      setBusy(false);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void performAuth();
  }

  function submitOnEnter(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key !== "Enter") return;
    e.preventDefault();
    void performAuth();
  }

  async function startEnrollment() {
    setBusy(true);
    setError(null);
    try {
      const next = await enrollTotp();
      setEnrollment(next);
      setOtp("");
      setShowSecret(false);
    } catch (err) {
      setError(friendlyMfaError(err));
    } finally {
      setBusy(false);
    }
  }

  async function verifyEnrollment() {
    if (!enrollment) return;
    const code = otp.replace(/\D/g, "");
    if (code.length !== 6) {
      setError("Enter the 6-digit TOTP code.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const challenge = await challengeMfa(enrollment.id);
      await verifyMfa(enrollment.id, challenge.id, code);
      setEnrollment(null);
      setFactor(null);
      await resolveAuthenticatedState();
    } catch (err) {
      setError(friendlyMfaError(err));
    } finally {
      setBusy(false);
    }
  }

  async function verifyLoginMfa() {
    if (!factor) return;
    const code = otp.replace(/\D/g, "");
    if (code.length !== 6) {
      setError("Enter the 6-digit TOTP code.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const challenge = await challengeMfa(factor.id);
      await verifyMfa(factor.id, challenge.id, code);
      // Re-read the server-authoritative AAL/RBAC state after verification.
      // This guarantees the application opens only after Supabase has issued
      // an AAL2 session and the backend confirms MFA is no longer required.
      await resolveAuthenticatedState();
    } catch (err) {
      setError(friendlyMfaError(err));
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    await supabaseSignOut();
    setMe(null);
    setEnrollment(null);
    setFactor(null);
    setOtp("");
    setState("login");
    setError(null);
  }

  if (state === "ready") {
    return (
      <>
        {children}
        <button className={styles.signout} onClick={() => void signOut()}>
          <LogOut size={14} /> Sign out
        </button>
      </>
    );
  }

  const loading = setupStatus === "loading";
  const canRegister = !loading && setupStatus.self_service_signup_enabled;
  const effectiveRegister = register && canRegister;

  if (state === "mfa-enroll" || state === "mfa-challenge") {
    const isEnroll = state === "mfa-enroll";
    return (
      <div className={styles.screen} dir="ltr">
        <div className={styles.card}>
          <div className={styles.brand}>
            <span><MirsadMark size={68} /></span>
            <div><strong>MIRSAD</strong><small>SECURITY PLATFORM</small></div>
          </div>

          <div className={styles.kicker}>MULTI-FACTOR AUTHENTICATION</div>
          <h1>{isEnroll ? "Enable two-factor authentication" : "Two-factor verification"}</h1>
          <p>
            {isEnroll
              ? "Administrator accounts require TOTP. Scan the QR code with Google Authenticator, 1Password, or any TOTP app, then enter the current code."
              : `Enter the current code from your authenticator app to finish signing in as ${me?.email ?? "the admin account"}.`}
          </p>

          {isEnroll && !enrollment && (
            <button className={styles.primaryButton} disabled={busy} onClick={() => void startEnrollment()}>
              <Smartphone size={16} /> {busy ? "Creating…" : "Set up authenticator app"}
            </button>
          )}

          {isEnroll && enrollment && (
            <div className={styles.mfaSetup}>
              <div className={styles.qrWrap}>
                <img src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(enrollment.totp.qr_code)}`} alt="MIRSAD TOTP QR" />
              </div>
              <p className={styles.mfaHint}>Scan the QR code, then enter the 6-digit code shown in your authenticator app.</p>
              {showSecret ? (
                <code className={styles.secret}>{enrollment.totp.secret}</code>
              ) : (
                <button className={styles.switch} onClick={() => setShowSecret(true)}>Show manual key instead of QR</button>
              )}
              <label className={styles.codeLabel}>
                TOTP code
                <input
                  className={styles.codeInput}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  pattern="[0-9]{6}"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  onKeyDown={(e) => { if (e.key === "Enter") void verifyEnrollment(); }}
                  autoFocus
                />
              </label>
              {error && <div className={styles.error}>{error}</div>}
              <button className={styles.formButton} disabled={busy} onClick={() => void verifyEnrollment()}>
                <ShieldCheck size={16} /> {busy ? "Verifying…" : "Enable MFA and continue"}
              </button>
            </div>
          )}

          {state === "mfa-challenge" && (
            <div className={styles.mfaSetup}>
              <div className={styles.factorBadge}><KeyRound size={16} /> TOTP is enabled on this account</div>
              <label className={styles.codeLabel}>
                TOTP code
                <input
                  className={styles.codeInput}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  pattern="[0-9]{6}"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  onKeyDown={(e) => { if (e.key === "Enter") void verifyLoginMfa(); }}
                  autoFocus
                />
              </label>
              {error && <div className={styles.error}>{error}</div>}
              <button className={styles.formButton} disabled={busy} onClick={() => void verifyLoginMfa()}>
                <ShieldCheck size={16} /> {busy ? "Verifying…" : "Verify and open the admin panel"}
              </button>
            </div>
          )}

          <button className={styles.switch} onClick={() => void signOut()}>Back to sign in</button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.screen} dir="ltr">
      <div className={styles.card}>
        <div className={styles.brand}>
          <span><MirsadMark size={68} /></span>
          <div><strong>MIRSAD</strong><small>SECURITY PLATFORM</small></div>
        </div>

        <div className={styles.kicker}>{effectiveRegister ? "CREATE ACCOUNT" : "SECURE SIGN-IN"}</div>
        <h1>{effectiveRegister ? "Create your workspace" : "Sign in"}</h1>

        {state === "loading" && <p>Checking your session…</p>}

        {state !== "loading" && (
          <form onSubmit={submit} className={styles.form}>
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={submitOnEnter}
                autoComplete="email"
                required
              />
            </label>

            {effectiveRegister && (
              <label>
                Organization name
                <input
                  value={tenantName}
                  onChange={(e) => setTenantName(e.target.value)}
                  onKeyDown={submitOnEnter}
                  minLength={2}
                  required
                />
              </label>
            )}

            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={submitOnEnter}
                minLength={12}
                autoComplete={effectiveRegister ? "new-password" : "current-password"}
                required
              />
            </label>

            {error && <div className={styles.error}>{error}</div>}
            {info && <div className={styles.info}>{info}</div>}

            <button disabled={busy || loading} type="submit">
              {effectiveRegister ? <UserPlus size={16} /> : <LogIn size={16} />} {busy ? "Please wait…" : effectiveRegister ? "Create account" : "Sign in securely"}
            </button>
          </form>
        )}

        {!loading && state !== "loading" && (
          canRegister ? (
            <button className={styles.switch} onClick={() => { setRegister(!register); setError(null); setInfo(null); }}>
              {effectiveRegister ? "Already have an account? Sign in" : "Create a new workspace"}
            </button>
          ) : (
            <p className={styles.hint}>Self-service sign-up isn't available in this environment. Contact your administrator for an invite.</p>
          )
        )}
      </div>
    </div>
  );
}
