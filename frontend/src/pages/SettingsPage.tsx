import { ApiError } from "../api/client";
import { useEffect, useState, type FormEvent } from "react";
import { safeUserError, safeErrorMessage } from "../utils/security";
import {
  KeyRound,
  Languages,
  Loader2,
  LogOut,
  Mail,
  RefreshCw,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  UserCircle,
} from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import {
  challengeMfa,
  enrollTotp,
  getAuthMe,
  listMfaFactors,
  signOut as supabaseSignOut,
  unenrollMfa,
  updatePassword,
  verifyMfa,
  type AAL,
  type AppRole,
  type MfaEnrollment,
  type SupabaseMfaFactor,
} from "../auth/supabase";
import dash from "../components/UnifiedDashboard.module.css";
import auth from "../auth/AuthGate.module.css";
import { PageHeader } from "../components/PageHeader";
import styles from "./SettingsPage.module.css";

interface AccountInfo {
  email: string;
  role: AppRole;
  tenant_id: string;
  tenant_name: string;
  aal: AAL;
  auth_provider: string;
}

function friendlyMfaError(error: unknown, language: "ar" | "en"): string {
  // Decide from GoTrue's structured error_code/status (safeUserError drops the raw message).
  const { code, status } = (error ?? {}) as { code?: string; status?: number };
  if (code === "mfa_verification_failed" || code === "mfa_challenge_expired") {
    return language === "ar" ? "رمز المصادقة غير صحيح أو انتهت صلاحيته. حاول مرة أخرى." : "The authentication code is invalid or expired. Try again.";
  }
  if (code === "mfa_totp_verify_not_enabled") {
    return language === "ar" ? "تحقق TOTP غير مفعّل في إعدادات المصادقة." : "TOTP verification is disabled in the authentication settings.";
  }
  if (code === "over_request_rate_limit" || status === 429) {
    return language === "ar" ? "محاولات كثيرة. انتظر دقيقة ثم حاول مجدداً." : "Too many attempts. Wait a minute, then try again.";
  }
  return safeUserError(error, language === "ar" ? "تعذر إتمام العملية" : "Could not complete the operation");
}

export function SettingsPage() {
  const { language, toggleLanguage } = useLanguage();
  const ar = language === "ar";

  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [accountError, setAccountError] = useState<string | null>(null);

  const [signingOut, setSigningOut] = useState(false);

  // --- MFA state (owner/admin only) ---
  const [mfaLoading, setMfaLoading] = useState(true);
  const [verifiedFactor, setVerifiedFactor] = useState<SupabaseMfaFactor | null>(null);
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [otp, setOtp] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [mfaBusy, setMfaBusy] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [mfaInfo, setMfaInfo] = useState<string | null>(null);

  // --- Password state ---
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwSuccess, setPwSuccess] = useState<string | null>(null);

  const privileged = account?.role === "admin" || account?.role === "owner";

  useEffect(() => {
    let cancelled = false;
    getAuthMe()
      .then((me) => {
        if (cancelled) return;
        setAccount({ email: me.email, role: me.role, tenant_id: me.tenant_id, tenant_name: me.tenant_name, aal: me.aal, auth_provider: me.auth_provider });
        if (me.role !== "admin" && me.role !== "owner") setMfaLoading(false);
      })
      .catch((err) => {
        if (!cancelled) {
          setAccountError(err instanceof ApiError ? safeErrorMessage(err.status) : ar ? "تعذر تحميل بيانات الحساب" : "Could not load account data");
          setMfaLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!privileged) return;
    let cancelled = false;
    setMfaLoading(true);
    listMfaFactors()
      .then((factors) => {
        if (cancelled) return;
        const verified = factors.totp.find((f) => f.status === "verified") ?? null;
        setVerifiedFactor(verified);
      })
      .catch((err) => {
        if (!cancelled) setMfaError(friendlyMfaError(err, language));
      })
      .finally(() => {
        if (!cancelled) setMfaLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [privileged]);

  async function refreshFactors() {
    const factors = await listMfaFactors();
    const verified = factors.totp.find((f) => f.status === "verified") ?? null;
    setVerifiedFactor(verified);
    return verified;
  }

  async function startEnrollment() {
    setMfaBusy(true);
    setMfaError(null);
    setMfaInfo(null);
    try {
      const next = await enrollTotp();
      setEnrollment(next);
      setOtp("");
      setShowSecret(false);
    } catch (err) {
      setMfaError(friendlyMfaError(err, language));
    } finally {
      setMfaBusy(false);
    }
  }

  async function verifyEnrollment() {
    if (!enrollment) return;
    const code = otp.replace(/\D/g, "");
    if (code.length !== 6) {
      setMfaError(ar ? "أدخل رمز TOTP المكوّن من 6 أرقام." : "Enter the 6-digit TOTP code.");
      return;
    }
    setMfaBusy(true);
    setMfaError(null);
    try {
      const challenge = await challengeMfa(enrollment.id);
      await verifyMfa(enrollment.id, challenge.id, code);
      setEnrollment(null);
      setOtp("");
      await refreshFactors();
      setMfaInfo(ar ? "تم تفعيل المصادقة الثنائية بنجاح." : "Two-factor authentication is now enabled.");
    } catch (err) {
      setMfaError(friendlyMfaError(err, language));
    } finally {
      setMfaBusy(false);
    }
  }

  async function resetFactor() {
    if (!verifiedFactor) return;
    const confirmed = window.confirm(
      ar
        ? "سيتم إلغاء ربط تطبيق المصادقة الحالي فوراً، وسيُطلب منك إعداد جهاز جديد. متابعة؟"
        : "This immediately removes your current authenticator, and you'll need to set up a new one. Continue?"
    );
    if (!confirmed) return;
    setMfaBusy(true);
    setMfaError(null);
    setMfaInfo(null);
    try {
      await unenrollMfa(verifiedFactor.id);
      setVerifiedFactor(null);
      await startEnrollment();
    } catch (err) {
      setMfaError(friendlyMfaError(err, language));
    } finally {
      setMfaBusy(false);
    }
  }

  function cancelEnrollment() {
    setEnrollment(null);
    setOtp("");
    setMfaError(null);
  }

  async function submitPasswordChange(e: FormEvent) {
    e.preventDefault();
    setPwError(null);
    setPwSuccess(null);
    if (newPassword.length < 12) {
      setPwError(ar ? "كلمة المرور يجب أن تكون 12 حرفاً على الأقل." : "Password must be at least 12 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwError(ar ? "كلمتا المرور غير متطابقتين." : "Passwords do not match.");
      return;
    }
    setPwBusy(true);
    try {
      await updatePassword(newPassword);
      setNewPassword("");
      setConfirmPassword("");
      setPwSuccess(ar ? "تم تحديث كلمة المرور بنجاح." : "Password updated successfully.");
    } catch (err) {
      setPwError(err instanceof ApiError ? safeErrorMessage(err.status) : ar ? "تعذر تحديث كلمة المرور" : "Could not update password");
    } finally {
      setPwBusy(false);
    }
  }

  async function handleSignOut() {
    setSigningOut(true);
    try {
      await supabaseSignOut();
    } finally {
      // Full reload so AuthGate re-initializes cleanly against the cleared session.
      window.location.assign("/");
    }
  }

  const roleLabel: Record<AppRole, { ar: string; en: string }> = {
    owner: { ar: "مالك", en: "Owner" },
    admin: { ar: "مدير", en: "Admin" },
    analyst: { ar: "محلل", en: "Analyst" },
    viewer: { ar: "مشاهد", en: "Viewer" },
  };

  return (
    <section className="animateIn">
      <PageHeader icon={SettingsIcon} eyebrow="SETTINGS" title={ar ? "الإعدادات" : "Settings"} />

      {/* Account */}
      <div className={dash.card}>
        <div className={dash.cardHeader}>
          <UserCircle size={15} />
          <span>{ar ? "الحساب" : "Account"}</span>
        </div>

        {!account && !accountError && (
          <p className={styles.mutedNote}>
            <Loader2 size={12} className="spin" /> {ar ? "جارٍ تحميل بيانات الحساب…" : "Loading account data…"}
          </p>
        )}
        {accountError && <div className={auth.error}>{accountError}</div>}

        {account && (
          <div className={styles.grid}>
            <div className={styles.row}>
              <div className={styles.rowLabel}>
                <b><Mail size={12} style={{ verticalAlign: "-2px", marginInlineEnd: 5 }} />{ar ? "البريد الإلكتروني" : "Email"}</b>
                <span className="ltr">{account.email}</span>
              </div>
            </div>
            <div className={styles.row}>
              <div className={styles.rowLabel}>
                <b>{ar ? "الدور" : "Role"}</b>
                <span className={`${styles.roleBadge} ${privileged ? styles.privileged : ""}`}>
                  <Shield size={11} /> {ar ? roleLabel[account.role].ar : roleLabel[account.role].en}
                </span>
              </div>
            </div>
            <div className={styles.row}>
              <div className={styles.rowLabel}>
                <b>{ar ? "المؤسسة" : "Organization"}</b>
                <span>{account.tenant_name}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Preferences */}
      <div className={dash.card}>
        <div className={dash.cardHeader}>
          <Languages size={15} />
          <span>{ar ? "التفضيلات" : "Preferences"}</span>
        </div>
        <div className={styles.row} style={{ borderBottom: 0 }}>
          <div className={styles.rowLabel}>
            <b>{ar ? "لغة الواجهة" : "Interface language"}</b>
            <span>{ar ? "العربية / English" : "English / العربية"}</span>
          </div>
          <button className={styles.button} onClick={toggleLanguage}>
            <Languages size={14} /> <span className="ltr">{ar ? "Switch to English" : "التبديل للعربية"}</span>
          </button>
        </div>
      </div>

      {/* Security: password */}
      <div className={dash.card}>
        <div className={dash.cardHeader}>
          <KeyRound size={15} />
          <span>{ar ? "كلمة المرور" : "Password"}</span>
        </div>
        <form className={styles.form} onSubmit={submitPasswordChange}>
          <label>
            {ar ? "كلمة المرور الجديدة" : "New password"}
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              minLength={12}
              autoComplete="new-password"
              required
            />
          </label>
          <label>
            {ar ? "تأكيد كلمة المرور" : "Confirm password"}
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              minLength={12}
              autoComplete="new-password"
              required
            />
          </label>
          {pwError && <div className={auth.error}>{pwError}</div>}
          {pwSuccess && <div className={auth.info}>{pwSuccess}</div>}
          <div>
            <button className={styles.primaryButton} disabled={pwBusy} type="submit">
              {pwBusy ? <Loader2 size={14} className="spin" /> : <KeyRound size={14} />}
              {pwBusy ? (ar ? "جارٍ التحديث…" : "Updating…") : ar ? "تحديث كلمة المرور" : "Update password"}
            </button>
          </div>
        </form>
      </div>

      {/* Security: MFA — owner/admin only */}
      {privileged && (
        <div className={dash.card}>
          <div className={dash.cardHeader}>
            <ShieldCheck size={15} />
            <span>{ar ? "المصادقة الثنائية (MFA)" : "Multi-factor authentication (MFA)"}</span>
          </div>
          <p className={styles.mutedNote}>
            {ar
              ? "إلزامية لحسابات المدير والمالك. تُطبَّق من طرف الخادم عند كل تسجيل دخول، بغض النظر عمّا يحدث هنا."
              : "Mandatory for admin and owner accounts. Enforced server-side on every login, regardless of what happens here."}
          </p>

          {mfaLoading && (
            <p className={styles.mutedNote}>
              <Loader2 size={12} className="spin" /> {ar ? "جارٍ التحقق من حالة MFA…" : "Checking MFA status…"}
            </p>
          )}

          {!mfaLoading && !enrollment && verifiedFactor && (
            <>
              <div className={styles.factorRow}>
                <span>
                  <ShieldCheck size={14} style={{ verticalAlign: "-2px", marginInlineEnd: 6 }} />
                  {ar ? "مفعّلة" : "Enabled"} — {verifiedFactor.friendly_name ?? "TOTP"}
                </span>
              </div>
              {mfaError && <div className={auth.error} style={{ marginTop: 10 }}>{mfaError}</div>}
              {mfaInfo && <div className={auth.info} style={{ marginTop: 10 }}>{mfaInfo}</div>}
              <div className={styles.footer}>
                <button className={styles.dangerButton} disabled={mfaBusy} onClick={() => void resetFactor()}>
                  <RefreshCw size={13} /> {ar ? "إعادة ضبط جهاز المصادقة" : "Reset authenticator device"}
                </button>
              </div>
            </>
          )}

          {!mfaLoading && !enrollment && !verifiedFactor && (
            <>
              <div className={styles.factorRow} style={{ borderColor: "var(--sev-medium)", background: "var(--sev-medium-dim)", color: "var(--sev-medium)" }}>
                <span>
                  <ShieldAlert size={14} style={{ verticalAlign: "-2px", marginInlineEnd: 6 }} />
                  {ar ? "لا يوجد جهاز مصادقة مفعّل بعد" : "No authenticator enrolled yet"}
                </span>
              </div>
              {mfaError && <div className={auth.error} style={{ marginTop: 10 }}>{mfaError}</div>}
              <div className={styles.footer}>
                <button className={styles.primaryButton} disabled={mfaBusy} onClick={() => void startEnrollment()}>
                  <Smartphone size={14} /> {mfaBusy ? (ar ? "جارٍ الإنشاء…" : "Creating…") : ar ? "إعداد تطبيق المصادقة" : "Set up authenticator app"}
                </button>
              </div>
            </>
          )}

          {enrollment && (
            <div className={auth.mfaSetup}>
              <div className={auth.qrWrap}>
                <img src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(enrollment.totp.qr_code)}`} alt="MIRSAD TOTP QR" />
              </div>
              <p className={auth.mfaHint}>
                {ar ? "امسح رمز QR، ثم اكتب الرمز ذي 6 أرقام الظاهر في تطبيق المصادقة." : "Scan the QR code, then enter the 6-digit code from your authenticator app."}
              </p>
              {showSecret ? (
                <code className={auth.secret}>{enrollment.totp.secret}</code>
              ) : (
                <button className={auth.switch} onClick={() => setShowSecret(true)}>
                  {ar ? "إظهار المفتاح اليدوي بدل QR" : "Show manual key instead of QR"}
                </button>
              )}
              <label className={auth.codeLabel}>
                {ar ? "رمز TOTP" : "TOTP code"}
                <input
                  className={auth.codeInput}
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
              {mfaError && <div className={auth.error}>{mfaError}</div>}
              <div style={{ display: "flex", gap: 10 }}>
                <button className={auth.formButton} disabled={mfaBusy} onClick={() => void verifyEnrollment()}>
                  <ShieldCheck size={16} /> {mfaBusy ? (ar ? "جارٍ التحقق…" : "Verifying…") : ar ? "تفعيل MFA" : "Enable MFA"}
                </button>
                <button className={styles.button} disabled={mfaBusy} onClick={cancelEnrollment} type="button">
                  {ar ? "إلغاء" : "Cancel"}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Sign out */}
      <div className={dash.card}>
        <div className={dash.cardHeader}>
          <LogOut size={15} />
          <span>{ar ? "تسجيل الخروج" : "Sign out"}</span>
        </div>
        <p className={styles.mutedNote}>
          {ar ? "سيتم إنهاء جلستك الحالية على هذا الجهاز فوراً." : "This immediately ends your current session on this device."}
        </p>
        <div className={styles.footer} style={{ justifyContent: "flex-start", marginTop: 10 }}>
          <button className={styles.dangerButton} disabled={signingOut} onClick={() => void handleSignOut()}>
            {signingOut ? <Loader2 size={14} className="spin" /> : <LogOut size={14} />}
            {signingOut ? (ar ? "جارٍ تسجيل الخروج…" : "Signing out…") : ar ? "تسجيل الخروج" : "Sign out"}
          </button>
        </div>
      </div>
    </section>
  );
}
