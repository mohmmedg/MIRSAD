import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { LogIn, LogOut, UserPlus } from "lucide-react";
import { MirsadMark } from "../components/MirsadMark";
import {
  getSession,
  refreshSession,
  shouldRefresh,
  signIn,
  signUp,
  signOut as supabaseSignOut,
} from "./supabase";
import styles from "./AuthGate.module.css";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

interface SetupStatus {
  self_service_signup_enabled: boolean;
}

// Fail closed: حتى نسمع من الـ backend عكس ذلك، نفترض أن التسجيل الذاتي غير
// مسموح. خطأ شبكة هنا يجب ألا يتحول أبداً إلى "أظهر نموذج التسجيل".
//
// ملاحظة: مسار "إعداد أول مدير" عبر الواجهة أُلغي عمداً — ظهور نموذج
// التسجيل يعتمد فقط على self_service_signup_enabled (إعداد صريح بالبيئة)،
// وليس على كون قاعدة البيانات فارغة. التزويد الفعلي لأول مستخدم (owner)
// يحدث بأمان بالكامل من طرف الـ backend بعد المصادقة الناجحة عبر Supabase
// (انظر SUPABASE_AUTO_PROVISION في core/auth.py) — الواجهة لا تعرف ولا يجب
// أن تعرف شيئاً عن ذلك مسبقاً.
function useSetupStatus(): SetupStatus | "loading" {
  const [status, setStatus] = useState<SetupStatus | "loading">("loading");
  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE_URL}/api/v1/auth/setup-status`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("bad status"))))
      .then((d: SetupStatus) => {
        if (!cancelled) setStatus(d);
      })
      .catch(() => {
        if (!cancelled) setStatus({ self_service_signup_enabled: false });
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return status;
}

export function AuthGate({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState(() => Boolean(getSession()));
  const [register, setRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const setupStatus = useSetupStatus();

  // تحديث الجلسة تلقائياً قبل انتهائها بدقيقة.
  useEffect(() => {
    if (!authed) return;
    const tick = () => {
      if (shouldRefresh(getSession())) {
        void refreshSession().then((s) => {
          if (!s) setAuthed(false);
        });
      }
    };
    tick();
    const timer = window.setInterval(tick, 30_000);
    return () => window.clearInterval(timer);
  }, [authed]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const next = register
        ? await signUp(email.trim(), password, tenantName.trim())
        : await signIn(email.trim(), password);
      if (!next) setInfo("تم إنشاء الحساب. تحقق من البريد الإلكتروني ثم سجّل الدخول.");
      else setAuthed(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "تعذّر إتمام المصادقة");
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    await supabaseSignOut();
    setAuthed(false);
  }

  if (authed) {
    return (
      <>
        {children}
        <button className={styles.signout} onClick={() => void signOut()}>
          <LogOut size={14} /> تسجيل الخروج
        </button>
      </>
    );
  }

  const loading = setupStatus === "loading";
  const canRegister = !loading && setupStatus.self_service_signup_enabled;
  const effectiveRegister = register && canRegister;

  return (
    <div className={styles.screen} dir="rtl">
      <div className={styles.card}>
        <div className={styles.brand}>
          <span>
            <MirsadMark size={24} />
          </span>
          <div>
            <strong>مرصاد</strong>
            <small>MIRSAD</small>
          </div>
        </div>

        <div className={styles.kicker}>{effectiveRegister ? "إنشاء حساب" : "تسجيل دخول آمن"}</div>
        <h1>{effectiveRegister ? "إنشاء مساحة العمل" : "تسجيل الدخول"}</h1>

        <form onSubmit={submit} className={styles.form}>
          <label>
            البريد الإلكتروني
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </label>

          {effectiveRegister && (
            <label>
              اسم المؤسسة
              <input value={tenantName} onChange={(e) => setTenantName(e.target.value)} minLength={2} required />
            </label>
          )}

          <label>
            كلمة المرور
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={12}
              autoComplete={effectiveRegister ? "new-password" : "current-password"}
              required
            />
          </label>

          {error && <div className={styles.error}>{error}</div>}
          {info && <div className={styles.info}>{info}</div>}

          <button disabled={busy || loading} type="submit">
            {effectiveRegister ? <UserPlus size={16} /> : <LogIn size={16} />}{" "}
            {busy ? "جارٍ التنفيذ…" : effectiveRegister ? "إنشاء الحساب" : "دخول آمن"}
          </button>
        </form>

        {!loading &&
          (canRegister ? (
            <button
              className={styles.switch}
              onClick={() => {
                setRegister(!register);
                setError(null);
                setInfo(null);
              }}
            >
              {effectiveRegister ? "لديك حساب؟ تسجيل الدخول" : "إنشاء مساحة عمل جديدة"}
            </button>
          ) : (
            <p className={styles.hint}>لا يوجد إنشاء حساب ذاتي بهذه البيئة. تواصل مع مدير النظام للحصول على دعوة.</p>
          ))}
      </div>
    </div>
  );
}
