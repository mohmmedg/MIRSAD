import { useState } from "react";
import { KeyRound, Play, Loader2 } from "lucide-react";
import { runFullScanAsync, ApiError } from "../api/client";
import type { UnifiedScanResult } from "../types/api";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";
import { INPUT_LIMITS, safeUserError, safeErrorMessage, validateApiSpecUrl, validateBoundedInput, validateTarget, firstFailureMessage } from "../utils/security";

interface Props { onResult: (result: UnifiedScanResult) => void; }

export function APISecurityControl({ onResult }: Props) {
  const { language } = useLanguage();
  const ar = language === "ar";
  const [target, setTarget] = useState("");
  const [specUrl, setSpecUrl] = useState("");
  const [auth, setAuth] = useState("");
  const [cookie, setCookie] = useState("");
  const [introspection, setIntrospection] = useState(true);
  const [writeMethods] = useState(false);
  const [safeMode, setSafeMode] = useState("safe");
  const [destructiveConfirmation, setDestructiveConfirmation] = useState(false);
  const [state, setState] = useState<DotState>("idle");
  const [error, setError] = useState<string | null>(null);

  // يمر عبر /platform/scan/async (api فقط) بدل النسخة المتزامنة، لنفس سبب
  // باقي الفحوصات الفردية: تفعيل مسار normalizer/correlator/risk_engine مع
  // polling دوري بدل انتظار fetch() واحد بلا مهلة من جهة المتصفح.
  async function handleRun() {
    const checkedTarget = validateTarget(target, { maxLength: INPUT_LIMITS.apiTarget, requireHttpUrl: true });
    const checkedSpec = validateApiSpecUrl(specUrl);
    const checkedAuth = validateBoundedInput(auth, INPUT_LIMITS.authorization, "Authorization");
    const checkedCookie = validateBoundedInput(cookie, INPUT_LIMITS.cookie, "Cookie");
    if (!checkedTarget.ok || !checkedSpec.ok || !checkedAuth.ok || !checkedCookie.ok) {
      setState("failed");
      setError(firstFailureMessage(checkedTarget, checkedSpec, checkedAuth, checkedCookie));
      return;
    }
    setState("running"); setError(null);
    try {
      const result = await runFullScanAsync({
        target: checkedTarget.value, network: false, web: false, api: true,
        api_spec_url: checkedSpec.value || undefined,
        auth_header: checkedAuth.value || undefined,
        cookie: checkedCookie.value || undefined,
        graphql_introspection: introspection,
        probe_write_methods: writeMethods, safe_mode: safeMode, destructive_confirmation: safeMode === "destructive" && destructiveConfirmation,
      });
      const api = result.api_scan;
      setState(api?.status === "completed" ? "completed" : "failed");
      if (api?.status === "failed" && api.error_message) setError(safeUserError(api.error_message, ar ? "فشل فحص API." : "API scan failed."));
      onResult(result);
    } catch (err) {
      setState("failed"); setError(err instanceof ApiError ? safeErrorMessage(err.status) : safeUserError(err, ar ? "تعذر تشغيل فحص API." : "Unable to start API scan."));
    }
  }

  return <div className={styles.card}>
    <div className={styles.sectionHeader}>
      <span className={styles.sectionIcon}><KeyRound size={14}/></span>
      <span className={styles.sectionLabel}>{ar ? "API Security" : "API Security"}</span>
    </div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "هدف API" : "API target"}</label><input className={styles.input} value={target} onChange={e=>setTarget(e.target.value)} placeholder="http://127.0.0.1:3000" maxLength={INPUT_LIMITS.apiTarget} disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "OpenAPI/Swagger URL (اختياري)" : "OpenAPI/Swagger URL (optional)"}</label><input className={styles.input} value={specUrl} onChange={e=>setSpecUrl(e.target.value)} placeholder="/openapi.json" maxLength={INPUT_LIMITS.apiSpec} disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "Authorization (اختياري)" : "Authorization (optional)"}</label><input className={styles.input} type="password" value={auth} onChange={e=>setAuth(e.target.value)} placeholder="Bearer …" maxLength={INPUT_LIMITS.authorization} disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "Cookie (اختياري)" : "Cookie (optional)"}</label><input className={styles.input} type="password" value={cookie} onChange={e=>setCookie(e.target.value)} placeholder="session=…" maxLength={INPUT_LIMITS.cookie} disabled={state==="running"}/></div>
    <label className={styles.radioOption}><input type="checkbox" checked={introspection} onChange={e=>setIntrospection(e.target.checked)} disabled={state==="running"}/><span>{ar ? "GraphQL introspection" : "GraphQL introspection"}</span></label>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "وضع السلامة" : "Safety mode"}</label><select className={styles.select} value={safeMode} onChange={e=>{setSafeMode(e.target.value); if(e.target.value!=="destructive")setDestructiveConfirmation(false)}} disabled={state==="running"}><option value="safe">Safe — read-only</option><option value="caution">Caution — schema-backed writes</option><option value="destructive">Destructive — bounded writes/deletes</option></select></div>
    {safeMode === "destructive" && <label className={styles.radioOption}><input type="checkbox" checked={destructiveConfirmation} onChange={e=>setDestructiveConfirmation(e.target.checked)} disabled={state==="running"}/><span>{ar ? "أؤكد التفويض الصريح للاختبارات التغييرية" : "I explicitly authorize state-changing tests"}</span></label>}
    <div style={{fontSize:11,opacity:.72,marginTop:6}}>{ar ? "يمكن أيضًا تشغيل API Security تلقائيًا من Web Scanner؛ الـ endpoints المكتشفة تنتقل للمحرك مباشرة." : "Web Scanner can hand discovered API endpoints to this engine automatically."}</div>
    <button className={styles.button} onClick={handleRun} disabled={state==="running"||!target.trim()}>{state==="running"?<><Loader2 size={14} className="spin"/>{ar?"جاري فحص API...":"Scanning API..."}</>:<><Play size={14}/>{ar?"شغّل API Security":"Run API Security"}</>}</button>
    <div className={styles.statusRow}><StatusDot state={state}/><span>{state==="idle"?(ar?"لم يبدأ بعد":"Not started"):state==="running"?(ar?"الفحص جارٍ":"Running"):state==="completed"?(ar?"اكتمل الفحص":"Completed"):(ar?"فشل الفحص":"Failed")}</span></div>
    {error&&<div className={styles.errorText}>{error}</div>}
  </div>;
}
