import { useState } from "react";
import { KeyRound, Play, Loader2 } from "lucide-react";
import { runAPISecurityScan, ApiError } from "../api/client";
import type { APISecurityResult } from "../types/api";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./panel.module.css";

interface Props { onResult: (result: APISecurityResult) => void; }

export function APISecurityControl({ onResult }: Props) {
  const { language } = useLanguage();
  const ar = language === "ar";
  const [target, setTarget] = useState("");
  const [specUrl, setSpecUrl] = useState("");
  const [auth, setAuth] = useState("");
  const [cookie, setCookie] = useState("");
  const [introspection, setIntrospection] = useState(true);
  const [writeMethods, setWriteMethods] = useState(false);
  const [state, setState] = useState<DotState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    if (!target.trim()) return;
    setState("running"); setError(null);
    try {
      const result = await runAPISecurityScan({
        target: target.trim(),
        spec_url: specUrl.trim() || undefined,
        auth_header: auth.trim() || undefined,
        cookie: cookie.trim() || undefined,
        enable_graphql_introspection: introspection,
        probe_write_methods: writeMethods,
      });
      setState(result.status === "completed" ? "completed" : "failed");
      if (result.status === "failed" && result.error_message) setError(result.error_message);
      onResult(result);
    } catch (err) {
      setState("failed"); setError(err instanceof ApiError ? err.message : "Unexpected error");
    }
  }

  return <div className={styles.card}>
    <div className={styles.sectionHeader}>
      <span className={styles.sectionIcon}><KeyRound size={14}/></span>
      <span className={styles.sectionLabel}>{ar ? "API Security" : "API Security"}</span>
    </div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "هدف API" : "API target"}</label><input className={styles.input} value={target} onChange={e=>setTarget(e.target.value)} placeholder="http://127.0.0.1:3000" disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "OpenAPI/Swagger URL (اختياري)" : "OpenAPI/Swagger URL (optional)"}</label><input className={styles.input} value={specUrl} onChange={e=>setSpecUrl(e.target.value)} placeholder="/openapi.json" disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "Authorization (اختياري)" : "Authorization (optional)"}</label><input className={styles.input} type="password" value={auth} onChange={e=>setAuth(e.target.value)} placeholder="Bearer …" disabled={state==="running"}/></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{ar ? "Cookie (اختياري)" : "Cookie (optional)"}</label><input className={styles.input} type="password" value={cookie} onChange={e=>setCookie(e.target.value)} placeholder="session=…" disabled={state==="running"}/></div>
    <label className={styles.radioOption}><input type="checkbox" checked={introspection} onChange={e=>setIntrospection(e.target.checked)} disabled={state==="running"}/><span>{ar ? "GraphQL introspection" : "GraphQL introspection"}</span></label>
    <label className={styles.radioOption}><input type="checkbox" checked={writeMethods} onChange={e=>setWriteMethods(e.target.checked)} disabled={state==="running"}/><span>{ar ? "اختبار POST/PUT/PATCH/DELETE (يتطلب تفويضًا صريحًا)" : "Probe POST/PUT/PATCH/DELETE (explicit authorization required)"}</span></label>
    <div style={{fontSize:11,opacity:.72,marginTop:6}}>{ar ? "يمكن أيضًا تشغيل API Security تلقائيًا من Web Scanner؛ الـ endpoints المكتشفة تنتقل للمحرك مباشرة." : "Web Scanner can hand discovered API endpoints to this engine automatically."}</div>
    <button className={styles.button} onClick={handleRun} disabled={state==="running"||!target.trim()}>{state==="running"?<><Loader2 size={14} className="spin"/>{ar?"جاري فحص API...":"Scanning API..."}</>:<><Play size={14}/>{ar?"شغّل API Security":"Run API Security"}</>}</button>
    <div className={styles.statusRow}><StatusDot state={state}/><span>{state==="idle"?(ar?"لم يبدأ بعد":"Not started"):state==="running"?(ar?"الفحص جارٍ":"Running"):state==="completed"?(ar?"اكتمل الفحص":"Completed"):(ar?"فشل الفحص":"Failed")}</span></div>
    {error&&<div className={styles.errorText}>{error}</div>}
  </div>;
}
