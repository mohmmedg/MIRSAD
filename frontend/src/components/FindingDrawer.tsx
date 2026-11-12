import { createPortal } from "react-dom";
import { useEffect, useState } from "react";
import { X, ExternalLink, ShieldAlert, Crosshair, Activity, Wrench, CheckCircle2, Target, Bug, Database, Sparkles, Copy } from "lucide-react";
import type { UnifiedScanResult } from "../types/api";
import { replayAssessmentRequest, updateFindingLifecycle, suggestRemediation, type RemediationSuggestion } from "../api/client";
import { useLanguage } from "../i18n/LanguageContext";
import { isLocalFirstEnabled } from "../offline/registerServiceWorker";
import { enqueueFindingLifecycleUpdate } from "../offline/outbox";
import { getTenantId } from "../auth/supabase";
import styles from "./UnifiedDashboard.module.css";

// *** إضافة (تكامل Local-First) ***: نفس السلوك بالضبط لو الميزة مطفأة —
// استدعاء مباشر لـupdateFindingLifecycle كما كان قبل هذا التعديل. لو مفعّلة
// (وtenant_id متوفر فعلاً — راجع getTenantId بـauth/supabase.ts)، الكتابة
// تمر بـenqueueFindingLifecycleUpdate: تحديث فوري بالواجهة عبر IndexedDB ثم
// إرسال بالخلفية مع Rollback حقيقي عند رفض السيرفر.
async function updateLifecycle(scanId: string, findingId: string, status: string): Promise<void> {
  const tenantId = getTenantId();
  if (isLocalFirstEnabled() && tenantId) {
    await enqueueFindingLifecycleUpdate({ scanId, findingId, status, note: "", tenantId });
    return;
  }
  await updateFindingLifecycle(scanId, findingId, status);
}

type Finding = UnifiedScanResult["findings"][number];

function externalUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  try { const u = new URL(value); return /^https?:$/.test(u.protocol) ? u.toString() : null; } catch { return null; }
}

function AiRemediationSuggestion({ finding, ar }: { finding: Finding; ar: boolean }) {
  const [suggestion, setSuggestion] = useState<RemediationSuggestion | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState(false);

  const request = async () => {
    setLoading(true);
    setError(false);
    try {
      const result = await suggestRemediation(
        {
          title: finding.title,
          description: finding.description,
          severity: finding.severity,
          affected_asset: finding.affected_asset,
          tags: finding.tags,
        },
        ar ? "ar" : "en",
      );
      setSuggestion(result);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    if (!suggestion) return;
    try {
      await navigator.clipboard.writeText(suggestion.text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard access denied - the text is still visible to copy manually */
    }
  };

  return (
    <div className={styles.drawerSection}>
      <label>
        <Sparkles size={12} /> {ar ? "اقتراح إصلاح بالذكاء الاصطناعي" : "AI-suggested fix"}
      </label>
      {!suggestion && !loading && (
        <button type="button" onClick={request} className={styles.chip} style={{ cursor: "pointer" }}>
          {ar ? "اقترح إصلاحاً" : "Suggest a fix"}
        </button>
      )}
      {loading && <p>{ar ? "جارٍ التحضير..." : "Preparing..."}</p>}
      {error && <p>{ar ? "تعذّر الحصول على اقتراح الآن." : "Couldn't get a suggestion right now."}</p>}
      {suggestion && (
        <>
          <p style={{ whiteSpace: "pre-wrap" }}>{suggestion.text}</p>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <button type="button" onClick={copy} className={styles.chip} style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4 }}>
              <Copy size={11} /> {copied ? (ar ? "تم النسخ" : "Copied") : ar ? "نسخ الإصلاح المقترح" : "Copy suggested fix"}
            </button>
            <span className={styles.chip}>
              {suggestion.source === "ai" ? (ar ? "من الذكاء الاصطناعي" : "AI-generated") : ar ? "قالب افتراضي" : "Template fallback"}
            </span>
          </div>
        </>
      )}
    </div>
  );
}

export function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const { language } = useLanguage();
  const ar = language === "ar";
  const targetUrl = externalUrl(finding.affected_asset);
  const evidenceText = finding.evidence?.map(e => e.evidence).join("\n") || "";
  const [lifecycle, setLifecycle] = useState(finding.verification_status === "VERIFIED" ? "VERIFIED" : "DISCOVERED");
  const [replay, setReplay] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => { document.body.style.overflow = previousOverflow; window.removeEventListener("keydown", onKey); };
  }, [onClose]);

  const explanation = finding.exploitability || (ar
    ? "قابلية الاستغلال لا تُفترض من وجود مؤشر فقط؛ يجب ربط الدليل بالتعرض والإصدار/الإعداد ونتيجة التحقق."
    : "Exploitability is not assumed from an indicator alone; evidence must be tied to exposure, version/configuration and validation.");

  const why = finding.description || (ar
    ? "سجّل MIRSAD هذه النتيجة لأن أحد محركات الاكتشاف وجد مؤشراً أمنياً قابلاً للتفسير."
    : "MIRSAD recorded this result because a discovery engine observed a security-relevant indicator.");

  const impact = finding.impact || (ar
    ? "الأثر يعتمد على ما إذا كان المؤشر قابلاً للوصول والاستغلال فعلياً وعلى حساسية الأصل المتأثر."
    : "Impact depends on whether the indicator is actually reachable/exploitable and on the sensitivity of the affected asset.");

  return createPortal((
    <div className={styles.drawerBackdrop} onClick={onClose}>
      <aside className={styles.drawer} dir={ar ? "rtl" : "ltr"} onClick={e => e.stopPropagation()} aria-label={ar ? "تفاصيل الاكتشاف" : "Finding details"}>
        <button className={styles.closeButton} onClick={onClose} aria-label="Close"><X size={18} /></button>

        <div className={styles.kicker}><ShieldAlert size={13} /> {finding.severity} · {finding.source_module}</div>
        <h3>{finding.title}</h3>
        <div className={styles.drawerAsset}>
          {targetUrl ? <a href={targetUrl} target="_blank" rel="noopener noreferrer" className="ltr">{finding.affected_asset}<ExternalLink size={12} /></a> : <span className="ltr">{finding.affected_asset ?? "—"}</span>}
        </div>

        <div style={{display:"flex",gap:8,flexWrap:"wrap",margin:"10px 0"}}>
          {targetUrl && <button className={styles.chip} onClick={async()=>{setBusy(true);try{setReplay(await replayAssessmentRequest({url:targetUrl,method:"GET"}))}finally{setBusy(false)}}}>{busy ? "Replaying…" : "Replay GET"}</button>}
          <select className={styles.chip} value={lifecycle} onChange={async e=>{const v=e.target.value;setLifecycle(v);try{await updateLifecycle(finding.scan_id ?? "", finding.finding_id, v)}catch{}}}><option>DISCOVERED</option><option>TRIAGED</option><option>VERIFIED</option><option>REPORTED</option><option>FIXED</option><option>RETESTED</option><option>CLOSED</option></select>
        </div>
        {replay && <div className={styles.drawerSection}><label>Replay result</label><pre className="ltr">{JSON.stringify(replay,null,2)}</pre></div>}
        <div className={styles.drawerStats}>
          <span>Risk <b>{finding.risk?.score ?? 0}</b></span>
          <span>Confidence <b>{Math.round((finding.confidence ?? 0) * 100)}%</b></span>
          <span>Verification <b>{finding.verification_status ?? "UNVERIFIED"}</b></span>
        </div>

        <div className={styles.drawerSection}><label><Activity size={12} /> {ar ? "لماذا ظهر هذا الاكتشاف؟" : "Why this finding exists"}</label><p>{why}</p></div>
        <div className={styles.drawerSection}><label><Crosshair size={12} /> {ar ? "كيف اكتشفه MIRSAD؟" : "How MIRSAD detected it"}</label><p>{finding.discovery_method || (finding.source_module === "network" ? "Nmap network/service discovery" : "Rule-based web/API observation")}</p>{finding.discovery_command && <pre className="ltr">{finding.discovery_command}</pre>}</div>
        {finding.rule_id && <div className={styles.drawerSection}><label>Rule / Category</label><p className="ltr">{finding.rule_id} · {finding.category ?? "security"}</p></div>}
        {finding.parameter && <div className={styles.drawerSection}><label><Database size={12} /> {ar ? "المعامل المختبر" : "Tested parameter"}</label><p className="ltr">{finding.parameter}</p></div>}

        <div className={styles.drawerSection}><label><Target size={12} /> {ar ? "قابلية الاستغلال" : "Exploitability"}</label><p>{explanation}</p></div>
        <div className={styles.drawerSection}><label><Bug size={12} /> {ar ? "خطة الاختبار" : "Assessment context"}</label><p>{ar ? "يُربط الاكتشاف بنقطة النهاية والمعامل ومصدر الاكتشاف قبل رفع الثقة. المؤشر وحده لا يعني أن الثغرة مؤكدة." : "The finding is tied to its endpoint, parameter and discovery source before confidence is increased. An indicator alone does not mean the vulnerability is confirmed."}</p></div>
        <div className={styles.drawerSection}><label>{ar ? "الأثر الأمني" : "Security impact"}</label><p>{impact}</p></div>

        <div className={styles.drawerSection}><label><CheckCircle2 size={12} /> {ar ? "حالة التحقق" : "Verification state"}</label><p>{finding.verification_status ?? "UNVERIFIED"} — {finding.status ?? "OPEN"}. {ar ? "النتيجة لا تصبح مؤكدة إلا عندما يدعمها دليل كافٍ ومرحلة تحقق مناسبة." : "The result should be treated as confirmed only when sufficient evidence and an appropriate validation stage support it."}</p></div>

        <div className={styles.drawerSection}><label>{ar ? "الأدلة الفنية" : "Technical evidence"}</label>
          <div className={styles.evidence}>{finding.evidence?.length ? finding.evidence.map((e, i) => <div key={`${e.source}-${e.asset}-${i}`}><b>{e.source}</b><div className="ltr">{e.asset}</div><pre>{e.evidence}</pre></div>) : <p>—</p>}</div>
        </div>
        {evidenceText && <div className={styles.drawerSection}><label>{ar ? "قراءة الدليل" : "Evidence interpretation"}</label><p>{ar ? "الدليل أعلاه هو المادة التي بُني عليها الاكتشاف. قارنه بالطلب/الاستجابة الفعلية والإعدادات قبل تنفيذ أي إجراء يدوي." : "The evidence above is the material behind the finding. Compare it with the actual request/response and configuration before treating the issue as exploitable."}</p></div>}

        <div className={styles.drawerSection}><label><Wrench size={12} /> {ar ? "المعالجة" : "Remediation"}</label><p>{finding.remediation || "—"}</p></div>

        <AiRemediationSuggestion finding={finding} ar={ar} />

        {(finding.cwe || finding.mitre_attack?.length || finding.cve_matches?.length) ? <div className={styles.drawerSection}><label>{ar ? "المراجع والتصنيفات" : "References & classifications"}</label>
          {finding.cwe && externalUrl(finding.cwe.url) && <p><b>CWE:</b> <a href={externalUrl(finding.cwe.url)!} target="_blank" rel="noopener noreferrer" className="ltr">{finding.cwe.id}</a> — {finding.cwe.name}</p>}
          {finding.mitre_attack?.map(t => { const url = externalUrl(t.url); return url ? <p key={t.id}><b>MITRE ATT&amp;CK:</b> <a href={url} target="_blank" rel="noopener noreferrer" className="ltr">{t.id}</a> — {t.name} ({t.tactic})</p> : null; })}
          {finding.cve_matches?.map(c => <p key={c.cve_id} className="ltr"><b>{c.cve_id}</b> — CVSS {c.cvss_score ?? "N/A"}{c.severity ? ` (${c.severity})` : ""}</p>)}
        </div> : null}

        {finding.tags?.length ? <div className={styles.chipCloud}>{finding.tags.map(tag => <span key={tag} className={styles.chip}>{tag}</span>)}</div> : null}
      </aside>
    </div>
  ), document.body);
}
