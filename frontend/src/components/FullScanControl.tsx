import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layers, Play, Loader2 } from "lucide-react";
import { startFullScanAsync, pauseJob, resumeJob, cancelJob, ApiError } from "../api/client";
import { StatusDot, type DotState } from "./StatusDot";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";
import styles from "./panel.module.css";
import { INPUT_LIMITS, safeUserError, safeErrorMessage, validateBoundedInput, validateIntegerRange, validateTarget, firstFailureMessage } from "../utils/security";
import { ACTIVE_SCAN_KEY, LAST_SCAN_KEY, writeScanKey } from "../utils/scanTracking";

export function FullScanControl() {
  const navigate = useNavigate();
  const { strings } = useLanguage(); const s = strings.fullScan;
  const { clearCurrentScan } = useScan();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("standard");
  const [networkEnabled, setNetworkEnabled] = useState(true);
  const [webEnabled, setWebEnabled] = useState(true);
  const [apiEnabled, setApiEnabled] = useState(true);
  const [safeMode, setSafeMode] = useState("safe");
  const [destructiveConfirmation, setDestructiveConfirmation] = useState(false);
  const [maxRequests, setMaxRequests] = useState(5000);
  const [rps, setRps] = useState(5);
  const [pages, setPages] = useState(80);
  const [depth, setDepth] = useState(4);
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [oobDomain, setOobDomain] = useState("");
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(true);
  const [subdomainDns, setSubdomainDns] = useState(true);
  const [subdomainNetwork, setSubdomainNetwork] = useState(true);
  const [subdomainWeb, setSubdomainWeb] = useState(true);
  const [subdomainApi, setSubdomainApi] = useState(true);
  const [includeHardening, setIncludeHardening] = useState(false);
  const [state, setState] = useState<DotState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<string>("idle");
  const [progress, setProgress] = useState(0);

  function handleProfileChange(value: string) {
    setProfile(value);
    const defaults: Record<string, {requests:number;rps:number;pages:number;depth:number}> = {
      passive:{requests:250,rps:2,pages:1,depth:0}, quick:{requests:750,rps:3,pages:25,depth:2},
      standard:{requests:5000,rps:5,pages:80,depth:4}, deep:{requests:15000,rps:8,pages:250,depth:6},
      maximum:{requests:30000,rps:10,pages:10000,depth:32},
    };
    if (defaults[value]) {
      setMaxRequests(defaults[value].requests); setRps(defaults[value].rps);
      setPages(defaults[value].pages); setDepth(defaults[value].depth);
    }
  }

  async function handleRun() {
    const checkedTarget = validateTarget(target, { maxLength: INPUT_LIMITS.webTarget });
    const checkedLoginUrl = loginUrl.trim() ? validateTarget(loginUrl, { maxLength: INPUT_LIMITS.loginUrl, requireHttpUrl: true }) : { ok: true as const, value: "" };
    const checkedUsername = validateBoundedInput(loginUsername, INPUT_LIMITS.username, "Username");
    const checkedPassword = validateBoundedInput(loginPassword, INPUT_LIMITS.password, "Password");
    const checkedOob = validateBoundedInput(oobDomain, INPUT_LIMITS.oobDomain, "OOB domain");
    if (!checkedTarget.ok || !checkedLoginUrl.ok || !checkedUsername.ok || !checkedPassword.ok || !checkedOob.ok) {
      setState("failed");
      setError(firstFailureMessage(checkedTarget, checkedLoginUrl, checkedUsername, checkedPassword, checkedOob));
      return;
    }
    const checkedRequests = validateIntegerRange(maxRequests, 1, INPUT_LIMITS.maxRequests, "Max requests");
    const checkedRps = validateIntegerRange(rps, 1, INPUT_LIMITS.requestsPerSecond, "Requests per second");
    const checkedPages = validateIntegerRange(pages, 1, INPUT_LIMITS.maxPages, "Pages");
    const checkedDepth = validateIntegerRange(depth, 0, INPUT_LIMITS.maxDepth, "Depth");
    if (!checkedRequests.ok || !checkedRps.ok || !checkedPages.ok || !checkedDepth.ok) {
      setState("failed"); setError(firstFailureMessage(checkedRequests, checkedRps, checkedPages, checkedDepth)); return;
    }
    setState("running"); setError(null);
    try {
      const authFields = checkedLoginUrl.value && checkedUsername.value && checkedPassword.value
        ? { login_url: checkedLoginUrl.value, login_username: checkedUsername.value, login_password: checkedPassword.value } : {};
      const oobFields = oobDomain.trim() ? { oob_callback_domain: checkedOob.value } : {};
      const created = await startFullScanAsync({
        target: checkedTarget.value, network:networkEnabled, web:webEnabled, api:apiEnabled, scan_profile:profile === "custom" ? "custom" : profile, safe_mode:safeMode,
        subdomain_discovery:subdomainDiscovery, subdomain_dns_verification:subdomainDns,
        subdomain_network_scan:subdomainNetwork, subdomain_web_scan:subdomainWeb, subdomain_api_security:subdomainApi,
        scan_discovered_subdomains:subdomainDiscovery && (subdomainDns || subdomainNetwork || subdomainWeb || subdomainApi),
        include_hardening_findings:includeHardening,
        max_requests:maxRequests, requests_per_second:rps, max_concurrency:4,
        network_profile: profile === "quick" ? "quick" : profile === "deep" ? "deep" : profile === "maximum" ? "maximum" : "balanced",
        web_profile: profile === "quick" ? "balanced" : profile === "maximum" ? "maximum" : "deep", max_pages:pages, max_depth:depth,
        graphql_introspection:true, probe_write_methods:safeMode !== "safe", destructive_confirmation: safeMode === "destructive" && destructiveConfirmation,
        // Full assessment = every available capability runs by default, since
        // there's no separate toggle for this in the UI. `run_gemini` is a no-op
        // (reported back as "not_configured") if the backend has no GEMINI_API_KEY set.
        run_gemini:true,
        ...authFields, ...oobFields,
      });
      // Starting a new scan is an explicit lifecycle boundary: the previous
      // completed result remains in backend scan history, while the dashboard
      // gets a clean current-scan workspace for the new job.
      await clearCurrentScan();
      setJobId(created.job_id); setJobStatus(created.status);
      writeScanKey(ACTIVE_SCAN_KEY, created.job_id); writeScanKey(LAST_SCAN_KEY, created.job_id);
      // The dedicated execution screen owns live progress now.
      navigate(`/scan-progress/${encodeURIComponent(created.job_id)}`);
    } catch (err) {
      setState("failed"); setError(err instanceof ApiError ? safeErrorMessage(err.status) : safeUserError(err, "تعذر تشغيل الفحص."));
    }
  }

  async function control(action:"pause"|"resume"|"cancel") {
    if (!jobId) return;
    try {
      const job = action === "pause" ? await pauseJob(jobId) : action === "resume" ? await resumeJob(jobId) : await cancelJob(jobId);
      setProgress(job.progress); setJobStatus(job.status);
      if (job.status === "cancelled") setState("failed");
    } catch (err) { setError(err instanceof ApiError ? safeErrorMessage(err.status) : safeUserError(err, "تعذر تنفيذ العملية.")); }
  }

  return <div className={styles.card}>
    <div className={styles.sectionHeader}><span className={styles.sectionIcon}><Layers size={14} /></span><span className={styles.sectionLabel}>{s.sectionLabel}</span></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.targetLabel}</label><input className={styles.input} value={target} onChange={e => setTarget(e.target.value)} maxLength={INPUT_LIMITS.webTarget} placeholder={s.placeholder} disabled={state === "running"} /></div>
    <div className={styles.field}>
      <label className={styles.fieldLabel}>{s.profileLabel}</label>
      <select className={styles.select} value={profile} onChange={e => handleProfileChange(e.target.value)} disabled={state === "running"}>
        <option value="passive">Passive Recon</option>
        <option value="quick">Quick</option>
        <option value="standard">Standard</option>
        <option value="deep">Deep</option>
        <option value="maximum">Maximum</option>
        <option value="custom">Custom — اختر الفحوصات يدويًا</option>
      </select>
    </div>
    {profile === "custom" && <div className={styles.field}>
      <label className={styles.fieldLabel}>نطاق التقييم والفحوصات</label>
      <div style={{display:"grid",gap:8,padding:10,border:"1px solid var(--line)",borderRadius:10,background:"var(--bg-panel-raised)"}}>
        <strong style={{fontSize:12}}>الفحوصات الأساسية</strong>
        <label><input type="checkbox" checked={networkEnabled} onChange={e => setNetworkEnabled(e.target.checked)} disabled={state === "running"}/> Network scan</label>
        <label><input type="checkbox" checked={webEnabled} onChange={e => setWebEnabled(e.target.checked)} disabled={state === "running"}/> Web scan</label>
        <label><input type="checkbox" checked={apiEnabled} onChange={e => setApiEnabled(e.target.checked)} disabled={state === "running"}/> API security</label>
        <strong style={{fontSize:12,marginTop:4}}>Subdomain policy</strong>
        <label><input type="checkbox" checked={subdomainDiscovery} onChange={e => setSubdomainDiscovery(e.target.checked)} disabled={state === "running"}/> اكتشاف Subdomains</label>
        <label style={{opacity:subdomainDiscovery?1:.55}}><input type="checkbox" checked={subdomainDns} onChange={e => setSubdomainDns(e.target.checked)} disabled={state === "running" || !subdomainDiscovery}/> Subdomain DNS verification</label>
        <label style={{opacity:subdomainDiscovery?1:.55}}><input type="checkbox" checked={subdomainNetwork} onChange={e => setSubdomainNetwork(e.target.checked)} disabled={state === "running" || !subdomainDiscovery}/> Subdomain network scan</label>
        <label style={{opacity:subdomainDiscovery?1:.55}}><input type="checkbox" checked={subdomainWeb} onChange={e => setSubdomainWeb(e.target.checked)} disabled={state === "running" || !subdomainDiscovery}/> Subdomain web scan</label>
        <label style={{opacity:subdomainDiscovery?1:.55}}><input type="checkbox" checked={subdomainApi} onChange={e => setSubdomainApi(e.target.checked)} disabled={state === "running" || !subdomainDiscovery}/> Subdomain API security</label>
        <label><input type="checkbox" checked={includeHardening} onChange={e => setIncludeHardening(e.target.checked)} disabled={state === "running"}/> أظهر Hardening findings منخفضة القيمة في النتائج</label>
      </div>
      <div className={styles.hint}>يمكنك اكتشاف النطاقات الفرعية فقط دون فحصها، أو تشغيل كل فرع بشكل مستقل. النتائج المكررة منخفضة القيمة مثل بعض Security Headers تُستبعد افتراضيًا من Findings وتبقى ضمن telemetry.</div>
    </div>}
    <div className={styles.field}><label className={styles.fieldLabel}>Safety mode</label><select className={styles.select} value={safeMode} onChange={e => { setSafeMode(e.target.value); if (e.target.value !== "destructive") setDestructiveConfirmation(false); }} disabled={state === "running"}><option value="safe">Safe — read-only</option><option value="caution">Caution — schema-backed mutations only</option><option value="destructive">Destructive — bounded write/delete tests</option></select></div>
    {safeMode === "destructive" && <div className={styles.field}><label><input type="checkbox" checked={destructiveConfirmation} onChange={e => setDestructiveConfirmation(e.target.checked)} disabled={state === "running"}/> أؤكد أن هذا الفحص مصرح به ويمكنه تنفيذ طلبات DELETE واختبارات اعتماد محدودة على الهدف.</label><div className={styles.hint}>لن يسمح الخادم بوضع destructive بدون هذا التأكيد.</div></div>}
    <div className={styles.field}><label className={styles.fieldLabel}>Request budget</label><input className={styles.input} type="number" min={100} max={50000} value={maxRequests} onChange={e => setMaxRequests(Number(e.target.value))} disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>Requests / second</label><input className={styles.input} type="number" min={1} max={20} value={rps} onChange={e => setRps(Number(e.target.value))} disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.pagesLabel}</label><input className={styles.input} type="number" min={1} max={500} value={pages} onChange={e => setPages(Number(e.target.value))} disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.depthLabel}</label><input className={styles.input} type="number" min={0} max={8} value={depth} onChange={e => setDepth(Number(e.target.value))} disabled={state === "running"} /></div>
    <div className={styles.sectionHeader}><span className={styles.sectionLabel}>{s.authSectionLabel}</span></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.loginUrlLabel}</label><input className={styles.input} value={loginUrl} onChange={e => setLoginUrl(e.target.value)} maxLength={INPUT_LIMITS.loginUrl} placeholder="https://target.example/login" disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.loginUsernameLabel}</label><input className={styles.input} value={loginUsername} onChange={e => setLoginUsername(e.target.value)} maxLength={INPUT_LIMITS.username} disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.loginPasswordLabel}</label><input className={styles.input} type="password" value={loginPassword} onChange={e => setLoginPassword(e.target.value)} maxLength={INPUT_LIMITS.password} disabled={state === "running"} /></div>
    <div className={styles.field}><label className={styles.fieldLabel}>{s.oobDomainLabel}</label><input className={styles.input} value={oobDomain} onChange={e => setOobDomain(e.target.value)} maxLength={INPUT_LIMITS.oobDomain} placeholder="your-id.oast.pro" disabled={state === "running"} /></div>
    <div className={styles.hint}>{s.authHint}</div>
    <div className={styles.hint}>{s.hint}</div>
    <button className={styles.button} onClick={handleRun} disabled={state === "running" || !target.trim() || (safeMode === "destructive" && !destructiveConfirmation)}>
      {state === "running" ? <><Loader2 size={14} className="spin" /> {s.running}</> : <><Play size={14} /> {s.runButton}</>}
    </button>
    <div className={styles.statusRow}><StatusDot state={state} /><span>{state === "idle" && s.idle}{state === "running" && `${s.runningStatus} · ${progress}% · ${jobStatus}`}{state === "completed" && s.completed}{state === "failed" && s.failed}</span></div>
    {state === "running" && jobId && <div style={{display:"flex",gap:6,marginTop:8}}><button className={styles.button} onClick={() => control(jobStatus === "paused" ? "resume" : "pause")}>{jobStatus === "paused" ? "Resume" : "Pause"}</button><button className={styles.button} onClick={() => control("cancel")}>Cancel</button></div>}
    {error && <div className={styles.errorText}>{error}</div>}
  </div>;
}
