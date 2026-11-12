import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { CheckCircle2, Circle, Clock3, ExternalLink, Pause, Play, Radar, RotateCw, Square, XCircle, Zap } from "lucide-react";
import { createPortal } from "react-dom";
import { useNavigate, useParams } from "react-router-dom";
import { getJob, getActiveJobs, pauseJob, resumeJob, cancelJob, type JobSnapshot, type JobStage } from "../api/client";
import { getAccessToken } from "../auth/supabase";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { PageHeader } from "../components/PageHeader";
import styles from "./ScanProgressPage.module.css";
import { describeRequestError, safeDiagnosticText } from "../utils/security";
import { ACTIVE_SCAN_KEY, LAST_SCAN_KEY, LIVE_JOB_STATUSES, TERMINAL_JOB_STATUSES, readScanKey, removeScanKey, writeScanKey } from "../utils/scanTracking";

function formatDuration(seconds:number|null|undefined){ if(seconds==null) return "—"; const s=Math.max(0,Math.round(seconds)); const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60; return h?`${h}h ${String(m).padStart(2,"0")}m`:m?`${m}m ${String(sec).padStart(2,"0")}s`:`${sec}s`; }
function stageIcon(status:string){ if(status==="completed") return <CheckCircle2 size={15}/>; if(status==="failed") return <XCircle size={15}/>; if(status==="running") return <RotateCw size={15} className="spin"/>; return <Circle size={12}/>; }

/**
 * Renders the scan stages as a vertical branching tree (top → bottom): every stage is a glowing
 * box and the curved connectors fan out from a parent to its children. Edge colour follows the
 * status of the two stages it joins (blue = running/completed, red = failed, amber = partial,
 * slate = skipped, dim = pending), and edges leading into a running stage flow.
 *
 * Connector geometry is measured from the real DOM boxes (ResizeObserver) and drawn in one SVG
 * overlay, so the lines stay attached to the nodes whatever the width, wrapping or text direction.
 */
const SOURCE_TOOLS = ["source_semgrep", "source_gitleaks", "source_trufflehog", "source_trivy", "httpx_probe"];
const EXTERNAL_TOOLS = ["external_nuclei", "external_zap", "external_sqlmap", "external_ghauri", "external_ffuf", "external_testssl"];
const SUB_BRANCHES = ["subdomain_dns", "subdomain_network", "subdomain_web", "subdomain_api"];
type TreeEdge = { from: string; to: string; side?: boolean };
const TREE_EDGES: TreeEdge[] = [
  { from: "target_validation", to: "target_reachability" },
  { from: "target_reachability", to: "dns_lookup" },
  ...["port_scan", "service_discovery", "web_crawl", "api_security"].map((to) => ({ from: "dns_lookup", to })),
  { from: "web_crawl", to: "source_intelligence" },
  { from: "web_crawl", to: "external_scanners" },
  ...SOURCE_TOOLS.map((to) => ({ from: "source_intelligence", to, side: true })),
  ...EXTERNAL_TOOLS.map((to) => ({ from: "external_scanners", to, side: true })),
  { from: "httpx_probe", to: "subdomain_discovery" },
  { from: "external_testssl", to: "subdomain_discovery" },
  ...SUB_BRANCHES.map((to) => ({ from: "subdomain_discovery", to })),
  ...SUB_BRANCHES.map((from) => ({ from, to: "vulnerability_analysis" })),
  { from: "vulnerability_analysis", to: "risk_correlation" },
  { from: "vulnerability_analysis", to: "ai_validation" },
  { from: "risk_correlation", to: "finalize" },
  { from: "ai_validation", to: "finalize" },
];
const EDGE_COLOR: Record<string, string> = { blue: "var(--accent-action)", green: "var(--accent-ok)", bronze: "var(--brand-mark)", red: "var(--sev-critical)", amber: "var(--sev-medium)", slate: "var(--sev-info)", dim: "var(--line-strong)" };
const edgeTone = (status: string) => status === "failed" || status === "partial" ? "red" : status === "paused" ? "amber" : status === "completed" ? "green" : status === "running" ? "blue" : status === "skipped" ? "bronze" : "dim";
type EdgePath = { key: string; d: string; x0: number; y0: number; x1: number; y1: number; c0: string; c1: string; live: boolean; dim: boolean };

function StageTree({ stages, dir }: { stages: JobStage[]; dir: "rtl" | "ltr" }) {
  const byId = new Map(stages.map((s) => [s.id, s]));
  const get = (id: string): JobStage => byId.get(id) ?? { id, label: id, status: "pending", progress: 0, started_at: null, finished_at: null, message: "" };
  const toolByStage: Record<string,string> = {
    target_validation: "MIRSAD Scope / SSRF Guard", target_reachability: "MIRSAD Reachability Probe", dns_lookup: "DNS resolver", port_scan: "Nmap", service_discovery: "Nmap",
    web_crawl: "MIRSAD Web Engine + Playwright", source_intelligence: "MIRSAD Source Intelligence", external_scanners: "MIRSAD External Orchestrator",
    api_security: "MIRSAD API Security Engine", subdomain_discovery: "Subfinder + Nmap", subdomain_dns: "DNS resolver",
    subdomain_network: "Nmap", subdomain_web: "MIRSAD Web Engine", subdomain_api: "MIRSAD API Security",
    vulnerability_analysis: "Normalizer + Verification Engine", risk_correlation: "Finding / Risk Pipeline",
    ai_validation: "Gemini / Rule-based Validator", finalize: "MIRSAD Persistence",
  };
  // Official GitHub source repositories for the open-source tools shown in the tree.
  // Static allowlist (never derived from scan data), opened in a new tab.
  const sourceByStage: Record<string,string> = {
    source_semgrep: "https://github.com/semgrep/semgrep", source_gitleaks: "https://github.com/gitleaks/gitleaks",
    source_trufflehog: "https://github.com/trufflesecurity/trufflehog", source_trivy: "https://github.com/aquasecurity/trivy",
    httpx_probe: "https://github.com/projectdiscovery/httpx", external_nuclei: "https://github.com/projectdiscovery/nuclei",
    external_zap: "https://github.com/zaproxy/zaproxy", external_sqlmap: "https://github.com/sqlmapproject/sqlmap", external_ghauri: "https://github.com/r0oth3x49/ghauri",
    external_ffuf: "https://github.com/ffuf/ffuf", external_testssl: "https://github.com/testssl/testssl.sh",
    subdomain_discovery: "https://github.com/projectdiscovery/subfinder", port_scan: "https://github.com/nmap/nmap",
    service_discovery: "https://github.com/nmap/nmap", subdomain_network: "https://github.com/nmap/nmap",
  };
  const ar = dir === "rtl";
  const [tip, setTip] = useState<{ stage: JobStage; x: number; y: number; above: boolean } | null>(null);
  useEffect(() => { if (!tip) return; const hide = () => setTip(null); window.addEventListener("scroll", hide, true); return () => window.removeEventListener("scroll", hide, true); }, [tip]);
  const statusInfo = (st: string) => {
    const m: Record<string, [string, string, string]> = {
      running: ["قيد التشغيل", "Running", "الأداة تعمل الآن."],
      completed: ["اكتملت", "Completed", "اشتغلت الأداة وأنهت عملها بنجاح."],
      partial: ["اكتملت جزئياً", "Partial", "اشتغلت الأداة لكن لم تكمل (مهلة أو نتائج جزئية)."],
      skipped: ["تم تخطيها", "Skipped", "لم تُشغَّل الأداة."],
      failed: ["فشلت", "Failed", "بدأت الأداة لكنها فشلت."],
      pending: ["بانتظار الدور", "Pending", "لم تبدأ بعد."],
    };
    const v = m[st] ?? m.pending; return { label: ar ? v[0] : v[1], text: v[2], textEn: ({running:"The tool is running now.",completed:"The tool ran and finished successfully.",partial:"The tool ran but did not fully finish (timeout or partial results).",skipped:"The tool was not run.",failed:"The tool started but failed.",pending:"Not started yet."} as Record<string,string>)[st] ?? "Not started yet." };
  };
  // The popover is portalled to <body> and positioned with viewport coordinates, so ancestors with
  // transform/filter/contain (page transitions, glass panels) cannot shift it away from the cursor target.
  const showTip = (stage: JobStage, el: HTMLElement) => {
    const r = el.getBoundingClientRect();
    const above = r.top > 190; // enough room above the node, otherwise show below it
    setTip({ stage, x: Math.min(Math.max(r.left + r.width / 2, 170), window.innerWidth - 170), y: above ? r.top - 8 : r.bottom + 8, above });
  };

  // ── connector geometry (measured) ──────────────────────────────────────────
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const canvasRef = useRef<HTMLDivElement>(null);
  const nodeEls = useRef(new Map<string, HTMLElement>());
  const setNodeRef = (id: string) => (el: HTMLElement | null) => { if (el) nodeEls.current.set(id, el); else nodeEls.current.delete(id); };
  const [edges, setEdges] = useState<EdgePath[]>([]);
  const [box, setBox] = useState({ w: 0, h: 0 });
  const statusKey = stages.map((s) => `${s.id}:${s.status}`).join("|");
  const measure = useCallback(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    const cr = canvas.getBoundingClientRect();
    if (!cr.width) return;
    const out: EdgePath[] = [];
    for (const e of TREE_EDGES) {
      const a = nodeEls.current.get(e.from), b = nodeEls.current.get(e.to); if (!a || !b) continue;
      const ar_ = a.getBoundingClientRect(), br = b.getBoundingClientRect();
      const y0 = ar_.bottom - cr.top;
      let x0: number, x1: number, y1: number, d: string;
      if (e.side) {
        // parent ➜ child listed under it: leave the parent near its inline-start edge, bend into the child's side
        x0 = (dir === "rtl" ? ar_.right - 22 : ar_.left + 22) - cr.left;
        x1 = (dir === "rtl" ? br.right : br.left) - cr.left; y1 = br.top + br.height / 2 - cr.top;
        d = `M ${x0} ${y0} C ${x0} ${y1}, ${x0} ${y1}, ${x1} ${y1}`;
      } else {
        x0 = ar_.left + ar_.width / 2 - cr.left; x1 = br.left + br.width / 2 - cr.left; y1 = br.top - cr.top;
        const ym = y0 + (y1 - y0) / 2;
        d = `M ${x0} ${y0} C ${x0} ${ym}, ${x1} ${ym}, ${x1} ${y1}`;
      }
      const sa = get(e.from).status, sb = get(e.to).status;
      out.push({ key: `${e.from}>${e.to}`, d, x0, y0, x1, y1, c0: EDGE_COLOR[edgeTone(sa)], c1: EDGE_COLOR[edgeTone(sb)], live: sb === "running", dim: sb === "pending" });
    }
    setEdges(out); setBox({ w: canvas.scrollWidth, h: canvas.scrollHeight });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dir, statusKey]);
  useLayoutEffect(() => { measure(); }, [measure]);
  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => measure()) : null;
    ro?.observe(canvas); window.addEventListener("resize", measure);
    return () => { ro?.disconnect(); window.removeEventListener("resize", measure); };
  }, [measure]);

  const renderNode = (stage: JobStage, compact = false) => {
    const toolName = safeDiagnosticText(stage.tool || toolByStage[stage.id] || "MIRSAD Engine", "tool");
    const sourceUrl = sourceByStage[stage.id];
    return (
    <div ref={setNodeRef(stage.id)} className={`${styles.treeNode} ${styles[stage.status] ?? ""} ${compact ? styles.treeNodeCompact : ""}`} tabIndex={0}
      onMouseEnter={(e) => showTip(stage, e.currentTarget)} onMouseLeave={() => setTip(null)}
      onFocus={(e) => showTip(stage, e.currentTarget)} onBlur={() => setTip(null)}>
      <div className={styles.treeIcon}>{stageIcon(stage.status)}</div>
      <div className={styles.treeCopy}><strong>{safeDiagnosticText(stage.label, "Stage")}</strong><em className="ltr">{toolName}</em>{sourceUrl && <a className={styles.sourceLink} href={sourceUrl} target="_blank" rel="noopener noreferrer" title={sourceUrl}><ExternalLink size={10}/> Source code</a>}<span>{safeDiagnosticText(stage.status, "pending")}</span>{stage.message && <small>{safeDiagnosticText(stage.message)}</small>}</div>
    </div>
    );
  };
  const single = (id: string) => <div className={styles.treeSingle}>{renderNode(get(id))}</div>;
  const row = (ids: string[]) => (
    <div className={styles.treeRow} style={{ "--cols": ids.length } as CSSProperties}>
      {ids.map((id) => <div className={styles.treeSlot} key={id}>{renderNode(get(id), true)}</div>)}
    </div>
  );
  const lane = (head: string, kids: string[]) => (
    <div className={styles.lane}>
      <div className={styles.laneHead}>{renderNode(get(head), true)}</div>
      <div className={styles.laneKids}>{kids.map((id) => <div className={styles.laneKid} key={id}>{renderNode(get(id))}</div>)}</div>
    </div>
  );
  const tipInfo = tip ? statusInfo(tip.stage.status) : null;
  const tipMsg = tip ? safeDiagnosticText(tip.stage.message || "", "") : "";
  return (
    <div className={styles.treeViewport} dir={dir}>
      {tip && tipInfo && createPortal(
        <div className={`${styles.stageTip} ${styles["tip_" + tip.stage.status] ?? ""}`} style={{ left: tip.x, top: tip.y, transform: tip.above ? "translate(-50%, -100%)" : "translate(-50%, 0)" }} role="tooltip" dir={dir}>
          <strong>{safeDiagnosticText(tip.stage.label, "Stage")}</strong>
          <span className={styles.stageTipStatus}>{tipInfo.label}</span>
          <p>{ar ? tipInfo.text : tipInfo.textEn}</p>
          {tip.stage.status === "skipped" && <p><b>{ar ? "سبب التخطي: " : "Why skipped: "}</b>{tipMsg || (ar ? "لم يُسجَّل سبب (الأداة معطّلة أو غير مثبتة أو غير مطلوبة في هذا الملف الشخصي للفحص)." : "No reason recorded (tool disabled, not installed, or not selected for this scan profile).")}</p>}
          {tip.stage.status === "failed" && <p><b>{ar ? "سبب الفشل / الخطأ: " : "Failure reason / error: "}</b><span className="ltr">{tipMsg || (ar ? "لم يُسجَّل خطأ تفصيلي — راجع السجل الحي." : "No detailed error recorded — check the live log.")}</span></p>}
          {tip.stage.status === "partial" && tipMsg && <p><b>{ar ? "تفاصيل: " : "Details: "}</b>{tipMsg}</p>}
          {(tip.stage.status === "completed" || tip.stage.status === "running") && tipMsg && <p className={styles.stageTipMsg}>{tipMsg}</p>}
        </div>,
        document.body
      )}
      <div className={styles.treeCanvas} ref={canvasRef}>
        <svg className={styles.treeEdges} width={box.w} height={box.h} aria-hidden="true" focusable="false">
          <defs>
            {edges.map((p) => (
              <linearGradient key={p.key} id={`${uid}-${p.key}`} gradientUnits="userSpaceOnUse" x1={p.x0} y1={p.y0} x2={p.x1 === p.x0 ? p.x1 + 0.01 : p.x1} y2={p.y1}>
                <stop offset="0" style={{ stopColor: p.c0 }} /><stop offset="1" style={{ stopColor: p.c1 }} />
              </linearGradient>
            ))}
          </defs>
          {edges.map((p) => (
            <path key={p.key} d={p.d} fill="none" stroke={`url(#${uid}-${p.key})`} strokeWidth={2} strokeLinecap="round"
              className={p.live ? styles.edgeLive : undefined} opacity={p.dim ? 0.55 : 1} />
          ))}
        </svg>
        {single("target_validation")}
        {single("target_reachability")}
        {single("dns_lookup")}
        {row(["port_scan", "service_discovery", "web_crawl", "api_security"])}
        <div className={styles.subdomainLabel}>SCANNER TOOLS</div>
        <div className={styles.lanes}>
          {lane("source_intelligence", SOURCE_TOOLS)}
          {lane("external_scanners", EXTERNAL_TOOLS)}
        </div>
        {single("subdomain_discovery")}
        <div className={styles.subdomainLabel}>SUBDOMAIN ASSESSMENT BRANCHES</div>
        {row(SUB_BRANCHES)}
        {single("vulnerability_analysis")}
        {row(["risk_correlation", "ai_validation"])}
        {single("finalize")}
      </div>
    </div>
  );
}

export function ScanProgressPage(){
 const { jobId="" }=useParams(); const navigate=useNavigate(); const {language,dir}=useLanguage(); const {applyFullScanResult, cachedJobs, cacheJob, activeScanId}=useScan();
 const [liveJob,setJob]=useState<JobSnapshot|null>(()=>jobId ? cachedJobs[jobId] ?? null : null);
 // Always show the newest snapshot we have for THIS job id. Deriving it (instead of relying on the
 // useState initialiser, which only runs once) means that when the route changes from
 // /scan-progress to /scan-progress/:jobId the cached state paints immediately.
 const job:JobSnapshot|null = (liveJob && liveJob.job_id===jobId) ? liveJob : (jobId ? cachedJobs[jobId] ?? null : null);
 const [checking,setChecking]=useState(()=>!jobId); const [error,setError]=useState<string|null>(null); const [socketState,setSocketState]=useState("connecting");
 const [clock,setClock]=useState(()=>Date.now());
 const pollInFlight=useRef(false);
 const [busy,setBusy]=useState(false);
 const langRef=useRef(language); langRef.current=language;
 useEffect(()=>{ const id=window.setInterval(()=>setClock(Date.now()),1000); return()=>window.clearInterval(id); },[]);
 const labels=useMemo(()=> language==="ar" ? {title:"تنفيذ الفحص",sub:"مراقبة مباشرة لمحركات مرصاد",live:"مباشر",elapsed:"الوقت المنقضي",eta:"الوقت المتبقي للفحص كاملاً",tasks:"المهام المكتملة",current:"العملية الحالية",stages:"مراحل الفحص",logs:"السجل الحي",graph:"فتح Intelligence Graph",scans:"العودة للفحوصات",pause:"إيقاف مؤقت",resume:"استئناف",cancel:"إلغاء",retry:"إعادة الاتصال",connected:"WebSocket متصل",polling:"وضع الاسترداد عبر HTTP",failed:"فشل الفحص",cancelling:"جارٍ الإلغاء…"} : {title:"Scan execution",sub:"Live orchestration of MIRSAD engines",live:"LIVE",elapsed:"Elapsed",eta:"Time remaining",tasks:"Tasks completed",current:"Current stage",stages:"Assessment stages",logs:"Live event stream",graph:"Open Intelligence Graph",scans:"Back to scans",pause:"Pause",resume:"Resume",cancel:"Cancel",retry:"Reconnect",connected:"WebSocket connected",polling:"HTTP recovery mode",failed:"Scan failed",cancelling:"Cancelling…"},[language]);
 useEffect(()=>{
   if (jobId) return;
   // Where to go when nothing is running. The page must never be a dead end right after a
   // scan ends: show the scan the workspace is on, else the last scan this browser ran, so
   // its final state (completed / failed / cancelled) and results stay reachable.
   const goToFallback=()=>{
     const fallback=activeScanId || readScanKey(LAST_SCAN_KEY);
     if(fallback) { navigate(`/scan-progress/${encodeURIComponent(fallback)}`, {replace:true}); return true; }
     return false;
   };
   // Instant path: the id of the running scan is remembered locally, so jump straight back to it
   // without waiting for a (possibly slow) network round-trip. If the id turns out to be stale,
   // the job page below falls back to the normal lookup.
   const stored=readScanKey(ACTIVE_SCAN_KEY);
   if(stored) { navigate(`/scan-progress/${encodeURIComponent(stored)}`, {replace:true}); return; }
   setChecking(true);
   let cancelled=false;
   let attempt=0;
   let retryTimer:number|undefined;
   // A single failed getActiveJobs() call (a transient network hiccup, or a
   // 401 caused by the backend's JWKS verification briefly failing under
   // load) used to be taken as proof there is no active scan, permanently
   // showing the "no active scan" empty state even while a scan was still
   // running server-side. Retry a few times with backoff before concluding
   // that there is genuinely nothing running.
   const MAX_ATTEMPTS=4;
   const check=async()=>{
     attempt+=1;
     try {
       const jobs=await getActiveJobs();
       if(cancelled) return;
       const active=jobs.find(x=>LIVE_JOB_STATUSES.has(x.status));
       if(active) {
         writeScanKey(ACTIVE_SCAN_KEY, active.job_id);
         writeScanKey(LAST_SCAN_KEY, active.job_id);
         navigate(`/scan-progress/${encodeURIComponent(active.job_id)}`, {replace:true});
         return;
       }
       // The request succeeded and nothing is running: a trustworthy answer, no retry needed.
       if(goToFallback()) return;
       setChecking(false);
     } catch {
       if(cancelled) return;
       if(attempt>=MAX_ATTEMPTS) { if(!goToFallback()) setChecking(false); return; }
       retryTimer=window.setTimeout(check, Math.min(4000, 500*2**attempt));
     }
   };
   void check();
   return()=>{cancelled=true; window.clearTimeout(retryTimer);};
 },[jobId,navigate,activeScanId]);

 useEffect(()=>{
   let cancelled=false;
   let ws:WebSocket|undefined;
   let timer:number|undefined;
   let reconnectTimer:number|undefined;
   let reconnectDelay=1000;
   // true while the last status request failed; keeps HTTP polling alive even if the socket is open
   let errored=false;
   const terminalStatuses=Array.from(TERMINAL_JOB_STATUSES);
   // Once the job is finished the server closes the socket on purpose (code 1000). Without this flag
   // the client treated that as a dropped connection and reconnected forever, once per second.
   let finished=!!(jobId && cachedJobs[jobId] && terminalStatuses.includes(cachedJobs[jobId].status));
   const consume=(x:JobSnapshot)=>{
     if(cancelled) return;
     if(terminalStatuses.includes(x.status)) { finished=true; if(timer) window.clearInterval(timer); }
     setJob(x); cacheJob(x); errored=false; setError(null);
     if(x.result) applyFullScanResult(x.result as any);
     writeScanKey(LAST_SCAN_KEY, x.job_id);
     if(terminalStatuses.includes(x.status)) {
       // Only forget the "running" marker if it still points at THIS job.
       if(readScanKey(ACTIVE_SCAN_KEY)===x.job_id) removeScanKey(ACTIVE_SCAN_KEY);
     } else {
       writeScanKey(ACTIVE_SCAN_KEY, x.job_id);
     }
   };
   const recoverActive=async()=>{
     try {
       const jobs=await getActiveJobs();
       const active=jobs.find(x=>LIVE_JOB_STATUSES.has(x.status));
       if(cancelled) return;
       if(active) {
         writeScanKey(ACTIVE_SCAN_KEY, active.job_id);
         if(active.job_id!==jobId) { navigate(`/scan-progress/${encodeURIComponent(active.job_id)}`,{replace:true}); return; }
         consume(active);
       } else {
         // This id no longer exists and nothing else is running: forget it everywhere, otherwise
         // the "no id" page would redirect straight back here and loop.
         if(readScanKey(ACTIVE_SCAN_KEY)===jobId) removeScanKey(ACTIVE_SCAN_KEY);
         if(readScanKey(LAST_SCAN_KEY)===jobId) removeScanKey(LAST_SCAN_KEY);
         navigate("/scan-progress",{replace:true});
       }
     } catch {}
   };
   const poll=async()=>{
     if(cancelled || !jobId || pollInFlight.current) return;
     pollInFlight.current=true;
     try { consume(await getJob(jobId)); }
     catch(e) {
       if(cancelled) return;
       // A failed *status request* is not a failed *scan*: say so, and include the HTTP status.
       const detail=describeRequestError(e,langRef.current,"");
       const message=(langRef.current==="ar"?"تعذر تحديث حالة الفحص (الفحص نفسه لم يتأثر)":"Could not refresh scan status (the scan itself is not affected)")+(detail?`: ${detail}`:"");
       // A stale URL should not strand the operator: recover the current durable job.
       // NOTE: safeUserError() always returns the generic fallback text, so the HTTP status
       // (ApiError.status) is the only reliable way to recognise "job not found".
       if((e as {status?:number})?.status===404) await recoverActive();
       else { errored=true; setError(message); }
     } finally {
       pollInFlight.current=false;
     }
   };
   const connect=()=>{
     if(cancelled || finished || !jobId) return;
     const token=getAccessToken();
     if(!token) { setSocketState("polling"); return; }
     const api=(import.meta.env.VITE_API_BASE_URL??"http://127.0.0.1:8000").replace(/^http:/,"ws:").replace(/^https:/,"wss:").replace(/\/$/,"");
     try {
       ws=new WebSocket(`${api}/api/v1/jobs/${encodeURIComponent(jobId)}/ws`,["bearer",token]);
       ws.onopen=()=>{ setSocketState("connected"); };
       // Reset the backoff only after real data arrives, so a socket that opens and is closed
       // immediately keeps backing off instead of hammering the server.
       ws.onmessage=e=>{ reconnectDelay=1000; try { consume(JSON.parse(e.data) as JobSnapshot); } catch {} };
       ws.onerror=()=>setSocketState("polling");
       ws.onclose=(ev)=>{
         if(cancelled) return;
         setSocketState("polling");
         if(finished) return;
         if(ev.code===4404||ev.code===4403) { void poll(); return; }
         window.clearTimeout(reconnectTimer);
         reconnectTimer=window.setTimeout(connect,reconnectDelay);
         reconnectDelay=Math.min(15_000,reconnectDelay*2);
       };
     } catch { setSocketState("polling"); }
   };
   void poll();
   connect();
   timer=window.setInterval(()=>{ if(finished) return; if(errored||!ws||ws.readyState!==WebSocket.OPEN) void poll(); },2000);
   const onVisible=()=>{ if(finished) return; if(document.visibilityState==="visible") { void poll(); if(!ws||ws.readyState!==WebSocket.OPEN) connect(); } };
   document.addEventListener("visibilitychange",onVisible);
   return()=>{ cancelled=true; window.clearTimeout(reconnectTimer); if(ws) ws.close(1000,"viewer left page"); if(timer) window.clearInterval(timer); document.removeEventListener("visibilitychange",onVisible); };
 },[jobId,applyFullScanResult,navigate,cacheJob]);
 async function control(kind:"pause"|"resume"|"cancel"){
   if(busy||!jobId) return;
   if(kind==="cancel" && !window.confirm(language==="ar"?"هل تريد إلغاء الفحص الجاري؟ سيتم إيقاف جميع الأدوات الجارية ولا يمكن استئنافه.":"Cancel the running scan? All running tools will be stopped and it cannot be resumed.")) return;
   setBusy(true);
   try{
     const next=kind==="pause"?await pauseJob(jobId):kind==="resume"?await resumeJob(jobId):await cancelJob(jobId);
     setJob(next);cacheJob(next);setError(null);
   }catch(e){
     // 409 on cancel means the job already reached a final state (e.g. a second click, or the worker
     // finished cancelling first). Not an error: just refresh the real status.
     if(kind==="cancel" && (e as {status?:number})?.status===409) { try { const j=await getJob(jobId); setJob(j); cacheJob(j); setError(null); return; } catch {} }
     const detail=describeRequestError(e,language,"");
     setError((language==="ar"?"تعذر تنفيذ العملية":"The action failed")+(detail?`: ${detail}`:""));
   } finally { setBusy(false); }
 }
 if (!jobId) {
   return <section className={`${styles.wrap} animateIn`}>
     <PageHeader icon={Radar} eyebrow="MIRSAD / LIVE ORCHESTRATION" title={labels.title} description={<>{labels.sub}</>} actions={<div className={styles.live}><i/>{labels.live}</div>} />
     <div className={styles.panel}>
       <div className={styles.emptyState}>
         <Clock3 size={28}/>
         <h3>{checking ? (language === "ar" ? "جارٍ البحث عن فحص جارٍ…" : "Looking for a running scan…") : (language === "ar" ? "لا يوجد فحص قيد التنفيذ" : "No active scan")}</h3>
         <p>{language === "ar" ? "هذه الصفحة تعرض تنفيذ الفحص الجاري، وبعد انتهائه تعرض حالته النهائية. ابدأ فحصًا جديدًا أو افتح فحصًا سابقًا من سجل الفحوصات." : "This page shows a running scan and, once it ends, its final state. Start a new scan or open a previous one from Scan history."}</p>
         <button className={styles.button} onClick={() => navigate("/scans")}>{labels.scans}</button>
       </div>
     </div>
   </section>;
 }
 const p=job?.progress??0; const terminal=job?.status && ["completed","partial","failed","cancelled"].includes(job.status); const cancelling=job?.status==="cancel_requested";
 const liveElapsed=job?.started_at && !terminal ? Math.max(job.elapsed_seconds || 0,(clock-Date.parse(job.started_at))/1000) : (job?.elapsed_seconds ?? 0);
 const waitingForWorker=job?.status==="pending";
 return <section className={`${styles.wrap} animateIn`}>
   <PageHeader icon={Radar} eyebrow="MIRSAD / LIVE ORCHESTRATION" title={labels.title} description={<span className="ltr">{job?.target??jobId}</span>} actions={<div className={styles.live}><i/>{socketState==="connected"?labels.connected:labels.polling}</div>} />
   <div className={styles.panel}>
     {waitingForWorker&&<div className={styles.queueNotice} role="status">{language==="ar" ? "الفحص في قائمة الانتظار ولم يبدأ بعد. تأكد من أن خدمة Worker تعمل، ثم راقب السجل الحي لتأكيد استلام المهمة." : "This scan is queued and has not started yet. Confirm that the Worker service is running, then check the live log for job pickup."}</div>}
     <div className={styles.hero}>
       <div className={styles.progressRing}>
         <div className={styles.ring}>
           <svg viewBox="0 0 100 100" className={styles.ringSvg}>
             <circle className={styles.ringTrack} cx="50" cy="50" r="44" />
             <circle
               className={styles.ringProgress}
               cx="50" cy="50" r="44"
               style={{ strokeDasharray: `${2 * Math.PI * 44}`, strokeDashoffset: `${2 * Math.PI * 44 * (1 - p / 100)}` } as CSSProperties}
             />
           </svg>
           <div className={styles.ringText}><strong>{p}%</strong><span>{job?.status??"pending"}</span></div>
         </div>
       </div>
       <div className={styles.metrics}>
         <div className={styles.metric}><span>{labels.elapsed}</span><b>{formatDuration(liveElapsed)}</b></div>
         <div className={styles.metric}><span>{labels.eta}</span><b>{formatDuration(job?.eta_seconds)}</b><small>{job?.eta_finish_at ? new Date(job.eta_finish_at).toLocaleString(language === "ar" ? "ar-SA" : undefined) : "—"}</small></div>
         <div className={styles.metric}><span>{language === "ar" ? "الوقت المتبقي للعملية الحالية" : "Time remaining for current operation"}</span><b>{formatDuration(job?.current_eta_seconds)}</b><small>{job?.current_eta_finish_at ? new Date(job.current_eta_finish_at).toLocaleString(language === "ar" ? "ar-SA" : undefined) : "—"}</small></div>
         <div className={styles.metric}><span>{language === "ar" ? "المهام" : "Tasks"}</span><b>{job?.completed_tasks??0}/{job?.total_tasks??0}</b>{job?.task_breakdown && (<small>{language === "ar" ? `${job.task_breakdown.completed??0} مكتملة، ${job.task_breakdown.skipped??0} متخطاة، ${job.task_breakdown.partial??0} جزئية، ${job.task_breakdown.failed??0} فاشلة` : `${job.task_breakdown.completed??0} completed, ${job.task_breakdown.skipped??0} skipped, ${job.task_breakdown.partial??0} partial, ${job.task_breakdown.failed??0} failed`}</small>)}</div>
         <div className={styles.metric}><span>{labels.current}</span><b className="ltr">{job?.current_engine??"—"}</b></div>
       </div>
     </div>
     <div className={styles.stageBlock}>
       <div className={styles.stageBlockHead}>
         <h3>{labels.stages}</h3>
       </div>
       <StageTree stages={job?.stages??[]} dir={dir}/>
     </div>
   </div>
   <div className={styles.panel}><div className={styles.actions}>{!terminal&&!cancelling&&job?.status!=="paused"&&<button className={styles.button} disabled={busy} onClick={()=>control("pause")}><Pause size={14}/>{labels.pause}</button>}{job?.status==="paused"&&!cancelling&&<button className={styles.button} disabled={busy} onClick={()=>control("resume")}><Play size={14}/>{labels.resume}</button>}{!terminal&&<button className={styles.button} disabled={busy||cancelling} onClick={()=>control("cancel")}><Square size={13}/>{cancelling?labels.cancelling:labels.cancel}</button>}{terminal&&(job.status==="completed"||job.status==="partial")&&<button className={`${styles.button} ${styles.primary}`} onClick={()=>navigate(`/attack-surface-intelligence/${jobId}`)}><Zap size={14}/>{labels.graph}<ExternalLink size={13}/></button>}<button className={styles.button} onClick={()=>navigate("/scans")}><Clock3 size={14}/>{labels.scans}</button></div>{error&&<div className={styles.error} role="alert">{error}</div>}{job?.status==="failed"&&<div className={styles.error} role="alert">{labels.failed}{job.error_message?`: ${safeDiagnosticText(job.error_message,"")}`:""}</div>}</div>
   <div className={styles.panel}><h3>{labels.logs}</h3><div className={styles.logs}>{(job?.logs??[]).slice().reverse().map((line,i)=><div className={styles.log} key={`${i}-${line}`}>{safeDiagnosticText(line, "Event")}</div>)}</div></div>
 </section>
}
