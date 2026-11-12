import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowDown, ArrowLeft, Ban, CheckCircle2, ChevronDown, Circle, Clipboard, Download,
  Globe, ListChecks, LoaderCircle, Pause, Play, Search, SkipForward, Terminal, XCircle, Radio, Square,
} from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";
import {
  cancelJob, getActiveJobs, getExecutionEventsSummary, getJob, getJobExecutions, getLiveScanResult, pauseJob, queryExecutionEvents, resumeJob,
  type ExecutionBuckets, type ExecutionEvent, type ExecutionEventsSummary, type ExecutionSummary, type JobSnapshot, type JobStage,
} from "../api/client";
import { safeUserError } from "../utils/security";
import { PageHeader } from "../components/PageHeader";
import styles from "./ScanExecutionPage.module.css";
import { ACTIVE_SCAN_KEY, LAST_SCAN_KEY, readScanKey } from "../utils/scanTracking";

/* ───────────────────────── helpers ───────────────────────── */

type Kind = "all" | "http" | "command" | "system" | "errors";
const TERMINAL = new Set(["completed", "partial", "failed", "cancelled"]);
const HTTP_TYPES = ["http", "browser_request"];
const CMD_TYPES = ["command", "command_exit", "output"];
const SYSTEM_TYPES = ["stage", "log", "engine", "external_result", "finding.created", "execution_started", "execution_finished", "trace_truncated", "note"];
const MAX_KEPT = 6000;
const FIRST_WINDOW = 300; // small first page so the stream paints fast; older events load on demand

/* The server persists everything (events + per-stage counters on the scan). These caches only make the
   page paint instantly on re-open: in-memory across navigation, localStorage (small stuff only) across reloads. */
const eventCache = new Map<string, { events: ExecutionEvent[]; lastSeq: number; hasEarlier: boolean }>();
const metaKey = (scanId: string) => `mirsad_exec_view_${scanId}`;
function readMeta(scanId: string): { executions: ExecutionSummary[]; executionId: string; summary: ExecutionEventsSummary | null } | null {
  try { const raw = localStorage.getItem(metaKey(scanId)); return raw ? JSON.parse(raw) : null; } catch { return null; }
}
function writeMeta(scanId: string, v: { executions: ExecutionSummary[]; executionId: string; summary: ExecutionEventsSummary | null }) {
  try { localStorage.setItem(metaKey(scanId), JSON.stringify(v)); } catch { /* storage full/unavailable */ }
}
const ZERO: ExecutionBuckets = { req: 0, ok: 0, redir: 0, c4: 0, c5: 0, fail: 0, cmds: 0, errs: 0 };

function fmtClock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
function fmtDuration(sec: number | null | undefined): string {
  if (sec == null || !Number.isFinite(sec)) return "—";
  if (sec < 1) return `${Math.round(sec * 1000)}ms`;
  if (sec < 90) return `${sec.toFixed(sec < 10 ? 1 : 0)}s`;
  const m = Math.floor(sec / 60), s = Math.floor(sec % 60);
  if (m < 90) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}
function fmtBytes(n: unknown): string {
  const v = Number(n); if (!Number.isFinite(v) || v <= 0) return "0 B";
  if (v < 1024) return `${v} B`; if (v < 1048576) return `${(v / 1024).toFixed(1)} KB`; return `${(v / 1048576).toFixed(1)} MB`;
}
function statusClass(code: number | null | undefined, hasError?: boolean): string {
  if (hasError || code == null) return "bad";
  if (code >= 500) return "bad"; if (code >= 400) return "warn"; if (code >= 300) return "info"; if (code >= 200) return "ok";
  return "info";
}
type P = Record<string, any>;
const pl = (e: ExecutionEvent): P => (e.payload ?? {}) as P;

function isErrorEvent(e: ExecutionEvent): boolean {
  const p = pl(e);
  if (e.event_type === "http" || e.event_type === "browser_request") return Boolean(p.error) || (p.response?.status ?? 0) >= 400;
  if (e.event_type === "command_exit") return (p.exit_code ?? 0) !== 0 || ["FAILED", "TIMEOUT"].includes(String(p.state));
  if (e.event_type === "output") return p.stream === "stderr";
  if (e.event_type === "stage") return p.status === "failed";
  if (e.event_type === "external_result") return ["FAILED", "TIMEOUT", "UNAVAILABLE"].includes(String(p.status));
  return false;
}
function toCurl(e: ExecutionEvent): string {
  const r = pl(e).request ?? {};
  const parts = ["curl", "-i", "-X", r.method ?? "GET", `'${String(r.url ?? "").replace(/'/g, "'\\''")}'`];
  for (const [k, v] of Object.entries<string>(r.headers ?? {})) {
    if (["host", "content-length", "accept-encoding", "connection"].includes(k.toLowerCase())) continue;
    parts.push("-H", `'${k}: ${String(v).replace(/'/g, "'\\''")}'`);
  }
  if (r.body?.text) parts.push("--data-raw", `'${String(r.body.text).replace(/'/g, "'\\''")}'`);
  return parts.join(" ");
}
function prettyBody(text: string, headers: Record<string, string> | undefined): string {
  const ct = Object.entries(headers ?? {}).find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
  if (/json/i.test(ct) || /^\s*[[{]/.test(text)) { try { return JSON.stringify(JSON.parse(text), null, 2); } catch { /* keep raw */ } }
  return text;
}
async function copy(text: string) { try { await navigator.clipboard.writeText(text); } catch { /* clipboard may be blocked */ } }

function stageIcon(s: JobStage | undefined) {
  switch (s?.status) {
    case "completed": return <CheckCircle2 size={14} />;
    case "failed": return <XCircle size={14} />;
    case "running": return <LoaderCircle size={14} className={styles.spin} />;
    case "skipped": return <SkipForward size={14} />;
    case "partial": return <AlertTriangle size={14} />;
    default: return <Circle size={14} />;
  }
}

/* ───────────────────────── page ───────────────────────── */

export function ScanExecutionPage() {
  const { scanId: routeScanId = "" } = useParams();
  const navigate = useNavigate();
  const { language } = useLanguage();
  const { unified, activeScanId, cachedJobs, cacheJob } = useScan();
  const ar = language === "ar";
  const t = useCallback((a: string, e: string) => (ar ? a : e), [ar]);
  const sharedId = readScanKey(ACTIVE_SCAN_KEY) || readScanKey(LAST_SCAN_KEY);
  const scanId = routeScanId || activeScanId || unified?.scan_id || sharedId;

  const [job, setJob] = useState<JobSnapshot | null>(() => (scanId ? cachedJobs[scanId] ?? null : null));
  const saved = useMemo(() => (scanId ? readMeta(scanId) : null), [scanId]);
  const [executions, setExecutions] = useState<ExecutionSummary[]>(() => saved?.executions ?? []);
  const [executionId, setExecutionId] = useState(() => saved?.executionId || (scanId ? cachedJobs[scanId]?.execution_id ?? "" : ""));
  const [summary, setSummary] = useState<ExecutionEventsSummary | null>(() => saved?.summary ?? null);
  const [liveResult, setLiveResult] = useState<P | null>(null);
  const [stageId, setStageId] = useState<string>("__all");
  const [kind, setKind] = useState<Kind>("all");
  const [query, setQuery] = useState("");
  const [events, setEvents] = useState<ExecutionEvent[]>([]);
  const [hasEarlier, setHasEarlier] = useState(false);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [follow, setFollow] = useState(true);
  const [streamPaused, setStreamPaused] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [resultTab, setResultTab] = useState<"external" | "verification" | "correlation" | "defectdojo" | "config" | "json">("external");
  const listRef = useRef<HTMLDivElement | null>(null);
  const lastSeqRef = useRef(0);
  const loadingRef = useRef(false); // the live tail must not run until the first page has landed

  /* — redirect to the running job when opened without an id — */
  useEffect(() => {
    if (scanId) return;
    let cancelled = false;
    (async () => {
      try {
        const active = await getActiveJobs();
        const cur = active.find((j) => ["pending", "running", "paused"].includes(String(j.status)));
        if (!cancelled && cur?.job_id) navigate(`/scan-execution/${encodeURIComponent(cur.job_id)}`, { replace: true });
      } catch { /* nothing active */ }
    })();
    return () => { cancelled = true; };
  }, [scanId, navigate]);

  /* — job + executions + summary polling — */
  useEffect(() => {
    if (!scanId) return;
    let stopped = false; let done = false; let timer: number | undefined; let busyNow = false;
    const tick = async () => {
      if (stopped || busyNow) return;
      busyNow = true;
      try {
        const [j, ex] = await Promise.all([getJob(scanId), getJobExecutions(scanId)]);
        if (stopped) return;
        setJob(j); cacheJob(j); setExecutions(ex); setError("");
        const eid = executionId || j.execution_id || ex[0]?.execution_id || "";
        if (eid && !executionId) setExecutionId(eid);
        let sm: ExecutionEventsSummary | null = null;
        if (eid) { try { sm = await getExecutionEventsSummary(scanId, eid); if (!stopped) setSummary(sm); } catch { /* keep the last known counters */ } }
        if (eid) writeMeta(scanId, { executions: ex, executionId: eid, summary: sm });
        if (TERMINAL.has(j.status)) done = true; // final state reached: stop polling
      } catch (e) {
        if (!stopped) setError(safeUserError(e, t("تعذر تحديث حالة الفحص. تتم إعادة المحاولة تلقائيًا.", "Could not refresh scan state. Retrying automatically.")));
      } finally {
        busyNow = false;
        if (!stopped && !done && document.visibilityState === "visible") timer = window.setTimeout(tick, 2000);
      }
    };
    const onVis = () => { if (document.visibilityState === "visible") { if (timer) window.clearTimeout(timer); void tick(); } };
    document.addEventListener("visibilitychange", onVis);
    void tick();
    return () => { stopped = true; if (timer) window.clearTimeout(timer); document.removeEventListener("visibilitychange", onVis); };
  }, [scanId, executionId, cacheJob, t]);

  /* — server-side filter for the event window — */
  const serverTypes = useMemo(() => (kind === "http" ? HTTP_TYPES : kind === "command" ? CMD_TYPES : kind === "system" ? SYSTEM_TYPES : undefined), [kind]);
  const stageFilter = stageId === "__all" ? undefined : stageId;

  /* — initial / filter-change load (newest 1500) — */
  useEffect(() => {
    if (!scanId || !executionId) { setEvents([]); return; }
    let cancelled = false;
    const key = `${scanId}|${executionId}|${stageFilter ?? ""}|${(serverTypes ?? []).join(",")}`;
    const hit = eventCache.get(key);
    setSelectedSeq(null); loadingRef.current = true;
    if (hit) { setEvents(hit.events); lastSeqRef.current = hit.lastSeq; setHasEarlier(hit.hasEarlier); setLoadingEvents(false); }
    else { lastSeqRef.current = 0; setLoadingEvents(true); }
    // Always re-fetch the newest window (cheap) so a cached view is refreshed, never left stale.
    queryExecutionEvents(scanId, executionId, { limit: FIRST_WINDOW, newestFirst: true, stage: stageFilter, eventTypes: serverTypes })
      .then((rows) => {
        if (cancelled) return;
        const lastSeq = rows.reduce((m, r) => Math.max(m, r.sequence), 0);
        setEvents(rows); lastSeqRef.current = lastSeq; setHasEarlier(rows.length >= FIRST_WINDOW);
        eventCache.set(key, { events: rows, lastSeq, hasEarlier: rows.length >= FIRST_WINDOW });
      })
      .catch((e) => { if (!cancelled && !hit) setError(safeUserError(e, t("تعذر تحميل أحداث التنفيذ.", "Unable to load execution events."))); })
      .finally(() => { loadingRef.current = false; if (!cancelled) setLoadingEvents(false); });
    return () => { cancelled = true; loadingRef.current = false; };
  }, [scanId, executionId, stageFilter, serverTypes, t]);

  /* — live tail: only events newer than what is on screen — */
  useEffect(() => {
    if (!scanId || !executionId || streamPaused) return;
    let stopped = false; let timer: number | undefined;
    const tail = async () => {
      if (stopped || loadingRef.current || document.visibilityState !== "visible") { if (!stopped) timer = window.setTimeout(tail, 1500); return; }
      try {
        let guard = 0; let got: ExecutionEvent[] = [];
        for (;;) {
          const rows = await queryExecutionEvents(scanId, executionId, { limit: 2000, afterSequence: lastSeqRef.current, stage: stageFilter, eventTypes: serverTypes });
          if (stopped) return;
          if (rows.length) { lastSeqRef.current = rows.reduce((m, r) => Math.max(m, r.sequence), lastSeqRef.current); got = got.concat(rows); }
          if (rows.length < 2000 || ++guard > 5) break;
        }
        if (got.length && !stopped) setEvents((prev) => {
          const merged = prev.concat(got); const kept = merged.length > MAX_KEPT ? merged.slice(merged.length - MAX_KEPT) : merged;
          eventCache.set(`${scanId}|${executionId}|${stageFilter ?? ""}|${(serverTypes ?? []).join(",")}`, { events: kept, lastSeq: lastSeqRef.current, hasEarlier: true });
          return kept;
        });
      } catch { /* next tick retries */ }
      if (!stopped) timer = window.setTimeout(tail, TERMINAL.has(String(job?.status)) ? 6000 : 2000);
    };
    timer = window.setTimeout(tail, 600);
    return () => { stopped = true; if (timer) window.clearTimeout(timer); };
  }, [scanId, executionId, stageFilter, serverTypes, streamPaused, job?.status]);

  /* — engine results: live partial bundle while running, final result afterwards (never blank) — */
  useEffect(() => {
    if (!scanId || !showResults) return;
    let stopped = false; let timer: number | undefined;
    const pull = async () => {
      try { const r = await getLiveScanResult(scanId); if (!stopped && r && Object.keys(r).length) setLiveResult(r as P); } catch { /* keep last */ }
      if (!stopped && !TERMINAL.has(String(job?.status))) timer = window.setTimeout(pull, 5000);
    };
    void pull();
    return () => { stopped = true; if (timer) window.clearTimeout(timer); };
  }, [scanId, showResults, job?.status]);

  /* — follow the tail — */
  useEffect(() => {
    if (!follow || !listRef.current) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [events, follow]);

  const loadEarlier = async () => {
    if (!events.length) return;
    const first = events.reduce((m, r) => Math.min(m, r.sequence), Infinity);
    try {
      const rows = await queryExecutionEvents(scanId, executionId, { limit: 1000, beforeSequence: first, newestFirst: true, stage: stageFilter, eventTypes: serverTypes });
      setFollow(false); setEvents((prev) => rows.concat(prev)); setHasEarlier(rows.length >= 1000);
    } catch (e) { setError(safeUserError(e, t("تعذر تحميل الأحداث الأقدم.", "Unable to load earlier events."))); }
  };

  /* — derived — */
  const stages = job?.stages ?? [];
  const stage = stageFilter ? stages.find((s) => s.id === stageFilter) : undefined;
  const counts = summary?.stages ?? {};
  const countFor = (id: string) => { const c = counts[id] ?? {}; const http = (c.http ?? 0) + (c.browser_request ?? 0); const cmd = c.command ?? 0; const total = Object.values(c).reduce((a, b) => a + b, 0); return { http, cmd, total }; };
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events.filter((e) => {
      if (kind === "errors" && !isErrorEvent(e)) return false;
      if (!q) return true;
      return (e.message + " " + e.tool + " " + e.event_type).toLowerCase().includes(q) || JSON.stringify(e.payload ?? {}).toLowerCase().includes(q);
    });
  }, [events, kind, query]);
  const selected = useMemo(() => visible.find((e) => e.sequence === selectedSeq) ?? null, [visible, selectedSeq]);
  const originMs = useMemo(() => { const d = new Date(executions.find((x) => x.execution_id === executionId)?.started_at ?? events[0]?.created_at ?? ""); return d.getTime(); }, [executions, executionId, events]);
  const viewStats = useMemo(() => {
    const bk = summary?.buckets;
    if (bk && kind === "all" && !query.trim()) { // persisted server-side counters: complete, and there even when this page was closed
      const b = stageFilter ? (bk[stageFilter] ?? ZERO) : Object.values(bk).reduce((a, x) => ({ req: a.req + x.req, ok: a.ok + x.ok, redir: a.redir + x.redir, c4: a.c4 + x.c4, c5: a.c5 + x.c5, fail: a.fail + x.fail, cmds: a.cmds + x.cmds, errs: a.errs + x.errs }), ZERO);
      return b;
    }
    let req = 0, ok = 0, redir = 0, c4 = 0, c5 = 0, fail = 0, cmds = 0, errs = 0;
    for (const e of events) {
      const p = pl(e);
      if (e.event_type === "http" || e.event_type === "browser_request") {
        req++; const s = p.response?.status;
        if (p.error) fail++; else if (s >= 500) c5++; else if (s >= 400) c4++; else if (s >= 300) redir++; else if (s >= 200) ok++;
      } else if (e.event_type === "command") cmds++;
      if (isErrorEvent(e)) errs++;
    }
    return { req, ok, redir, c4, c5, fail, cmds, errs };
  }, [events, summary, stageFilter, kind, query]);

  const control = async (fn: (id: string) => Promise<JobSnapshot>) => {
    setBusy(true);
    try { const j = await fn(scanId); setJob(j); cacheJob(j); } catch (e) { setError(safeUserError(e, t("تعذر تنفيذ الأمر.", "Command failed."))); } finally { setBusy(false); }
  };
  const exportView = () => {
    const blob = new Blob([JSON.stringify({ scan_id: scanId, execution_id: executionId, stage: stageFilter ?? "all", exported_at: new Date().toISOString(), events: visible }, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `mirsad-trace-${scanId.slice(0, 8)}-${stageFilter ?? "all"}.json`; a.click(); URL.revokeObjectURL(a.href);
  };

  if (!scanId) {
    return <section className={`${styles.wrap} animateIn`}><div className={styles.empty}><ListChecks size={28} /><h2>{t("لا يوجد فحص محدد", "No scan selected")}</h2><p>{t("اختر فحصًا من سجل الفحوصات أو شغّل فحصًا جديدًا.", "Pick a scan from history or start a new one.")}</p><button className={styles.btn} onClick={() => navigate("/scan-history")}>{t("فتح السجل", "Open history")}</button></div></section>;
  }

  const result = (job?.result ?? (unified?.scan_id === scanId ? unified : null) ?? liveResult) as P | null;
  const status = String(job?.status ?? "—");
  const live = job ? !TERMINAL.has(job.status) : false;
  const rel = (iso: string) => { const d = new Date(iso).getTime() - originMs; return Number.isFinite(d) && d >= 0 ? `+${fmtDuration(d / 1000)}` : ""; };

  return (
    <section className={`${styles.wrap} animateIn`} dir={ar ? "rtl" : "ltr"}>
      {/* ───────── header ───────── */}
      <PageHeader
        icon={ListChecks}
        eyebrow="MIRSAD · EXECUTION TRACE"
        title={t("تنفيذ الفحص المباشر", "Live scan execution")}
        description={<><bdi>{(result?.target as string) ?? job?.target ?? scanId}</bdi><span className={styles.sep}>·</span><code dir="ltr">{scanId}</code></>}
        actions={<>
          <span className={`${styles.pill} ${styles[`st_${status}`] ?? ""}`}>
            {live ? <Radio size={12} className={styles.pulse} /> : null}
            {live ? t("مباشر", "LIVE") : status.toUpperCase()}
          </span>
          {live && job?.status !== "paused" && <button className={styles.btn} disabled={busy} onClick={() => control(pauseJob)}><Pause size={14} />{t("إيقاف مؤقت", "Pause")}</button>}
          {job?.status === "paused" && <button className={styles.btn} disabled={busy} onClick={() => control(resumeJob)}><Play size={14} />{t("استئناف", "Resume")}</button>}
          {live && <button className={`${styles.btn} ${styles.danger}`} disabled={busy} onClick={() => { if (window.confirm(t("إلغاء الفحص الحالي؟", "Cancel the running scan?"))) void control(cancelJob); }}><Square size={13} />{t("إلغاء", "Cancel")}</button>}
          <button className={styles.btn} onClick={() => navigate("/scan-history")}><ArrowLeft size={14} />{t("السجل", "History")}</button>
        </>}
      />

      {error && <div className={styles.error} role="alert"><AlertTriangle size={15} />{error}</div>}

      {/* ───────── overall strip ───────── */}
      <div className={styles.strip}>
        <div className={styles.bar} role="progressbar" aria-valuenow={job?.progress ?? 0} aria-valuemin={0} aria-valuemax={100}><i style={{ width: `${job?.progress ?? 0}%` }} /></div>
        <div className={styles.stats}>
          <span><b>{job?.progress ?? 0}%</b>{t("التقدم", "progress")}</span>
          <span><b>{job?.completed_tasks ?? 0}/{job?.total_tasks ?? stages.length}</b>{t("مراحل", "stages")}</span>
          <span><b>{fmtDuration(job?.elapsed_seconds)}</b>{t("المدة", "elapsed")}</span>
          <span><b dir="ltr">{job?.current_engine ?? "—"}</b>{t("المحرك الحالي", "current engine")}</span>
          <span><b>{summary?.total ?? 0}</b>{t("حدث مسجّل", "events recorded")}</span>
          {executions.length > 1 && (
            <select aria-label={t("محاولة التنفيذ", "Execution attempt")} value={executionId} onChange={(e) => { setExecutionId(e.target.value); setStageId("__all"); }}>
              {executions.map((x) => <option key={x.execution_id} value={x.execution_id}>#{x.attempt} · {x.status}</option>)}
            </select>
          )}
        </div>
      </div>

      {/* ───────── workspace ───────── */}
      <div className={styles.workspace}>
        {/* stages */}
        <nav className={styles.stages} aria-label={t("المراحل", "Stages")}>
          <button type="button" className={`${styles.stageRow} ${stageId === "__all" ? styles.stageActive : ""}`} onClick={() => setStageId("__all")}>
            <span className={styles.stageIcon}><Activity size={14} /></span>
            <span className={styles.stageText}><b>{t("كل المراحل", "All stages")}</b><small>{t("التدفق الكامل بترتيبه الزمني", "Full chronological stream")}</small></span>
            <span className={styles.badges}><em>{summary?.total ?? 0}</em></span>
          </button>
          {stages.length === 0 && <p className={styles.muted}>{t("لم تبدأ مراحل بعد…", "No stages yet…")}</p>}
          {stages.map((s) => {
            const c = countFor(s.id);
            return (
              <button type="button" key={s.id} className={`${styles.stageRow} ${styles[`s_${s.status}`] ?? ""} ${stageId === s.id ? styles.stageActive : ""}`} onClick={() => setStageId(s.id)} aria-pressed={stageId === s.id}>
                <span className={styles.stageIcon}>{stageIcon(s)}</span>
                <span className={styles.stageText}>
                  <b>{s.label}</b>
                  <small><bdi>{s.status}{s.status === "running" ? ` · ${s.progress}%` : ""}{s.message && !/^(running|queued|pending)/i.test(s.message) ? ` · ${s.message}` : ""}</bdi></small>
                  {s.status === "running" && <span className={styles.miniBar}><i style={{ width: `${s.progress}%` }} /></span>}
                </span>
                <span className={styles.badges} dir="ltr">
                  {c.http > 0 && <em title={t("طلبات HTTP", "HTTP requests")}><Globe size={10} />{c.http}</em>}
                  {c.cmd > 0 && <em title={t("أوامر", "Commands")}><Terminal size={10} />{c.cmd}</em>}
                  {c.http === 0 && c.cmd === 0 && c.total > 0 && <em>{c.total}</em>}
                </span>
              </button>
            );
          })}
        </nav>

        {/* stream */}
        <div className={styles.stream}>
          <div className={styles.streamHead}>
            <div className={styles.streamTitle}>
              <h2>{stage?.label ?? t("كل المراحل", "All stages")}</h2>
              {stage && <p><bdi>{stage.message || stage.status}</bdi>{stage.started_at ? ` · ${t("بدأت", "started")} ${fmtClock(stage.started_at)}` : ""}{stage.finished_at ? ` · ${t("انتهت", "finished")} ${fmtClock(stage.finished_at)}` : ""}</p>}
            </div>
            <div className={styles.viewStats} dir="ltr">
              <span title="requests"><Globe size={11} />{viewStats.req}</span>
              <span className={styles.cOk} title="2xx">{viewStats.ok}</span>
              <span className={styles.cInfo} title="3xx">{viewStats.redir}</span>
              <span className={styles.cWarn} title="4xx">{viewStats.c4}</span>
              <span className={styles.cBad} title="5xx / failed">{viewStats.c5 + viewStats.fail}</span>
              <span title="commands"><Terminal size={11} />{viewStats.cmds}</span>
              {viewStats.errs > 0 && <span className={styles.cBad} title="errors"><AlertTriangle size={11} />{viewStats.errs}</span>}
            </div>
          </div>

          <div className={styles.toolbar}>
            <div className={styles.seg} role="tablist">
              {([["all", t("الكل", "All")], ["http", t("طلبات واستجابات", "Requests")], ["command", t("أوامر ومخرجات", "Commands")], ["system", t("أحداث النظام", "System")], ["errors", t("الأخطاء", "Errors")]] as [Kind, string][]).map(([k, label]) => (
                <button key={k} role="tab" aria-selected={kind === k} className={kind === k ? styles.segOn : ""} onClick={() => setKind(k)}>{label}</button>
              ))}
            </div>
            <label className={styles.search}><Search size={13} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("بحث في الروابط والأوامر والرؤوس…", "Search URLs, commands, headers…")} dir="auto" /></label>
            <button className={`${styles.btn} ${styles.sm}`} onClick={() => setStreamPaused((v) => !v)} aria-pressed={streamPaused}>{streamPaused ? <Play size={13} /> : <Pause size={13} />}{streamPaused ? t("استئناف التدفق", "Resume feed") : t("تجميد التدفق", "Freeze feed")}</button>
            <button className={`${styles.btn} ${styles.sm}`} onClick={exportView}><Download size={13} />JSON</button>
          </div>

          <div className={styles.split}>
            <div className={styles.list} ref={listRef} onScroll={(e) => { const el = e.currentTarget; const atEnd = el.scrollHeight - el.scrollTop - el.clientHeight < 40; if (atEnd !== follow) setFollow(atEnd); }} dir="ltr">
              {hasEarlier && <button className={styles.earlier} onClick={loadEarlier}>↑ {t("تحميل أحداث أقدم", "Load earlier events")}</button>}
              {loadingEvents && <div className={styles.loading}>{t("جارٍ التحميل…", "Loading…")}</div>}
              {!loadingEvents && visible.length === 0 && (
                <div className={styles.emptyList} dir={ar ? "rtl" : "ltr"}>
                  {live ? <><LoaderCircle size={18} className={styles.spin} /><p>{t("بانتظار أول نشاط لهذه المرحلة… سيظهر هنا فور حدوثه.", "Waiting for the first activity of this stage… it will appear here as it happens.")}</p></>
                    : <><Ban size={18} /><p>{stage?.status === "skipped" ? t("تم تخطي هذه المرحلة؛ لم يُنفَّذ فيها شيء.", "This stage was skipped; nothing was executed.") : t("لا توجد أحداث مسجلة لهذا العرض. الفحوصات القديمة لا تحتوي تتبعًا تفصيليًا.", "No events recorded for this view. Older scans have no detailed trace.")}</p></>}
                </div>
              )}
              {visible.map((e) => <Row key={e.event_id} e={e} rel={rel(e.created_at)} active={e.sequence === selectedSeq} onSelect={() => setSelectedSeq(e.sequence)} />)}
              {!follow && visible.length > 0 && <button className={styles.jump} onClick={() => { setFollow(true); }}><ArrowDown size={13} />{t("متابعة المباشر", "Follow live")}</button>}
            </div>
            <aside className={styles.inspector} dir="ltr" aria-label="Inspector">
              {selected ? <Inspector e={selected} ar={ar} /> : <div className={styles.inspectorEmpty} dir={ar ? "rtl" : "ltr"}><Clipboard size={20} /><p>{t("اختر أي سطر لعرض الطلب والاستجابة كاملين، أو الأمر ومخرجاته.", "Select a row to see the full request & response, or the command and its output.")}</p></div>}
            </aside>
          </div>
        </div>
      </div>

      {/* ───────── results (kept from the previous page) ───────── */}
      <section className={styles.results}>
        <button className={styles.resultsToggle} onClick={() => setShowResults((v) => !v)} aria-expanded={showResults}><ChevronDown size={14} style={{ transform: showResults ? "rotate(180deg)" : "none" }} />{t("نتائج المحركات والإعدادات", "Engine results & configuration")}</button>
        {showResults && <div className={styles.resultsBody}>
          <div className={styles.seg}>{(["external", "verification", "correlation", "defectdojo", "config", "json"] as const).map((k) => <button key={k} className={resultTab === k ? styles.segOn : ""} onClick={() => setResultTab(k)}>{({ external: t("الفاحصات الخارجية", "External scanners"), verification: t("التحقق", "Verification"), correlation: t("الربط", "Correlation"), defectdojo: "DefectDojo", config: t("الإعدادات", "Config"), json: "Raw JSON" })[k]}</button>)}</div>
          {resultTab === "external" && <div className={styles.cards}>{Object.entries<P>((result?.external_scanners ?? {}) as Record<string, P>).map(([name, v]) => <pre key={name} dir="ltr">{`${name.toUpperCase()}\nstatus   ${v?.status ?? "—"}\nversion  ${v?.version ?? "—"}\nfindings ${v?.findings?.length ?? 0}\nreason   ${v?.reason ?? v?.persistence_error ?? "—"}`}</pre>)}</div>}
          {resultTab === "verification" && <pre dir="ltr">{JSON.stringify(result?.verification_summary ?? result?.pipeline?.verification ?? {}, null, 2)}</pre>}
          {resultTab === "correlation" && <pre dir="ltr">{JSON.stringify(((result?.findings ?? []) as P[]).map((f) => ({ finding_id: f.finding_id, duplicate_count: f.duplicate_count, source_engines: f.source_engines })), null, 2)}</pre>}
          {resultTab === "defectdojo" && <pre dir="ltr">{JSON.stringify(result?.pipeline?.defectdojo ?? { status: "PENDING/disabled" }, null, 2)}</pre>}
          {resultTab === "config" && <pre dir="ltr">{JSON.stringify(job?.execution_config ?? {}, null, 2)}</pre>}
          {resultTab === "json" && <pre dir="ltr">{JSON.stringify({ scan_id: scanId, result }, null, 2).slice(0, 400000)}</pre>}
        </div>}
      </section>
    </section>
  );
}

/* ───────────────────────── row ───────────────────────── */

function Row({ e, rel, active, onSelect }: { e: ExecutionEvent; rel: string; active: boolean; onSelect: () => void }) {
  const p = pl(e);
  const time = <span className={styles.time}>{fmtClock(e.created_at)}<small>{rel}</small></span>;
  let badge: React.ReactNode; let main: React.ReactNode; let meta: React.ReactNode = null;
  if (e.event_type === "http" || e.event_type === "browser_request") {
    const status = p.response?.status as number | undefined; const cls = statusClass(status, Boolean(p.error));
    badge = <span className={`${styles.method}`}>{p.request?.method ?? "GET"}</span>;
    main = <span className={styles.url} title={p.request?.url}>{p.request?.url ?? e.message}</span>;
    meta = <>
      <span className={`${styles.code} ${styles[`c_${cls}`]}`}>{p.error ? "ERR" : status ?? "…"}</span>
      {p.duration_ms != null && <span className={styles.dim}>{Math.round(p.duration_ms)}ms</span>}
      {p.response?.body?.size ? <span className={styles.dim}>{fmtBytes(p.response.body.size)}</span> : null}
      {p.source && p.source !== "httpx" && <span className={styles.tag}>{p.source}</span>}
    </>;
  } else if (e.event_type === "command") {
    badge = <span className={`${styles.method} ${styles.mCmd}`}>$</span>;
    main = <span className={styles.url} title={p.command}>{p.command ?? e.message}</span>;
  } else if (e.event_type === "output") {
    badge = <span className={`${styles.method} ${styles.mOut}`}>{p.stream === "stderr" ? "err" : "out"}</span>;
    main = <span className={`${styles.url} ${p.stream === "stderr" ? styles.stderr : ""}`}>{e.message}</span>;
  } else if (e.event_type === "command_exit") {
    const bad = (p.exit_code ?? 0) !== 0 || p.state === "TIMEOUT";
    badge = <span className={`${styles.method} ${styles.mCmd}`}>exit</span>;
    main = <span className={styles.url}>{e.message}</span>;
    meta = <span className={`${styles.code} ${bad ? styles.c_bad : styles.c_ok}`}>{p.exit_code ?? "—"}</span>;
  } else {
    badge = <span className={`${styles.method} ${styles.mSys}`}>{e.event_type.replace("_", " ").slice(0, 9)}</span>;
    main = <span className={styles.url}>{e.message}</span>;
  }
  return (
    <button type="button" className={`${styles.row} ${active ? styles.rowActive : ""} ${isErrorEvent(e) ? styles.rowErr : ""}`} onClick={onSelect}>
      {time}{badge}{main}<span className={styles.meta}>{meta}</span>
    </button>
  );
}

/* ───────────────────────── inspector ───────────────────────── */

function KV({ data }: { data: Record<string, string> | undefined }) {
  const rows = Object.entries(data ?? {});
  if (!rows.length) return <p className={styles.dim}>—</p>;
  return <table className={styles.kv}><tbody>{rows.map(([k, v]) => <tr key={k}><th>{k}</th><td>{String(v)}</td></tr>)}</tbody></table>;
}
function BodyBlock({ body, headers }: { body: P | undefined; headers: Record<string, string> | undefined }) {
  if (!body || (!body.text && !body.note)) return <p className={styles.dim}>(empty body)</p>;
  return <>
    <p className={styles.dim}>{fmtBytes(body.size)}{body.truncated ? " · truncated preview" : ""}{body.note ? ` · ${body.note}` : ""}</p>
    {body.text ? <pre className={styles.code2}>{prettyBody(String(body.text), headers)}</pre> : null}
  </>;
}

function Inspector({ e, ar }: { e: ExecutionEvent; ar: boolean }) {
  const p = pl(e); const t = (a: string, en: string) => (ar ? a : en);
  const [tab, setTab] = useState<"req" | "res" | "raw">("res");
  useEffect(() => { setTab(p.response || p.error ? "res" : "req"); }, [e.event_id]); // eslint-disable-line react-hooks/exhaustive-deps
  const head = <div className={styles.inspHead}><span>#{e.sequence}</span><span>{e.event_type}</span>{e.tool && <span>{e.tool}</span>}<span>{e.created_at}</span></div>;

  if (e.event_type === "http" || e.event_type === "browser_request") {
    const status = p.response?.status as number | undefined;
    return <div className={styles.insp}>
      {head}
      <div className={styles.inspLine}>
        <span className={styles.method}>{p.request?.method}</span>
        <span className={`${styles.code} ${styles[`c_${statusClass(status, Boolean(p.error))}`]}`}>{p.error ? "ERROR" : `${status ?? "…"} ${p.response?.reason ?? ""}`}</span>
        {p.duration_ms != null && <span className={styles.dim}>{Math.round(p.duration_ms)} ms</span>}
        {p.resource_type && <span className={styles.tag}>{p.resource_type}</span>}
      </div>
      <pre className={styles.urlFull}>{p.request?.url}</pre>
      <div className={styles.inspActions}>
        <button className={`${styles.btn} ${styles.sm}`} onClick={() => copy(p.request?.url ?? "")}><Clipboard size={12} />URL</button>
        <button className={`${styles.btn} ${styles.sm}`} onClick={() => copy(toCurl(e))}><Terminal size={12} />cURL</button>
      </div>
      <div className={styles.seg}>
        <button className={tab === "req" ? styles.segOn : ""} onClick={() => setTab("req")}>{t("الطلب", "Request")}</button>
        <button className={tab === "res" ? styles.segOn : ""} onClick={() => setTab("res")}>{t("الاستجابة", "Response")}</button>
        <button className={tab === "raw" ? styles.segOn : ""} onClick={() => setTab("raw")}>JSON</button>
      </div>
      {tab === "req" && <><h4>Headers</h4><KV data={p.request?.headers} /><h4>Body</h4><BodyBlock body={p.request?.body} headers={p.request?.headers} /></>}
      {tab === "res" && (p.error ? <div className={styles.errBox}><AlertTriangle size={14} />{p.error}</div> : p.response ? <>
        <h4>Headers</h4><KV data={p.response.headers} />
        <h4>Body</h4><BodyBlock body={p.response.body} headers={p.response.headers} />
        {p.response.remote_ip && <p className={styles.dim}>remote {p.response.remote_ip}</p>}
      </> : <p className={styles.dim}>{t("لم تصل استجابة بعد.", "No response yet.")}</p>)}
      {tab === "raw" && <pre className={styles.code2}>{JSON.stringify(p, null, 2)}</pre>}
    </div>;
  }
  if (e.event_type === "command") {
    return <div className={styles.insp}>{head}
      <h4>{t("الأمر", "Command")}</h4><pre className={styles.code2}>{p.command}</pre>
      <div className={styles.inspActions}><button className={`${styles.btn} ${styles.sm}`} onClick={() => copy(String(p.command ?? ""))}><Clipboard size={12} />{t("نسخ", "Copy")}</button></div>
      <table className={styles.kv}><tbody>
        <tr><th>timeout</th><td>{p.timeout_seconds ?? "—"}s</td></tr>
        {p.cwd && <tr><th>cwd</th><td>{p.cwd}</td></tr>}
        <tr><th>argv</th><td>{(p.argv ?? []).length} args</td></tr>
      </tbody></table>
      <h4>argv</h4><pre className={styles.code2}>{(p.argv ?? []).map((a: string, i: number) => `[${i}] ${a}`).join("\n")}</pre>
    </div>;
  }
  return <div className={styles.insp}>{head}
    <h4>{t("الرسالة", "Message")}</h4><pre className={styles.code2}>{e.message}</pre>
    {Object.keys(p).length > 0 && <><h4>Payload</h4><pre className={styles.code2}>{JSON.stringify(p, null, 2)}</pre></>}
  </div>;
}
