import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, CalendarClock, CheckCircle2, Clock3, ExternalLink, Filter, History, Search, ShieldAlert, ShieldCheck, Trash2, XCircle, Code2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { deleteScan, type ScanHistoryRecord } from "../api/client";
import { ACTIVE_SCAN_KEY, LAST_SCAN_KEY, readScanKey, removeScanKey } from "../utils/scanTracking";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";
import { PageHeader } from "../components/PageHeader";
import styles from "./ScanHistoryPage.module.css";
import { describeRequestError, safeUserError } from "../utils/security";

function formatDate(value: string | null | undefined, ar: boolean) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat(ar ? "ar-SA" : "en-US", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
  } catch { return value; }
}

function statusMeta(status: string, ar: boolean) {
  const key = status.toLowerCase();
  if (key === "completed") return { label: ar ? "مكتمل" : "Completed", className: "ok" };
  if (key === "partial") return { label: ar ? "جزئي" : "Partial", className: "warn" };
  if (key === "failed") return { label: ar ? "فشل" : "Failed", className: "danger" };
  if (key === "cancelled") return { label: ar ? "ملغى" : "Cancelled", className: "muted" };
  if (key === "running") return { label: ar ? "جارٍ" : "Running", className: "warn" };
  if (key === "pending") return { label: ar ? "بالانتظار" : "Pending", className: "warn" };
  return { label: status, className: "muted" };
}

function durationLabel(start: string | null | undefined, end: string | null | undefined, ar: boolean) {
  if (!start) return "—";
  const seconds = Math.max(0, Math.round(((end ? new Date(end) : new Date()).getTime() - new Date(start).getTime()) / 1000));
  if (seconds < 60) return ar ? `${seconds}ث` : `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return ar ? `${minutes}د ${rest}ث` : `${minutes}m ${rest}s`;
}

export function ScanHistoryPage() {
  const { language } = useLanguage();
  const ar = language === "ar";
  const navigate = useNavigate();
  const { getCachedScanHistory, loadScanHistory, selectScan, invalidateScanHistory } = useScan();
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanHistoryRecord[]>([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const pageSize = 50;

  useEffect(() => {
    setPage(0);
  }, [query, status]);

  const historyKey = useMemo(() => `${pageSize}|${page}|${query.trim()}|${status}`, [page, query, status]);

  useEffect(() => {
    const cached = getCachedScanHistory(historyKey);
    // Render the last successful result immediately. Returning to this route must
    // never blank the table while the server is being revalidated in the background.
    if (cached) {
      setScans(cached.scans);
      setTotal(cached.total);
      setLoading(false);
    } else {
      setLoading(true);
    }
    setError(null);
    let cancelled = false;
    loadScanHistory(historyKey, { limit: pageSize, offset: page * pageSize, q: query.trim(), status })
      .then((data) => {
        if (!cancelled) {
          setScans(data.scans);
          setTotal(data.total);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          // If cached data exists, keep showing it even when background refresh fails.
          if (!cached) setLoading(false);
          setError(safeUserError(e, ar ? "تعذر تحميل سجل الفحوصات" : "Unable to load scan history"));
        }
      });
    return () => { cancelled = true; };
  }, [ar, historyKey, page, query, status, getCachedScanHistory, loadScanHistory]);

  const remove = async (scan: ScanHistoryRecord) => {
    if (!window.confirm(ar ? `حذف هذا الفحص نهائيًا من السجل وقاعدة البيانات؟\n${scan.target}` : `Permanently delete this scan from history and the database?\n${scan.target}`)) return;
    setDeletingId(scan.scan_id); setError(null);
    try {
      await deleteScan(scan.scan_id);
      setScans((prev) => prev.filter((x) => x.scan_id !== scan.scan_id));
      setTotal((n) => Math.max(0, n - 1));
      invalidateScanHistory();
      try { localStorage.removeItem(`mirsad_exec_view_${scan.scan_id}`); } catch { /* ignore */ }
      for (const k of [ACTIVE_SCAN_KEY, LAST_SCAN_KEY]) if (readScanKey(k) === scan.scan_id) removeScanKey(k);
    } catch (e) {
      const code = (e as { status?: number } | null)?.status;
      setError(code === 409 ? (ar ? "الفحص ما زال نشطًا؛ ألغِه أولًا ثم احذفه." : "The scan is still active; cancel it first, then delete it.")
        : describeRequestError(e, ar ? "ar" : "en", ar ? "تعذر حذف الفحص" : "Unable to delete the scan"));
    } finally { setDeletingId(null); }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section className={`${styles.wrap} animateIn`}>
      <PageHeader
        icon={History}
        eyebrow={`MIRSAD / ${ar ? "السجل" : "HISTORY"}`}
        title={ar ? "سجل الفحوصات" : "Scan history"}
        description={ar ? "يعرض هذا السجل الفحوصات التي أنشأها حسابك فقط، مع حالتها ونتيجتها ومعلومات التنفيذ." : "Only scans created by your account are shown, with their status, results, and execution details."}
        actions={<div className={styles.count}>{total} <span>{ar ? "فحص محفوظ" : "stored scans"}</span></div>}
      />

      <div className={styles.toolbar}>
        <label className={styles.search}>
          <Search size={15} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={ar ? "ابحث بالهدف أو رقم الفحص…" : "Search target or scan ID…"} />
        </label>
        <label className={styles.filter}>
          <Filter size={14} />
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="all">{ar ? "كل الحالات" : "All statuses"}</option>
            <option value="completed">{ar ? "مكتمل" : "Completed"}</option>
            <option value="partial">{ar ? "جزئي" : "Partial"}</option>
            <option value="running">{ar ? "جارٍ" : "Running"}</option>
            <option value="pending">{ar ? "بالانتظار" : "Pending"}</option>
            <option value="failed">{ar ? "فشل" : "Failed"}</option>
            <option value="cancelled">{ar ? "ملغى" : "Cancelled"}</option>
          </select>
        </label>
      </div>

      {error && <div className={styles.error}><XCircle size={16} /> {error}</div>}

      {loading ? (
        <div className={styles.loading}><div /><div /><div /><div /></div>
      ) : scans.length === 0 ? (
        <div className={styles.empty}>
          <History size={28} />
          <h2>{query || status !== "all" ? (ar ? "لا توجد نتائج مطابقة" : "No matching scans") : (ar ? "لا توجد فحوصات محفوظة بعد" : "No scans recorded yet")}</h2>
          <p>{ar ? "كل عملية فحص تُحفظ كسجل مستقل في قاعدة البيانات، ولا تعتمد هذه الصفحة على آخر فحص فقط." : "Every scan attempt is stored as an independent database record and does not replace the dashboard's initial state."}</p>
          <button onClick={() => navigate("/scans")}>{ar ? "ابدأ فحصًا" : "Start a scan"}<ArrowUpRight size={14} /></button>
        </div>
      ) : (
        <div className={styles.tableWrap}>
          <div className={styles.tableHead}>
            <span>{ar ? "الهدف" : "Target"}</span>
            <span>{ar ? "النوع" : "Type"}</span>
            <span>{ar ? "الحالة" : "Status"}</span>
            <span>{ar ? "المخاطر" : "Risk"}</span>
            <span>{ar ? "الاكتشافات" : "Findings"}</span>
            <span>{ar ? "المدة" : "Duration"}</span>
            <span>{ar ? "تاريخ التنفيذ" : "Executed"}</span>
            <span />
          </div>
          {scans.map((scan) => {
            const meta = statusMeta(scan.status, ar);
            return (
              <article key={scan.scan_id} className={styles.row}>
                <div className={styles.target}>
                  <strong className="ltr">{scan.target}</strong>
                  <code>{scan.scan_id}</code>
                </div>
                <span className={styles.kind}>{scan.scan_kind ?? "full"}</span>
                <span className={`${styles.status} ${styles[meta.className]}`}>
                  {meta.className === "ok" ? <CheckCircle2 size={13} /> : meta.className === "danger" ? <XCircle size={13} /> : <Clock3 size={13} />}
                  {meta.label}
                </span>
                <div className={styles.risk}><b>{scan.risk_score == null ? "—" : Math.round(scan.risk_score)}</b><span>{scan.risk_score == null ? "" : "/100"}</span></div>
                <span className={styles.findings}><ShieldAlert size={13} /> {scan.findings_count}</span>
                <span className={styles.duration}><Clock3 size={13} /> {durationLabel(scan.started_at, scan.finished_at, ar)}</span>
                <span className={styles.date}><CalendarClock size={13} /> {formatDate(scan.finished_at ?? scan.started_at, ar)}</span>
                <div className={styles.rowActions}>
                  {scan.result ? (
                    <>
                      <button className={styles.rawButton} onClick={() => { selectScan(scan.result!, scan.scan_id); navigate("/defectdojo"); }} title={ar ? "اكتشافات هذا الفحص في DefectDojo" : "This scan's findings in DefectDojo"}>
                        <ShieldCheck size={14} /> DefectDojo
                      </button>
                      <button className={styles.rawButton} onClick={() => { selectScan(scan.result!, scan.scan_id); navigate(`/raw-results/${encodeURIComponent(scan.scan_id)}`); }} title={ar ? "عرض جميع النتائج الخام بدون تعديل" : "View complete unmodified raw results"}>
                        <Code2 size={14} /> {ar ? "خام" : "Raw"}
                      </button>
                      <button className={styles.open} onClick={() => { selectScan(scan.result!, scan.scan_id); navigate(`/attack-surface-intelligence/${encodeURIComponent(scan.scan_id)}`); }} title={ar ? "فتح تفاصيل الفحص" : "Open scan intelligence"} aria-label={ar ? "فتح تفاصيل الفحص" : "Open scan intelligence"}><ExternalLink size={15} /></button>
                    </>
                  ) : (
                    <span className={styles.openDisabled} title={safeUserError(scan.error_message, ar ? "لا توجد نتيجة" : "No result")} aria-label={ar ? "لا توجد نتيجة" : "No result"}><XCircle size={14} /></span>
                  )}
                  <button className={styles.deleteButton} disabled={deletingId === scan.scan_id} onClick={() => void remove(scan)} title={ar ? "حذف الفحص نهائيًا" : "Delete scan permanently"} aria-label={ar ? "حذف الفحص نهائيًا" : "Delete scan permanently"}><Trash2 size={14} /></button>
                </div>
              </article>
              
            );
          })}
        </div>
      )}

      {!loading && total > 0 && (
        <div className={styles.pagination}>
          <button disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>{ar ? "السابق" : "Previous"}</button>
          <span>{ar ? `صفحة ${page + 1} من ${totalPages}` : `Page ${page + 1} of ${totalPages}`}</span>
          <button disabled={page + 1 >= totalPages} onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}>{ar ? "التالي" : "Next"}</button>
        </div>
      )}
    </section>
  );
}
