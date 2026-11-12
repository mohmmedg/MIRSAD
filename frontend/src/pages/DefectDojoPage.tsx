import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Download, ExternalLink, RefreshCw, Search, ShieldCheck, X } from "lucide-react";
import {
  getDefectDojoDashboard,
  getDefectDojoFinding,
  getDefectDojoFindings,
  getScanDefectDojoStatus,
  resyncScanToDefectDojo,
  type DefectDojoDashboard,
  type DefectDojoFinding,
  type DefectDojoFindingDetail,
  type DefectDojoFindingsPage,
  type DefectDojoScanSyncStatus,
} from "../api/client";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";
import { PageHeader } from "../components/PageHeader";
import styles from "./DefectDojoPage.module.css";

const PAGE_SIZE = 25;
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
type Severity = (typeof SEVERITIES)[number];
type StateFilter = "active" | "closed" | "all";
type Order = "severity" | "newest" | "oldest";

const SEV_VAR: Record<Severity, string> = {
  Critical: "var(--sev-critical)",
  High: "var(--sev-high)",
  Medium: "var(--sev-medium)",
  Low: "var(--sev-low)",
  Info: "var(--sev-info)",
};
const SEV_AR: Record<Severity, string> = { Critical: "حرجة", High: "عالية", Medium: "متوسطة", Low: "منخفضة", Info: "معلوماتية" };
const asSeverity = (s: string): Severity => ((SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : "Info");

const fmt = (n: number | undefined | null) => (typeof n === "number" ? n.toLocaleString("en-US") : "—");

/** Cells starting with = + - @ are executed as formulas by spreadsheet apps. */
const csvCell = (v: unknown) => {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
};

export function DefectDojoPage() {
  const { language } = useLanguage();
  const ar = language === "ar";
  const t = (a: string, e: string) => (ar ? a : e);

  // Scope: the scan the workspace is on (opened from history / just finished) or ?scan=<id>.
  // "all" shows everything DefectDojo holds, as before. The user can switch at any time.
  const { activeScanId } = useScan();
  const [searchParams] = useSearchParams();
  const selectedScanId = searchParams.get("scan") || activeScanId || null;
  const [scope, setScope] = useState<"scan" | "all">("scan");
  const scanId = scope === "scan" ? selectedScanId : null;
  const [sync, setSync] = useState<DefectDojoScanSyncStatus | null>(null);
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncError, setSyncError] = useState("");

  const [dash, setDash] = useState<DefectDojoDashboard | null>(null);
  const [dashLoading, setDashLoading] = useState(true);
  const [list, setList] = useState<DefectDojoFindingsPage | null>(null);
  const [listLoading, setListLoading] = useState(true);
  const [products, setProducts] = useState<Array<{ id: number; name: string }>>([]);

  const [sev, setSev] = useState<Severity | null>(null);
  const [stateFilter, setStateFilter] = useState<StateFilter>("active");
  const [product, setProduct] = useState<number | "">("");
  const [order, setOrder] = useState<Order>("severity");
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);

  const [openId, setOpenId] = useState<number | null>(null);
  const [openRow, setOpenRow] = useState<DefectDojoFinding | null>(null);
  const [detail, setDetail] = useState<DefectDojoFindingDetail | null>(null);
  const [detailState, setDetailState] = useState<"idle" | "loading" | "error">("idle");
  const closeRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);

  const loadDash = useCallback(async (silent = false) => {
    if (!silent) setDashLoading(true);
    try { setDash(await getDefectDojoDashboard(scanId)); } catch { /* keep previous */ } finally { if (!silent) setDashLoading(false); }
  }, [scanId]);

  const loadList = useCallback(async (silent = false) => {
    if (!silent) setListLoading(true);
    try {
      const res = await getDefectDojoFindings({
        limit: PAGE_SIZE, offset: page * PAGE_SIZE, severity: sev ?? undefined, q: query || undefined,
        active: stateFilter === "all" ? undefined : stateFilter === "active",
        product: product === "" ? undefined : product, order, scanId,
      });
      setList(res);
      if (res.products?.length) setProducts(res.products);
    } catch {
      setList({ enabled: true, health: null, total: 0, limit: PAGE_SIZE, offset: 0, findings: [], error: "REQUEST_FAILED" });
    } finally { if (!silent) setListLoading(false); }
  }, [page, sev, query, stateFilter, product, order, scanId]);

  useEffect(() => {
    void loadDash();
    const id = window.setInterval(() => void loadDash(true), 30000);
    return () => window.clearInterval(id);
  }, [loadDash]);
  useEffect(() => { void loadList(); }, [loadList]);
  useEffect(() => { setPage(0); setProduct(""); }, [scanId]);

  // Sync state of the selected scan towards DefectDojo, to explain an empty list.
  const loadSync = useCallback(async () => {
    if (!scanId) { setSync(null); return; }
    try { setSync(await getScanDefectDojoStatus(scanId)); } catch { setSync(null); }
  }, [scanId]);
  useEffect(() => { void loadSync(); }, [loadSync]);
  const scopeSynced = dash?.scan_scope?.synced ?? list?.scan_scope?.synced;
  const jobStatus = sync?.jobs?.[0]?.status;
  const syncInFlight = jobStatus === "PENDING" || jobStatus === "RUNNING";
  useEffect(() => {
    // Poll only while the push is really queued/running (FAILED / DEAD_LETTER / no job never change on their own),
    // and refresh silently so the message and the list don't flicker.
    if (!scanId || scopeSynced !== false || !syncInFlight) return;
    const id = window.setInterval(() => { void loadSync(); void loadDash(true); void loadList(true); }, 10000);
    return () => window.clearInterval(id);
  }, [scanId, scopeSynced, syncInFlight, loadSync, loadDash, loadList]);
  const resync = async () => {
    if (!scanId) return;
    setSyncBusy(true); setSyncError("");
    try { await resyncScanToDefectDojo(scanId); await loadSync(); }
    catch { setSyncError(t("تعذّر طلب المزامنة. هذا الإجراء يتطلب صلاحية مدير.", "Couldn't request the sync. This action requires an admin role.")); }
    finally { setSyncBusy(false); }
  };

  // detail drawer
  useEffect(() => {
    if (openId == null) return;
    let cancelled = false;
    setDetail(null); setDetailState("loading");
    getDefectDojoFinding(openId)
      .then((d) => { if (!cancelled) { setDetail(d); setDetailState("idle"); } })
      .catch(() => { if (!cancelled) setDetailState("error"); });
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") closeDrawer(); };
    window.addEventListener("keydown", onKey);
    return () => { cancelled = true; window.removeEventListener("keydown", onKey); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openId]);

  const openDrawer = (f: DefectDojoFinding, el: HTMLElement) => { returnFocus.current = el; setOpenRow(f); setOpenId(f.id); };
  function closeDrawer() { setOpenId(null); setOpenRow(null); returnFocus.current?.focus(); }

  const refreshAll = () => { void loadDash(); void loadList(); };
  const base = (dash?.url || "http://localhost:8081").replace(/\/$/, "");
  const up = dash?.health === "AVAILABLE";
  const down = !!dash && !up;
  const counts = dash?.findings_by_severity ?? {};
  const sevTotal = SEVERITIES.reduce((s, k) => s + (counts[k] ?? 0), 0);
  const listError = list?.error;
  const filtered = !!(sev || query || stateFilter !== "active" || product !== "");
  const firstLoad = listLoading && !list;

  const stateOf = (f: { false_p?: boolean; duplicate?: boolean; risk_accepted?: boolean; mitigated?: string | null; active?: boolean }): [string, "active" | "done" | "other"] => {
    if (f.false_p) return [t("إيجابي كاذب", "False positive"), "other"];
    if (f.duplicate) return [t("مكرّرة", "Duplicate"), "other"];
    if (f.risk_accepted) return [t("مخاطرة مقبولة", "Risk accepted"), "other"];
    if (f.mitigated) return [t("عولجت", "Mitigated"), "done"];
    return f.active ? [t("نشطة", "Active"), "active"] : [t("غير نشطة", "Inactive"), "other"];
  };

  const ageText = (date: string | null) => {
    if (!date) return "—";
    const d = Math.floor((Date.now() - new Date(date + "T00:00:00").getTime()) / 86400000);
    if (!Number.isFinite(d) || d < 0) return date;
    if (d === 0) return t("اليوم", "Today");
    if (d === 1) return t("أمس", "Yesterday");
    return ar ? `منذ ${d} يومًا` : `${d} days ago`;
  };

  const pickSeverity = (k: Severity) => { setPage(0); setSev((cur) => (cur === k ? null : k)); };
  const clearFilters = () => { setSev(null); setQuery(""); setDraft(""); setStateFilter("active"); setProduct(""); setPage(0); };

  const exportCsv = () => {
    const rows = list?.findings ?? [];
    const head = ["id", "severity", "title", "product", "engagement", "test", "cve", "cwe", "component", "date", "state"];
    const body = rows.map((f) => [f.id, f.severity, f.title, f.product, f.engagement, f.test, f.cve, f.cwe, f.component, f.date, stateOf(f)[0]].map(csvCell).join(","));
    const blob = new Blob(["﻿" + [head.map(csvCell).join(","), ...body].join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `defectdojo-findings-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  const section = (title: string, body: string | null) =>
    body ? <section className={styles.dSection}><h3>{title}</h3><div className={styles.prose} dir="auto">{body}</div></section> : null;

  return (
    <section className={styles.page}>
      <PageHeader
        icon={ShieldCheck}
        eyebrow="DEFECTDOJO"
        title="DefectDojo"
        description={t("كل الاكتشافات التي رفعها مرصاد إلى DefectDojo، مرتبة من الأخطر إلى الأقل. اضغط على أي شدّة لتصفية القائمة، وعلى أي اكتشاف لقراءة تفاصيله.", "Every finding MIRSAD has pushed to DefectDojo. Select a severity to filter the list, or a finding to read its details.")}
        actions={<>
          <span className={styles.conn} data-state={up ? "up" : down ? "down" : "wait"} role="status">
            <i />{up ? t("متصل", "Connected") : down ? t("غير متاح", "Unavailable") : t("جارٍ التحقق", "Checking")}
          </span>
          <button className={styles.btn} onClick={refreshAll} disabled={dashLoading || listLoading}>
            <RefreshCw size={14} className={dashLoading || listLoading ? styles.spin : undefined} aria-hidden />{t("تحديث", "Refresh")}
          </button>
          <a className={`${styles.btn} ${styles.btnPrimary}`} href={base} target="_blank" rel="noreferrer">
            {t("فتح DefectDojo", "Open DefectDojo")}<ExternalLink size={14} aria-hidden />
          </a>
        </>}
      />

      {selectedScanId && (
        <div className={styles.notice} role="status" style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <span>
            {scanId
              ? <>{t("المعروض: اكتشافات الفحص", "Showing findings of scan")} <code dir="ltr">{scanId}</code></>
              : t("المعروض: كل ما في DefectDojo (كل الفحوصات)", "Showing everything in DefectDojo (all scans)")}
          </span>
          <button type="button" className={styles.btn} onClick={() => setScope((s) => (s === "scan" ? "all" : "scan"))}>
            {scanId ? t("عرض كل الفحوصات", "Show all scans") : t("عرض الفحص المحدد فقط", "Show selected scan only")}
          </button>
        </div>
      )}

      {down && (
        <div className={styles.notice} role="alert">
          <b>{t("تعذّر الاتصال بـ DefectDojo.", "Can't reach DefectDojo.")}</b>{" "}
          {dash?.health === "AUTH_ERROR"
            ? t("مفتاح API مرفوض. أنشئ مفتاحًا جديدًا من DefectDojo وضعه في DEFECTDOJO_API_TOKEN ثم أعد إنشاء backend وworker.", "The API key was rejected. Create a new key in DefectDojo, set DEFECTDOJO_API_TOKEN, then recreate backend and worker.")
            : t("تأكد أن الحاوية تعمل بحالة healthy (docker compose ps) ثم حدّث الصفحة.", "Check that the container is healthy (docker compose ps), then refresh.")}
        </div>
      )}

      <div className={styles.surface}>
        <div className={styles.posture}>
          <div>
            <h2 className={styles.postureTitle}>{t("توزيع الشدّة", "Severity breakdown")}</h2>
            <div className={styles.bar} data-empty={sevTotal === 0} role="img"
              aria-label={SEVERITIES.map((k) => `${ar ? SEV_AR[k] : k}: ${counts[k] ?? 0}`).join("، ")}>
              {sevTotal === 0 && <span />}
              {sevTotal > 0 && SEVERITIES.map((k) => (
                <span key={k} style={{ flexGrow: counts[k] ?? 0, flexBasis: 0, background: SEV_VAR[k], opacity: sev && sev !== k ? 0.25 : 1, display: (counts[k] ?? 0) === 0 ? "none" : undefined }} />
              ))}
            </div>
            <div className={styles.legend}>
              {SEVERITIES.map((k) => (
                <button key={k} type="button" className={styles.sevBtn} aria-pressed={sev === k} onClick={() => pickSeverity(k)} style={{ ["--c" as string]: SEV_VAR[k] }}>
                  <span>{ar ? SEV_AR[k] : k}</span><b>{fmt(counts[k] ?? 0)}</b>
                </button>
              ))}
            </div>
          </div>
          <dl className={styles.totals}>
            <div><dt>{t("المنتجات", "Products")}</dt><dd>{fmt(dash?.products)}</dd></div>
            <div><dt>{t("الارتباطات", "Engagements")}</dt><dd>{fmt(dash?.engagements)}</dd></div>
            <div><dt>{t("الاختبارات", "Tests")}</dt><dd>{fmt(dash?.tests)}</dd></div>
            <div><dt>{t("الاكتشافات", "Findings")}</dt><dd>{fmt(dash?.findings)}</dd></div>
          </dl>
        </div>

        <div className={styles.toolbar}>
          <form className={styles.search} role="search" onSubmit={(e) => { e.preventDefault(); setPage(0); setQuery(draft.trim()); }}>
            <Search size={15} aria-hidden />
            <input className={styles.input} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder={t("ابحث في عنوان الاكتشاف", "Search finding titles")} aria-label={t("بحث", "Search")} />
          </form>
          {!scanId && products.length > 1 && (
            <select className={styles.select} value={product} aria-label={t("المنتج", "Product")} onChange={(e) => { setPage(0); setProduct(e.target.value === "" ? "" : Number(e.target.value)); }}>
              <option value="">{t("كل المنتجات", "All products")}</option>
              {products.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )}
          <select className={styles.select} value={order} aria-label={t("الترتيب", "Sort")} onChange={(e) => { setPage(0); setOrder(e.target.value as Order); }}>
            <option value="severity">{t("الأخطر أولًا", "Most severe first")}</option>
            <option value="newest">{t("الأحدث أولًا", "Newest first")}</option>
            <option value="oldest">{t("الأقدم أولًا", "Oldest first")}</option>
          </select>
          <div className={styles.seg} role="group" aria-label={t("الحالة", "State")}>
            {([["active", t("نشطة", "Active")], ["closed", t("مغلقة", "Closed")], ["all", t("الكل", "All")]] as const).map(([k, label]) => (
              <button key={k} type="button" aria-pressed={stateFilter === k} onClick={() => { setPage(0); setStateFilter(k); }}>{label}</button>
            ))}
          </div>
          {filtered && <button type="button" className={styles.chipClear} onClick={clearFilters}><X size={13} aria-hidden />{t("مسح التصفية", "Clear filters")}</button>}
          <button type="button" className={`${styles.btn} ${styles.toolbarEnd}`} onClick={exportCsv} disabled={!list?.findings.length} title={t("تصدير الصفحة الحالية", "Export the current page")}>
            <Download size={14} aria-hidden />CSV
          </button>
        </div>

        {listError ? (
          <div className={styles.empty}>
            <h3>{t("تعذّر جلب الاكتشافات", "Couldn't load findings")}</h3>
            <p>{t("لم يرد DefectDojo على الطلب. تحقق من حالته ثم أعد المحاولة.", "DefectDojo didn't answer the request. Check its status and try again.")}</p>
            <button className={styles.btn} onClick={() => void loadList()}>{t("إعادة المحاولة", "Try again")}</button>
          </div>
        ) : firstLoad ? (
          <ul className={styles.list} aria-busy="true" aria-label={t("جارٍ التحميل", "Loading")}>
            {Array.from({ length: 6 }).map((_, i) => <li key={i} className={`${styles.row} ${styles.skel}`}><span /><span /><span /><span /><span /><span /></li>)}
          </ul>
        ) : list && !listLoading && list.findings.length === 0 ? (
          <div className={styles.empty}>
            <h3>{filtered ? t("لا توجد نتائج مطابقة", "No matching findings")
              : scanId && scopeSynced === false ? t("لم يصل هذا الفحص إلى DefectDojo بعد", "This scan hasn't reached DefectDojo yet")
              : scanId ? t("لا توجد اكتشافات لهذا الفحص", "No findings for this scan")
              : t("لا توجد اكتشافات بعد", "No findings yet")}</h3>
            <p>{filtered ? t("غيّر التصفية أو امسحها لعرض كل الاكتشافات.", "Change or clear the filters to see every finding.")
              : scanId && scopeSynced === false
                ? (() => {
                    const job = sync?.jobs?.[0];
                    const state = job ? `${job.status}${job.last_error_code ? ` — ${job.last_error_code}` : ""}` : t("لم تُسجَّل مزامنة", "no sync recorded");
                    return t(`حالة المزامنة: ${state}. يرفع مرصاد النتائج تلقائيًا بعد انتهاء الفحص؛ إن كان الفحص قديمًا أو فشلت المزامنة فاطلب مزامنته يدويًا.`, `Sync state: ${state}. MIRSAD pushes results automatically once a scan finishes; if the scan is older or the sync failed, request it manually.`);
                  })()
              : scanId ? t("اكتمل رفع هذا الفحص ولكنه لم ينتج اكتشافات.", "This scan was pushed but produced no findings.")
              : t("يرفع مرصاد النتائج إلى DefectDojo تلقائيًا عند انتهاء كل فحص. شغّل فحصًا وستظهر نتائجه هنا.", "MIRSAD pushes results to DefectDojo automatically when a scan finishes. Run a scan and its findings will appear here.")}</p>
            {syncError && <p role="alert">{syncError}</p>}
            {filtered ? <button className={styles.btn} onClick={clearFilters}>{t("مسح التصفية", "Clear filters")}</button>
              : scanId && scopeSynced === false ? <button className={`${styles.btn} ${styles.btnPrimary}`} onClick={() => void resync()} disabled={syncBusy}>{t("مزامنة هذا الفحص الآن", "Sync this scan now")}</button>
              : <Link className={`${styles.btn} ${styles.btnPrimary}`} to="/scans">{t("بدء فحص", "Start a scan")}</Link>}
          </div>
        ) : (
          <>
            <div className={styles.listHead} aria-hidden>
              <span>{t("الشدّة", "Severity")}</span><span>{t("الاكتشاف", "Finding")}</span><span>{t("المعرّف", "Reference")}</span>
              <span>{t("العمر", "Age")}</span><span>{t("الحالة", "State")}</span><span />
            </div>
            <ul className={styles.list} data-busy={listLoading}>
              {(list?.findings ?? []).map((f) => {
                const key = asSeverity(f.severity);
                const [stateText, stateKind] = stateOf(f);
                return (
                  <li key={f.id} className={styles.row} data-selected={openId === f.id} style={{ ["--c" as string]: SEV_VAR[key] }}
                    tabIndex={0} aria-haspopup="dialog"
                    onClick={(e) => openDrawer(f, e.currentTarget)}
                    onKeyDown={(e) => { if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openDrawer(f, e.currentTarget); } }}>
                    <span className={styles.sev}>{ar ? SEV_AR[key] : key}</span>
                    <div className={styles.what}>
                      <strong dir="auto">{f.title}</strong>
                      <div className={styles.where} dir="auto">
                        {[f.product, f.engagement, f.test, f.component].filter(Boolean).flatMap((x, i) => (i === 0 ? [<bdi key={i}>{x}</bdi>] : [<i key={`s${i}`} aria-hidden>/</i>, <bdi key={i}>{x}</bdi>]))}
                      </div>
                    </div>
                    <span className={styles.ref}>{f.cve ?? (f.cwe ? `CWE-${f.cwe}` : "—")}</span>
                    <span className={styles.date} title={f.date ?? undefined}>{ageText(f.date)}</span>
                    <span className={styles.state} data-s={stateKind}>{stateText}</span>
                    <a className={styles.open} href={`${base}/finding/${f.id}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
                      aria-label={t("فتح الاكتشاف في DefectDojo", "Open finding in DefectDojo")}><ArrowUpRight size={15} aria-hidden /></a>
                  </li>
                );
              })}
            </ul>
            {list && list.total > PAGE_SIZE && (
              <div className={styles.pager}>
                <button className={styles.btn} disabled={page === 0 || listLoading} onClick={() => setPage((p) => Math.max(0, p - 1))}>{t("السابق", "Previous")}</button>
                <span>{fmt(page * PAGE_SIZE + 1)}–{fmt(Math.min((page + 1) * PAGE_SIZE, list.total))} {t("من", "of")} {fmt(list.total)}</span>
                <button className={styles.btn} disabled={(page + 1) * PAGE_SIZE >= list.total || listLoading} onClick={() => setPage((p) => p + 1)}>{t("التالي", "Next")}</button>
              </div>
            )}
          </>
        )}
      </div>

      {(dash?.native_surfaces?.length ?? 0) > 0 && (
        <div className={styles.native}>
          <h2>{t("شاشات DefectDojo الكاملة", "Full DefectDojo screens")}</h2>
          <p>{t("التقارير والمقاييس وإدارة المستخدمين وبقية الميزات تبقى في واجهة DefectDojo الأصلية.", "Reports, metrics, user administration and the rest live in DefectDojo's own interface.")}</p>
          <nav className={styles.links} aria-label="DefectDojo">
            {dash!.native_surfaces.map((x) => (
              <a key={x.key} href={`${base}${x.path}`} target="_blank" rel="noreferrer"><span>{x.label}</span><ExternalLink size={13} aria-hidden /></a>
            ))}
          </nav>
        </div>
      )}

      {openId != null && (
        <>
          <div className={styles.backdrop} onClick={closeDrawer} aria-hidden />
          <aside className={styles.drawer} role="dialog" aria-modal="true" aria-label={openRow?.title ?? "Finding"}
            style={{ ["--c" as string]: SEV_VAR[asSeverity(detail?.severity ?? openRow?.severity ?? "Info")] }}>
            <header className={styles.dHead}>
              <div>
                <span className={styles.sev}>{ar ? SEV_AR[asSeverity(detail?.severity ?? openRow?.severity ?? "Info")] : asSeverity(detail?.severity ?? openRow?.severity ?? "Info")}</span>
                <h2 dir="auto">{detail?.title ?? openRow?.title}</h2>
              </div>
              <button ref={closeRef} className={styles.iconBtn} onClick={closeDrawer} aria-label={t("إغلاق", "Close")}><X size={18} aria-hidden /></button>
            </header>
            <div className={styles.dBody}>
              {detailState === "loading" && <p className={styles.mutedText}>{t("جارٍ تحميل التفاصيل…", "Loading details…")}</p>}
              {detailState === "error" && (
                <div className={styles.notice} role="alert"><b>{t("تعذّر تحميل التفاصيل.", "Couldn't load the details.")}</b> {t("أعد المحاولة أو افتح الاكتشاف في DefectDojo.", "Try again or open the finding in DefectDojo.")}</div>
              )}
              {(() => {
                const d = detail;
                const base0 = openRow;
                const [stText] = stateOf(d ? { active: d.active, mitigated: base0?.mitigated, false_p: base0?.false_p, duplicate: base0?.duplicate, risk_accepted: base0?.risk_accepted } : base0 ?? {});
                const facts: Array<[string, string | null | undefined]> = [
                  [t("المنتج", "Product"), base0?.product], [t("الارتباط", "Engagement"), base0?.engagement], [t("الاختبار", "Test"), base0?.test],
                  [t("الحالة", "State"), stText], [t("تاريخ الاكتشاف", "Found"), d?.date ?? base0?.date],
                  [t("العمر", "Age"), d?.age_days != null ? (ar ? `${d.age_days} يومًا` : `${d.age_days} days`) : null],
                  [t("مهلة المعالجة", "SLA"), d?.sla_days_remaining != null ? (d.sla_days_remaining < 0 ? (ar ? `متأخرة ${Math.abs(d.sla_days_remaining)} يومًا` : `${Math.abs(d.sla_days_remaining)} days overdue`) : (ar ? `${d.sla_days_remaining} يومًا متبقية` : `${d.sla_days_remaining} days left`)) : null],
                  ["CVSS", d?.cvss_score != null ? String(d.cvss_score) : null], ["EPSS", d?.epss_score != null ? `${(d.epss_score * 100).toFixed(1)}%` : null],
                  ["CVE", d?.cve_ids?.length ? d.cve_ids.join(", ") : null], ["CWE", d?.cwe ? `CWE-${d.cwe}` : null],
                  [t("المكوّن", "Component"), d?.component ? `${d.component}${d.component_version ? ` ${d.component_version}` : ""}` : base0?.component],
                  [t("الملف", "File"), d?.file_path ? `${d.file_path}${d.line ? `:${d.line}` : ""}` : null],
                ];
                return (
                  <>
                    <dl className={styles.facts}>
                      {facts.filter(([, v]) => v).map(([k, v]) => <div key={k}><dt>{k}</dt><dd><bdi>{v}</bdi></dd></div>)}
                    </dl>
                    {d?.tags?.length ? <div className={styles.tags}>{d.tags.map((x) => <span key={x}>{x}</span>)}</div> : null}
                    {d && !d.description && !d.mitigation && !d.impact && !d.references && !d.steps_to_reproduce &&
                      <p className={styles.mutedText}>{t("لا يحتوي هذا الاكتشاف على وصف نصي في DefectDojo.", "This finding has no written description in DefectDojo.")}</p>}
                    {section(t("الوصف", "Description"), d?.description ?? null)}
                    {section(t("الأثر", "Impact"), d?.impact ?? null)}
                    {section(t("خطوات إعادة الإنتاج", "Steps to reproduce"), d?.steps_to_reproduce ?? null)}
                    {section(t("المعالجة المقترحة", "Mitigation"), d?.mitigation ?? null)}
                    {section(t("مراجع", "References"), d?.references ?? null)}
                  </>
                );
              })()}
            </div>
            <footer className={styles.dFoot}>
              <a className={`${styles.btn} ${styles.btnPrimary}`} href={`${base}/finding/${openId}`} target="_blank" rel="noreferrer">{t("فتح في DefectDojo", "Open in DefectDojo")}<ExternalLink size={14} aria-hidden /></a>
              <button className={styles.btn} onClick={closeDrawer}>{t("إغلاق", "Close")}</button>
            </footer>
          </aside>
        </>
      )}
    </section>
  );
}
