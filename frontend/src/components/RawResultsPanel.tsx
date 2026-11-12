import { useMemo, useState } from "react";
import { CheckCircle2, Clipboard, Code2, Copy, AlertTriangle } from "lucide-react";
import type { ScanHistoryRecord } from "../api/client";
import styles from "./RawResultsPanel.module.css";

export function RawResultsPanel({ scan }: { scan: ScanHistoryRecord }) {
  const [copied, setCopied] = useState(false);
  const rawJson = useMemo(() => JSON.stringify(scan.result, null, 2), [scan.result]);
  const findings = scan.result?.findings ?? [];
  const quality = scan.result_quality;

  async function copyRaw() {
    try {
      await navigator.clipboard.writeText(rawJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {}
  }

  function downloadRaw() {
    const blob = new Blob([rawJson], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mirsad-${scan.scan_id}-raw.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <div>
          <div className={styles.kicker}><Code2 size={13}/> RAW / ORIGINAL</div>
          <h3>النتائج الخام الأصلية</h3>
          <p>هذا العرض يطبع النتيجة المحفوظة كما وصلت من الفحص، بدون حذف أو إخفاء أو إعادة تصنيف أو تعديل.</p>
        </div>
        <div className={styles.quality}>
          {quality?.status === "good" ? <CheckCircle2 size={14}/> : <AlertTriangle size={14}/>}
          {quality?.status ?? "raw"}
        </div>
      </div>

      <div className={styles.actions}>
        <button onClick={copyRaw}><Copy size={13}/> {copied ? "تم النسخ" : "نسخ JSON الكامل"}</button>
        <button onClick={downloadRaw}><Clipboard size={13}/> حفظ JSON الكامل</button>
      </div>

      <div className={styles.metrics}>
        <div><b>{findings.length}</b><span>Finding</span></div>
        <div><b>{scan.result?.warnings?.length ?? 0}</b><span>Warnings</span></div>
        <div><b>{quality?.active_check_count ?? "—"}</b><span>Active checks</span></div>
        <div><b>{scan.result?.coverage?.percentage != null ? `${Math.round(scan.result.coverage.percentage)}%` : "—"}</b><span>Coverage</span></div>
      </div>

      <pre className={styles.raw}>{rawJson}</pre>
    </div>
  );
}
