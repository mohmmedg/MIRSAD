import { Activity, Code2, ListChecks, ShieldCheck, X } from "lucide-react";
import { Link } from "react-router-dom";
import { useLanguage } from "../i18n/LanguageContext";
import { useScan } from "../context/ScanContext";

export function ActiveScanBar() {
  const { language } = useLanguage();
  const { unified, activeScanId, clearCurrentScan } = useScan();
  if (!unified || !activeScanId) return null;
  const ar = language === "ar";
  return (
    <div dir={ar ? "rtl" : "ltr"} style={{display:"flex",alignItems:"center",gap:10,padding:"7px 18px",borderBottom:"1px solid var(--line)",background:"var(--bg-panel-raised)",minHeight:38,boxSizing:"border-box"}}>
      <Activity size={14} style={{color:"var(--accent-action)",flexShrink:0}}/>
      <span style={{color:"var(--text-faint)",font:"600 9px var(--font-mono)",letterSpacing:".08em"}}>{ar ? "الفحص المحدد" : "SELECTED SCAN"}</span>
      <strong className="ltr" style={{fontSize:11,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"30vw"}}>{unified.target}</strong>
      <code className="ltr" style={{color:"var(--text-faint)",fontSize:9,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"24vw"}}>{activeScanId}</code>
      <span style={{marginInlineStart:"auto",display:"flex",gap:6}}>
        <Link to={`/raw-results/${encodeURIComponent(activeScanId)}`} title={ar ? "البيانات الخام" : "Raw data"} style={{display:"inline-flex",alignItems:"center",gap:5,padding:"5px 8px",border:"1px solid var(--line)",borderRadius:7,background:"var(--bg-panel)",color:"var(--text-muted)",fontSize:10}}><Code2 size={12}/>{ar ? "خام" : "Raw"}</Link>
        <Link to="/defectdojo" title={ar ? "اكتشافات هذا الفحص في DefectDojo" : "This scan's findings in DefectDojo"} style={{display:"inline-flex",alignItems:"center",gap:5,padding:"5px 8px",border:"1px solid var(--line)",borderRadius:7,background:"var(--bg-panel)",color:"var(--text-muted)",fontSize:10}}><ShieldCheck size={12}/>DefectDojo</Link>
        <Link to={`/scan-execution/${encodeURIComponent(activeScanId)}`} title={ar ? "تنفيذ الفحص" : "Scan execution"} style={{display:"inline-flex",alignItems:"center",gap:5,padding:"5px 8px",border:"1px solid var(--line)",borderRadius:7,background:"var(--bg-panel)",color:"var(--text-muted)",fontSize:10}}><ListChecks size={12}/>{ar ? "التنفيذ" : "Execution"}</Link>
        <button onClick={() => void clearCurrentScan()} title={ar ? "إلغاء تحديد الفحص" : "Clear selected scan"} style={{display:"inline-grid",placeItems:"center",width:27,height:27,border:"1px solid var(--line)",borderRadius:7,background:"var(--bg-panel)",color:"var(--text-faint)"}}><X size={13}/></button>
      </span>
    </div>
  );
}
