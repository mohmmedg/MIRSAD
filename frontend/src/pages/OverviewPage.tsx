import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  Bot,
  Boxes,
  Code2,
  Gauge,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
} from "lucide-react";
import { useScan } from "../context/ScanContext";
import { useLanguage } from "../i18n/LanguageContext";
import { useDerivedScanStats } from "../utils/scanStats";
import { SEVERITY_ORDER, type Severity } from "../types/api";
import { MirsadMark } from "../components/MirsadMark";
import { getOrganizationScore, type OrganizationScoreResponse } from "../api/client";
import shell from "../App.module.css";
import styles from "../components/UnifiedDashboard.module.css";

const SEV_CLASS: Record<Severity, string> = {
  Critical: styles.critical,
  High: styles.high,
  Medium: styles.medium,
  Low: styles.low,
  Info: styles.info,
};

function OrganizationScoreCard() {
  const { language } = useLanguage();
  const [data, setData] = useState<OrganizationScoreResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getOrganizationScore()
      .then((res) => { if (!cancelled) setData(res); })
      .catch(() => { if (!cancelled) setData(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  if (loading || !data || data.asset_count === 0 || !Number.isFinite(data.score)) return null;

  const score = Math.min(100, Math.max(0, data.score));
  const assets = Array.isArray(data.assets)
    ? data.assets.filter((asset) => Number.isFinite(asset.score))
    : [];

  return (
    <section className={`${styles.card} ${styles.organizationScoreCard}`}>
      <div className={styles.cardHeader}>
        <Gauge size={15} />
        <span>{language === "ar" ? "مؤشر المخاطر التنظيمية" : "Organization risk score"}</span>
        <span className={styles.cardMeta}>
          {data.asset_count} {language === "ar" ? "أصل" : "assets"}
        </span>
      </div>

      <div className={styles.organizationScoreSummary}>
        <div>
          <span className={styles.organizationScoreLabel}>
            {language === "ar" ? "المتوسط المرجّح لمخاطر جميع الأصول" : "Weighted risk average across all assets"}
          </span>
          <p className={styles.organizationScoreHint}>
            {language === "ar" ? "كلما ارتفعت الدرجة زادت المخاطر" : "Higher scores indicate greater risk"}
          </p>
        </div>
        <strong className={styles.organizationScoreValue}>
          {Math.round(score)}
          <small>/100</small>
        </strong>
      </div>

      {assets.length > 0 && (
        <div className={styles.organizationAssets}>
          {assets.slice(0, 5).map((asset) => {
            const assetScore = Math.min(100, Math.max(0, asset.score));
            const severityClass = assetScore >= 70
              ? styles.critical
              : assetScore >= 40
                ? styles.high
                : styles.low;

            return (
              <div className={styles.organizationAssetRow} key={asset.scan_id ?? asset.target}>
                <span className={`ltr ${styles.organizationAssetTarget}`} title={asset.target}>
                  {asset.target}
                </span>
                <div
                  className={styles.barTrack}
                  role="progressbar"
                  aria-label={`${asset.target} risk score`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(assetScore)}
                >
                  <div
                    className={`${styles.barFill} ${severityClass}`}
                    style={{ width: `${assetScore}%` }}
                  />
                </div>
                <b className={styles.organizationAssetValue}>{Math.round(assetScore)}</b>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

export function OverviewPage() {
  const { language } = useLanguage();
  const navigate = useNavigate();
  const { unified } = useScan();
  const stats = useDerivedScanStats(unified);

  return (
    <section className="animateIn">
      <OrganizationScoreCard />
      {!unified && (
        <div className={shell.hero}>
          <div className={shell.heroCopy}>
            <h1>{language === "ar" ? "مرصاد — عين واحدة على كل نقاط ضعفك" : "MIRSAD — one console for your whole attack surface"}</h1>
            <p>
              {language === "ar"
                ? "مرصاد منصة فحص أمني موحّدة تجمع ثلاثة محركات فحص مستقلة — الشبكة (Nmap)، الويب (زحف + فحوصات ثغرات + Templates)، وأمن الـ API (OpenAPI/GraphQL/JWT) — ثم تُرابط نتائجها في صورة واحدة: أصول مكتشفة، سطح هجوم، اكتشافات مُرتّبة حسب الخطورة، ودرجة مخاطر إجمالية. يمكنك تشغيل كل محرك منفرداً لهدف سريع، أو تشغيل \"فحص شامل\" يجمعها كلها ويولّد تقريراً جاهزاً للمشاركة."
                : "MIRSAD is a unified security scanning console that combines three independent engines — network (Nmap), web (crawl + vulnerability checks + templates), and API security (OpenAPI/GraphQL/JWT) — then correlates their output into one picture: discovered assets, attack surface, severity-ranked findings, and an overall risk score. Run any engine on its own for a quick check, or run a Full Assessment that combines all three and produces a shareable report."}
            </p>
            <div className={shell.heroActions}>
              <span>
                <ShieldCheck size={14} /> {language === "ar" ? "أدلة أولاً" : "Evidence-first"}
              </span>
              <span>
                <Bot size={14} /> {language === "ar" ? "تحقّق بالذكاء الاصطناعي" : "AI-assisted validation"}
              </span>
              <span>
                <Activity size={14} /> {language === "ar" ? "جاهز للمراقبة المستمرة" : "Continuous-ready"}
              </span>
            </div>
            <ul className={shell.heroList}>
              <li>{language === "ar" ? "الفحوصات تعمل فقط على الأهداف التي أضفتها إلى قائمة النطاق المصرّح به." : "Scans only ever run against targets you've explicitly added to the allowed scope."}</li>
              <li>{language === "ar" ? "كل اكتشاف مرفق بدليله (الطلب/الاستجابة أو المخرج الخام) لتقليل النتائج الوهمية." : "Every finding carries its raw evidence (request/response or scanner output) to keep false positives low."}</li>
              <li>{language === "ar" ? "التقارير قابلة للتصدير ومناسبة لمشاركتها مع فِرق تقنية أو غير تقنية." : "Reports export cleanly and adapt to both technical and non-technical audiences."}</li>
            </ul>
            <button className={shell.heroCta} onClick={() => navigate("/scans")}>
              {language === "ar" ? "ابدأ فحصاً الآن" : "Start a scan"}
            </button>
          </div>
          <div className={shell.heroOrb}>
            <MirsadMark size={190} />
          </div>
        </div>
      )}

      {unified && (
        <>
          <div className={styles.dashboardHeader}>
            <div>
              <div className={styles.kicker}>
                <Sparkles size={13} />
                {language === "ar" ? "مركز القيادة" : "COMMAND CENTER"}
              </div>
              <h2 className={styles.title}>{language === "ar" ? "نظرة عامة على الفحص" : "Scan overview"}</h2>
              <p className={styles.subtitle}>
                <span className="ltr">{unified.target}</span> · {unified.scan_id}
              </p>
            </div>
            <div className={styles.scanState}>
              <span className={unified.status === "completed" ? styles.okDot : styles.liveDot} />
              <span className="ltr">{String(unified.status).toUpperCase()}</span>
            </div>
          </div>

          <div className={styles.metricGrid}>
            <div className={`${styles.metricCard} ${styles.primaryMetric}`}>
              <span className={styles.metricLabel}>
                <ShieldAlert size={13} /> {language === "ar" ? "درجة المخاطر" : "Risk score"}
              </span>
              <strong className={styles.metricValue}>
                {Math.round(unified.risk_score)}
                <small>/100</small>
              </strong>
              <span className={styles.metricHint}>
                {unified.risk_score >= 70
                  ? language === "ar"
                    ? "يحتاج إجراء سريع"
                    : "Action required"
                  : language === "ar"
                    ? "ضمن النطاق"
                    : "Within monitored range"}
              </span>
            </div>

            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>
                <Siren size={13} /> {language === "ar" ? "الاكتشافات" : "Findings"}
              </span>
              <strong className={styles.metricValue}>{unified.findings.length}</strong>
              <span className={styles.metricHint}>
                {stats.severityCounts.Critical ?? 0} critical · {stats.severityCounts.High ?? 0} high
              </span>
            </div>

            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>
                <Boxes size={13} /> {language === "ar" ? "الأصول" : "Assets"}
              </span>
              <strong className={styles.metricValue}>{unified.assets.length}</strong>
              <span className={styles.metricHint}>{stats.dnsAddresses.length} IPs discovered</span>
            </div>

            <div className={styles.metricCard}>
              <span className={styles.metricLabel}>
                <Code2 size={13} /> {language === "ar" ? "نقاط النهاية" : "Endpoints"}
              </span>
              <strong className={styles.metricValue}>{stats.totalEndpoints}</strong>
              <span className={styles.metricHint}>{stats.services} network services</span>
            </div>
          </div>

          <div className={styles.twoCol}>
            <div className={styles.card}>
              <div className={styles.cardHeader}>
                <Activity size={15} />
                <span>{language === "ar" ? "توزيع المخاطر" : "Risk distribution"}</span>
                <span className={styles.cardMeta}>{unified.findings.length} findings</span>
              </div>
              <div className={styles.riskBars}>
                {SEVERITY_ORDER.map((sev) => {
                  const count = stats.severityCounts[sev] ?? 0;
                  const pct = unified.findings.length ? Math.max(3, (count / unified.findings.length) * 100) : 3;
                  return (
                    <div className={styles.riskBarRow} key={sev}>
                      <span className={`${styles.sevDot} ${SEV_CLASS[sev]}`} />
                      <span>{sev}</span>
                      <div className={styles.barTrack}>
                        <div className={`${styles.barFill} ${SEV_CLASS[sev]}`} style={{ width: `${pct}%` }} />
                      </div>
                      <b>{count}</b>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className={styles.card}>
              <div className={styles.cardHeader}>
                <Activity size={15} />
                <span>{language === "ar" ? "خط أنابيب الفحص" : "Scan pipeline"}</span>
                <span className={styles.progressLabel}>{stats.progress}%</span>
              </div>
              <div className={styles.progressTrack}>
                <span style={{ width: `${stats.progress}%` }} />
              </div>
              <div className={styles.pipeline}>
                {[
                  ["Discovery", stats.completedModules > 0],
                  ["Network", unified.network_scan?.status === "completed"],
                  ["Web", unified.web_scan?.status === "completed"],
                  ["API", unified.api_scan?.status === "completed"],
                  ["Normalization", unified.status === "completed"],
                  ["Risk", unified.status === "completed"],
                  ["Gemini", false],
                  ["Report", false],
                ].map(([label, done], index) => (
                  <div key={String(label)} className={styles.pipelineItem}>
                    <span
                      className={
                        done ? styles.pipelineDone : index <= stats.completedModules ? styles.pipelineActive : styles.pipelinePending
                      }
                    >
                      {done ? "✓" : index <= stats.completedModules ? "●" : "○"}
                    </span>
                    <span>{String(label)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
