import { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck,
  GitBranch,
  Download,
  RefreshCw,
  Save,
  CheckCircle2,
  XCircle,
} from "lucide-react";

import {
  assessCompliance,
  getComplianceControls,
  getCIPolicy,
  updateCIPolicy,
  type ComplianceAssessment,
  type ComplianceControl,
  type CIPolicy,
  securityGateSarif,
} from "../api/client";

import { PageHeader } from "./PageHeader";
import { useLanguage } from "../i18n/LanguageContext";
import styles from "./ComplianceCenter.module.css";

type Props = {
  findings: Array<Record<string, unknown>>;
  // Scan coverage from the same scan the findings came from. When present, a control
  // with no matching findings can be resolved as a genuine PASS (the capability was
  // actually tested and came back clean) instead of always NOT_ASSESSED.
  coverage?: Record<string, unknown>;
};

type AssessmentControlView = {
  control_id: string;
  title: string;
  status: string;
  evidence_count: number;
};

function toAssessmentControl(value: unknown): AssessmentControlView {
  if (!value || typeof value !== "object") {
    return {
      control_id: "unknown",
      title: "Unknown control",
      status: "unknown",
      evidence_count: 0,
    };
  }

  const item = value as Record<string, unknown>;

  return {
    control_id:
      typeof item.control_id === "string"
        ? item.control_id
        : String(item.control_id ?? "unknown"),

    title:
      typeof item.title === "string"
        ? item.title
        : String(item.title ?? "Unknown control"),

    status:
      typeof item.status === "string"
        ? item.status
        : String(item.status ?? "unknown"),

    evidence_count:
      typeof item.evidence_count === "number"
        ? item.evidence_count
        : Number(item.evidence_count ?? 0),
  };
}

export function ComplianceCenter({ findings, coverage }: Props) {
  const { language } = useLanguage();
  const ar = language === "ar";
  const tr = (en: string, arabic: string) => (ar ? arabic : en);
  const statusLabel = (status: string) =>
    ar ? ({ pass: "ناجح", fail: "فاشل", observed: "مرصود", not_assessed: "غير مقيَّم", unknown: "غير معروف" } as Record<string, string>)[status] ?? status : status;
  const [framework, setFramework] = useState("all");

  const [controls, setControls] = useState<ComplianceControl[]>([]);

  const [assessment, setAssessment] =
    useState<ComplianceAssessment | null>(null);

  const [policy, setPolicy] = useState<CIPolicy>({
    critical_fail: 0,
    high_fail: 0,
    medium_fail: 0,
    enabled: true,
  });

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setError("");

      const [controlsResponse, policyResponse] = await Promise.all([
        getComplianceControls(
          framework === "all" ? undefined : framework
        ),
        getCIPolicy(),
      ]);

      setControls(controlsResponse.controls);
      setPolicy(policyResponse);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : tr("Unable to load compliance data", "تعذّر تحميل بيانات الامتثال")
      );
    }
  }, [framework, ar]);

  useEffect(() => {
    // Standard fetch-on-mount/dependency-change pattern: `load` sets loading
    // state from an async API call, not a synchronous derived-state update.
    // oxlint-disable-next-line react/set-state-in-effect
    void load();
  }, [load]);

  async function run() {
    setBusy(true);
    setError("");

    try {
      const result = await assessCompliance(
        findings,
        framework === "all" ? undefined : framework,
        coverage
      );

      setAssessment(result);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : tr("Assessment failed", "فشل التقييم")
      );
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setError("");

    try {
      const updated = await updateCIPolicy(policy);
      setPolicy(updated);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : tr("Policy update failed", "فشل تحديث السياسة")
      );
    } finally {
      setBusy(false);
    }
  }

  async function sarif() {
    try {
      setError("");

      const result = await securityGateSarif(findings);

      const blob = new Blob(
        [JSON.stringify(result, null, 2)],
        {
          type: "application/sarif+json",
        }
      );

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");

      anchor.href = url;
      anchor.download = "security-results.sarif";

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      URL.revokeObjectURL(url);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "SARIF export failed"
      );
    }
  }

  const assessmentControls: AssessmentControlView[] =
    assessment &&
    Array.isArray(assessment.controls)
      ? assessment.controls.map(toAssessmentControl)
      : [];

  return (
    <div className={styles.wrap}>
      <PageHeader
        icon={ShieldCheck}
        eyebrow="COMPLIANCE & CI/CD"
        title={tr("Compliance Center", "مركز الامتثال")}
        description={tr("Deterministic findings are mapped to controls. Gemini never decides pass/fail.", "تُربط الاكتشافات القطعية بالضوابط، ولا يقرر Gemini النجاح أو الفشل أبدًا.")}
        actions={
          <button className={styles.refreshBtn} onClick={() => void load()} disabled={busy}>
            <RefreshCw size={14} />
            {tr("Refresh", "تحديث")}
          </button>
        }
      />

      {error && (
        <div className={styles.error}>
          {error}
        </div>
      )}

      <div className={styles.toolbar}>
        <select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          disabled={busy}
        >
          <option value="all">{tr("All frameworks", "كل الأطر")}</option>
          <option value="OWASP ASVS">OWASP ASVS</option>
          <option value="OWASP API Security">
            OWASP API Security
          </option>
          <option value="NIST CSF">NIST CSF</option>
          <option value="CIS Controls">
            CIS Controls
          </option>
          <option value="Custom">Custom</option>
        </select>

        <button
          onClick={() => void run()}
          disabled={busy}
        >
          <ShieldCheck size={14} />
          {tr(`Assess ${findings.length} findings`, `تقييم ${findings.length} اكتشافًا`)}
        </button>

        <button
          onClick={() => void sarif()}
          disabled={busy}
        >
          <Download size={14} />
          {tr("Export SARIF", "تصدير SARIF")}
        </button>
      </div>

      {assessment && (
        <div className={styles.stats}>
          <div>
            <b>{assessment.score}%</b>
            <span>{tr("Compliance score", "درجة الامتثال")}</span>
          </div>

          <div>
            <b>{assessment.passed}</b>
            <span>{tr("Passed / observed", "ناجح / مرصود")}</span>
          </div>

          <div>
            <b>{assessment.failed}</b>
            <span>{tr("Failed controls", "ضوابط فاشلة")}</span>
          </div>
        </div>
      )}

      <div className={styles.grid}>
        <div className={styles.card}>
          <h4>{tr("Control catalog", "كتالوج الضوابط")}</h4>

          {controls.length === 0 ? (
            <p>{tr("No compliance controls found.", "لا توجد ضوابط امتثال.")}</p>
          ) : (
            controls.map((control) => (
              <div
                className={styles.control}
                key={String(control.control_id)}
              >
                <div>
                  <b>
                    {String(control.control_id)}
                  </b>

                  <span>
                    {String(control.title)}
                  </span>

                  <small>
                    {String(control.framework)}
                  </small>
                </div>

                <span
                  className={
                    control.enabled
                      ? styles.on
                      : styles.off
                  }
                >
                  {control.enabled
                    ? tr("Enabled", "مفعّل")
                    : tr("Disabled", "معطّل")}
                </span>
              </div>
            ))
          )}
        </div>

        <div className={styles.card}>
          <h4>
            <GitBranch size={15} />
            {tr("CI/CD Security Gate", "بوابة أمان CI/CD")}
          </h4>

          <p>
            {tr(
              "Pull requests can fail on deterministic severity thresholds and upload SARIF to GitHub Code Scanning.",
              "يمكن إفشال طلبات الدمج عند تجاوز حدود الخطورة القطعية، ورفع SARIF إلى GitHub Code Scanning."
            )}
          </p>

          <label>
            {tr("Critical allowed", "الحرجة المسموحة")}

            <input
              type="number"
              min="0"
              value={policy.critical_fail}
              onChange={(e) =>
                setPolicy({
                  ...policy,
                  critical_fail: Number(
                    e.target.value
                  ),
                })
              }
              disabled={busy}
            />
          </label>

          <label>
            {tr("High allowed", "العالية المسموحة")}

            <input
              type="number"
              min="0"
              value={policy.high_fail}
              onChange={(e) =>
                setPolicy({
                  ...policy,
                  high_fail: Number(
                    e.target.value
                  ),
                })
              }
              disabled={busy}
            />
          </label>

          <label>
            {tr("Medium allowed", "المتوسطة المسموحة")}

            <input
              type="number"
              min="0"
              value={policy.medium_fail}
              onChange={(e) =>
                setPolicy({
                  ...policy,
                  medium_fail: Number(
                    e.target.value
                  ),
                })
              }
              disabled={busy}
            />
          </label>

          <label className={styles.toggle}>
            <input
              type="checkbox"
              checked={policy.enabled}
              onChange={(e) =>
                setPolicy({
                  ...policy,
                  enabled: e.target.checked,
                })
              }
              disabled={busy}
            />

            {tr("Gate enabled", "البوابة مفعّلة")}
          </label>

          <button
            onClick={() => void save()}
            disabled={busy}
          >
            <Save size={14} />
            {tr("Save gate policy", "حفظ سياسة البوابة")}
          </button>
        </div>
      </div>

      {assessment && (
        <div className={styles.card}>
          <h4>{tr("Assessment results", "نتائج التقييم")}</h4>

          {assessmentControls.length === 0 ? (
            <p>{tr("No assessment results available.", "لا توجد نتائج تقييم.")}</p>
          ) : (
            assessmentControls.map((control) => (
              <div
                className={styles.result}
                key={control.control_id}
              >
                <span>
                  {control.status === "fail" ? (
                    <XCircle size={15} />
                  ) : (
                    <CheckCircle2 size={15} />
                  )}
                </span>

                <b>
                  {control.control_id}
                </b>

                <span>
                  {control.title}
                </span>

                <em>
                  {statusLabel(control.status)}
                </em>

                <small>
                  {control.evidence_count} {tr("evidence", "دليل")}
                </small>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}