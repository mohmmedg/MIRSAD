import { useEffect, useState } from "react";
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

import styles from "./ComplianceCenter.module.css";

type Props = {
  findings: Array<Record<string, unknown>>;
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

export function ComplianceCenter({ findings }: Props) {
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

  async function load() {
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
          : "Unable to load compliance data"
      );
    }
  }

  useEffect(() => {
    void load();
  }, [framework]);

  async function run() {
    setBusy(true);
    setError("");

    try {
      const result = await assessCompliance(
        findings,
        framework === "all" ? undefined : framework
      );

      setAssessment(result);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Assessment failed"
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
          : "Policy update failed"
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
      <div className={styles.header}>
        <div>
          <div className={styles.kicker}>
            <ShieldCheck size={14} />
            COMPLIANCE &amp; CI/CD
          </div>

          <h3>Compliance Center</h3>

          <p>
            Deterministic findings are mapped to controls.
            Gemini never decides pass/fail.
          </p>
        </div>

        <button
          onClick={() => void load()}
          disabled={busy}
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

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
          <option value="all">All frameworks</option>
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
          Assess {findings.length} findings
        </button>

        <button
          onClick={() => void sarif()}
          disabled={busy}
        >
          <Download size={14} />
          Export SARIF
        </button>
      </div>

      {assessment && (
        <div className={styles.stats}>
          <div>
            <b>{assessment.score}%</b>
            <span>Compliance score</span>
          </div>

          <div>
            <b>{assessment.passed}</b>
            <span>Passed / observed</span>
          </div>

          <div>
            <b>{assessment.failed}</b>
            <span>Failed controls</span>
          </div>
        </div>
      )}

      <div className={styles.grid}>
        <div className={styles.card}>
          <h4>Control catalog</h4>

          {controls.length === 0 ? (
            <p>No compliance controls found.</p>
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
                    ? "Enabled"
                    : "Disabled"}
                </span>
              </div>
            ))
          )}
        </div>

        <div className={styles.card}>
          <h4>
            <GitBranch size={15} />
            CI/CD Security Gate
          </h4>

          <p>
            Pull requests can fail on deterministic
            severity thresholds and upload SARIF to
            GitHub Code Scanning.
          </p>

          <label>
            Critical allowed

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
            High allowed

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
            Medium allowed

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

            Gate enabled
          </label>

          <button
            onClick={() => void save()}
            disabled={busy}
          >
            <Save size={14} />
            Save gate policy
          </button>
        </div>
      </div>

      {assessment && (
        <div className={styles.card}>
          <h4>Assessment results</h4>

          {assessmentControls.length === 0 ? (
            <p>No assessment results available.</p>
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
                  {control.status}
                </em>

                <small>
                  {control.evidence_count} evidence
                </small>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}