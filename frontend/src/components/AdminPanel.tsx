import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import {
  ShieldCheck,
  Users,
  UserCheck,
  UserX,
  RefreshCw,
  ScrollText,
  KeyRound,
  Settings2,
  ToggleRight,
  Activity,
  LogOut,
  Server,
  Bot,
  Database,
  Copy,
  Bell,
  Siren,
} from "lucide-react";

import {
  getAdminOverview,
  listAdminAudit,
  listAdminUsers,
  updateAdminUser,
  getAdminPolicies,
  updateAdminPolicy,
  getAdminFeatures,
  updateAdminFeatures,
  listAdminApiKeys,
  createAdminApiKey,
  revokeAdminApiKey,
  listAdminSessions,
  revokeAdminSession,
  revokeAllAdminSessions,
  getAdminHealth,
  getAdminBackupStatus,
  getAdminPermissions,
  getSecuritySummary,
  listSecurityAlerts,
  listSecurityIncidents,
  listSecurityEvents,
  updateSecurityAlert,
  updateSecurityIncident,
  listContinuousSchedules,
  createContinuousSchedule,
  deleteContinuousSchedule,
  type AdminUser,
  type AdminPolicies,
  type AdminApiKey,
  type AdminSession,
  type SecurityAlert,
  type SecurityIncident,
  type SecurityEvent,
} from "../api/client";

import { getAccessToken, getRole } from "../auth/supabase";
import styles from "./AdminPanel.module.css";

type Tab =
  | "overview"
  | "users"
  | "security"
  | "sessions"
  | "keys"
  | "features"
  | "operations"
  | "soc"
  | "asm";

type OverviewData = {
  total: number;
  active: number;
  admins: number;
  api_keys?: number;
  active_sessions?: number;
  active_jobs?: number;
};

type SecuritySummary = {
  open_alerts: number;
  critical_alerts: number;
  open_incidents: number;
  events_24h: number;
};

type BackupStatus = {
  status: string;
  note: string;
};

type StatsItem = {
  icon: LucideIcon;
  value: number;
  label: string;
};

export function AdminPanel() {
  const [tab, setTab] = useState<Tab>("overview");

  const [users, setUsers] = useState<AdminUser[]>([]);

  const [secSummary, setSecSummary] =
    useState<SecuritySummary | null>(null);

  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);

  const [audit, setAudit] = useState<Array<Record<string, unknown>>>([]);

  const [overview, setOverview] = useState<OverviewData | null>(null);

  const [policies, setPolicies] = useState<AdminPolicies | null>(null);

  const [features, setFeatures] = useState<Record<string, boolean>>({});

  const [keys, setKeys] = useState<AdminApiKey[]>([]);
  const [sessions, setSessions] = useState<AdminSession[]>([]);

  const [health, setHealth] = useState<Record<string, string>>({});

  const [backup, setBackup] = useState<BackupStatus | null>(null);

  const [permissions, setPermissions] =
    useState<Record<string, string[]>>({});

  const [asmSchedules, setAsmSchedules] = useState<
    Array<Record<string, unknown>>
  >([]);

  const [asmTarget, setAsmTarget] = useState("");
  const [asmInterval, setAsmInterval] = useState(3600);

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [keyFormOpen, setKeyFormOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [keyExpiryDays, setKeyExpiryDays] = useState(90);

  const role = getRole();
  const canManage = role === "owner" || role === "admin";

  async function load() {
    if (!getAccessToken() || !canManage) {
      return;
    }

    setError(null);

    try {
      const [
        o,
        u,
        a,
        p,
        f,
        k,
        s,
        h,
        b,
        pm,
        ss,
        al,
        inc,
        ev,
        asm,
      ] = await Promise.all([
        getAdminOverview(),
        listAdminUsers(),
        listAdminAudit(),
        getAdminPolicies(),
        getAdminFeatures(),
        listAdminApiKeys(),
        listAdminSessions(),
        getAdminHealth(),
        getAdminBackupStatus(),
        getAdminPermissions(),
        getSecuritySummary(),
        listSecurityAlerts(),
        listSecurityIncidents(),
        listSecurityEvents(),
        listContinuousSchedules(),
      ]);

      setOverview(o.users as OverviewData);
      setUsers(u.users);
      setAudit(a.events);
      setPolicies(p);
      setFeatures(f);
      setKeys(k.keys);
      setSessions(s.sessions);
      setHealth(h.checks);
      setBackup(b);
      setPermissions(pm.role_matrix);
      setSecSummary(ss);
      setAlerts(al.alerts);
      setIncidents(inc.incidents);
      setSecurityEvents(ev.events);
      setAsmSchedules(asm.schedules);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to load admin data"
      );
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function change(
    user: AdminUser,
    body: {
      role?: AdminUser["role"];
      is_active?: boolean;
    }
  ) {
    setBusy(user.user_id);

    try {
      const updated = await updateAdminUser(user.user_id, body);

      setUsers((current) =>
        current.map((item) =>
          item.user_id === updated.user_id ? updated : item
        )
      );

      await load();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Update failed"
      );
    } finally {
      setBusy(null);
    }
  }

  async function policy(
    kind: keyof Pick<
      AdminPolicies,
      "security" | "scan" | "ai" | "notifications"
    >,
    values: Record<string, unknown>
  ) {
    setBusy(kind);

    try {
      const updated = await updateAdminPolicy(kind, values);

      setPolicies((current) =>
        current
          ? {
              ...current,
              [kind]: updated,
            }
          : current
      );

      await load();
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Policy update failed"
      );
    } finally {
      setBusy(null);
    }
  }

  async function toggleFeature(name: string) {
    const next = {
      ...features,
      [name]: !features[name],
    };

    setFeatures(next);

    try {
      await updateAdminFeatures({
        [name]: next[name],
      });
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Feature update failed"
      );
    }
  }

  async function createAsm() {
    if (!asmTarget.trim()) {
      return;
    }

    setBusy("asm");

    try {
      await createContinuousSchedule(
        {
          target: asmTarget.trim(),
          network: true,
          web: true,
          api: true,
          run_gemini: false,
        },
        asmInterval
      );

      setAsmTarget("");
      await load();
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Continuous monitoring setup failed"
      );
    } finally {
      setBusy(null);
    }
  }

  async function removeAsmSchedule(
    schedule: Record<string, unknown>
  ) {
    try {
      await deleteContinuousSchedule(
        String(schedule.schedule_id)
      );

      await load();
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to delete schedule"
      );
    }
  }

  async function makeKey() {
    if (!keyName.trim()) {
      return;
    }

    setBusy("new-key");

    try {
      const result = await createAdminApiKey({
        name: keyName.trim(),
        expires_in_days: keyExpiryDays > 0 ? keyExpiryDays : undefined,
      });

      setNewSecret(result.secret);
      setKeyName("");
      setKeyFormOpen(false);
      await load();
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "API key creation failed"
      );
    } finally {
      setBusy(null);
    }
  }

  if (!canManage) {
    return null;
  }

  const sec = policies?.security || {};
  const scan = policies?.scan || {};
  const ai = policies?.ai || {};

  const overviewStats: StatsItem[] = [
    {
      icon: Users,
      value: overview?.total ?? 0,
      label: "Users",
    },
    {
      icon: UserCheck,
      value: overview?.active ?? 0,
      label: "Active",
    },
    {
      icon: ShieldCheck,
      value: overview?.admins ?? 0,
      label: "Admins",
    },
    {
      icon: KeyRound,
      value: overview?.api_keys ?? 0,
      label: "API keys",
    },
    {
      icon: Activity,
      value: overview?.active_sessions ?? 0,
      label: "Sessions",
    },
    {
      icon: Server,
      value: overview?.active_jobs ?? 0,
      label: "Active jobs",
    },
  ];

  const securityStats: StatsItem[] = [
    {
      icon: Bell,
      value: secSummary?.open_alerts ?? 0,
      label: "Open alerts",
    },
    {
      icon: Siren,
      value: secSummary?.critical_alerts ?? 0,
      label: "Critical",
    },
    {
      icon: Activity,
      value: secSummary?.open_incidents ?? 0,
      label: "Open incidents",
    },
    {
      icon: ScrollText,
      value: secSummary?.events_24h ?? 0,
      label: "Events / 24h",
    },
  ];

  return (
    <section
      className={styles.wrap}
      id="section-admin"
    >
      <header className={styles.header}>
        <div>
          <div className={styles.kicker}>
            <ShieldCheck size={14} />
            SECURITY ADMINISTRATION CENTER
          </div>

          <h2>Tenant security & administration</h2>

          <p>
            Users, access control, sessions, secrets,
            policies, operations and audit.
          </p>
        </div>

        <button
          className={styles.refresh}
          onClick={() => void load()}
          disabled={busy !== null}
        >
          <RefreshCw size={15} />
          Refresh
        </button>
      </header>

      {error && (
        <div className={styles.error}>
          {error}
        </div>
      )}

      {newSecret && (
        <div className={styles.secret}>
          <b>New API key — copy it now:</b>

          <code>{newSecret}</code>

          <button
            onClick={() =>
              void navigator.clipboard?.writeText(
                newSecret
              )
            }
          >
            <Copy size={14} />
            Copy
          </button>

          <button
            onClick={() => setNewSecret(null)}
          >
            Close
          </button>
        </div>
      )}

      <nav className={styles.tabs}>
        {(
          [
            "overview",
            "users",
            "security",
            "soc",
            "sessions",
            "keys",
            "features",
            "operations",
            "asm",
          ] as Tab[]
        ).map((item) => (
          <button
            key={item}
            className={
              tab === item
                ? styles.tabActive
                : styles.tab
            }
            onClick={() => setTab(item)}
          >
            {item}
          </button>
        ))}
      </nav>

      {tab === "overview" && (
        <>
          <div className={styles.stats}>
            {overviewStats.map(
              ({ icon: Icon, value, label }) => (
                <div key={label}>
                  <Icon />
                  <b>{String(value)}</b>
                  <span>{label}</span>
                </div>
              )
            )}
          </div>

          <div className={styles.grid}>
            <div className={styles.card}>
              <div className={styles.cardTitle}>
                <Activity size={15} />
                Platform health
              </div>

              {Object.entries(health).map(
                ([key, value]) => (
                  <div
                    className={styles.health}
                    key={key}
                  >
                    <span>{key}</span>
                    <b>{value}</b>
                  </div>
                )
              )}
            </div>

            <div className={styles.card}>
              <div className={styles.cardTitle}>
                <Database size={15} />
                Backup & recovery
              </div>

              <p>{backup?.note}</p>

              <strong>
                {backup?.status}
              </strong>
            </div>
          </div>
        </>
      )}

      {tab === "users" && (
        <div className={styles.card}>
          <div className={styles.cardTitle}>
            <Users size={15} />
            Users & RBAC
          </div>

          {users.map((user) => (
            <div
              className={styles.row}
              key={user.user_id}
            >
              <span>
                <strong>{user.email}</strong>
                <small>{user.user_id}</small>
              </span>

              <select
                value={user.role}
                disabled={
                  busy === user.user_id ||
                  (role !== "owner" &&
                    ["admin", "owner"].includes(
                      user.role
                    ))
                }
                onChange={(event) =>
                  void change(user, {
                    role: event.target
                      .value as AdminUser["role"],
                  })
                }
              >
                <option value="viewer">
                  Viewer
                </option>
                <option value="analyst">
                  Analyst
                </option>
                <option value="admin">
                  Admin
                </option>
                {/* لا يوجد خيار "Owner" هنا عمداً: الـ backend
                    (admin.py::_can_manage) لا يسمح لأي actor — ولا حتى
                    owner نفسه — بترقية مستخدم آخر إلى owner عبر هذا الـ
                    endpoint؛ الدور يُمنح فقط عبر bootstrap لمرة واحدة.
                    إظهاره هنا كان يعطي خياراً يفشل دائماً بـ 403. */}
              </select>

              <span
                className={
                  user.is_active
                    ? styles.active
                    : styles.inactive
                }
              >
                {user.is_active
                  ? "Active"
                  : "Disabled"}
              </span>

              <button
                className={styles.action}
                disabled={
                  busy === user.user_id ||
                  (user.role === "owner" &&
                    role !== "owner")
                }
                onClick={() =>
                  void change(user, {
                    is_active: !user.is_active,
                  })
                }
              >
                {user.is_active ? (
                  <>
                    <UserX size={14} />
                    Disable
                  </>
                ) : (
                  <>
                    <UserCheck size={14} />
                    Enable
                  </>
                )}
              </button>
            </div>
          ))}

          <div className={styles.permissions}>
            <h3>Permission matrix</h3>

            {Object.entries(permissions).map(
              ([permissionRole, permissionList]) => (
                <div key={permissionRole}>
                  <b>{permissionRole}</b>
                  <span>
                    {permissionList.join(" · ")}
                  </span>
                </div>
              )
            )}
          </div>
        </div>
      )}

      {tab === "asm" && (
        <div className={styles.grid}>
          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Activity size={15} />
              Continuous Attack Surface Monitoring
            </div>

            <p>
              Deterministic snapshots detect
              new/removed IPs, ports, services, DNS,
              technologies, endpoints, APIs and TLS
              changes, then send changes into the same
              SOC Finding → Risk → Alert → Incident
              pipeline.
            </p>

            <div className={styles.row}>
              <input
                value={asmTarget}
                onChange={(event) =>
                  setAsmTarget(event.target.value)
                }
                placeholder="https://example.com"
              />

              <select
                value={asmInterval}
                onChange={(event) =>
                  setAsmInterval(
                    Number(event.target.value)
                  )
                }
              >
                <option value={300}>
                  Every 5 min
                </option>
                <option value={900}>
                  Every 15 min
                </option>
                <option value={3600}>
                  Every hour
                </option>
                <option value={21600}>
                  Every 6 hours
                </option>
                <option value={86400}>
                  Daily
                </option>
              </select>

              <button
                className={styles.action}
                disabled={
                  busy === "asm" ||
                  !asmTarget.trim()
                }
                onClick={() => void createAsm()}
              >
                Start monitoring
              </button>
            </div>
          </div>

          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Server size={15} />
              Monitors
            </div>

            {asmSchedules.map((schedule) => (
              <div
                className={styles.row}
                key={String(
                  schedule.schedule_id
                )}
              >
                <span>
                  <strong>
                    {String(schedule.target)}
                  </strong>

                  <small>
                    {String(
                      schedule.schedule_id
                    )}
                  </small>
                </span>

                <span>
                  {String(
                    schedule.interval_seconds
                  )}
                  s
                </span>

                <span>
                  {String(
                    schedule.last_status ||
                      "never run"
                  )}
                </span>

                <button
                  className={styles.action}
                  onClick={() =>
                    void removeAsmSchedule(
                      schedule
                    )
                  }
                >
                  Stop
                </button>
              </div>
            ))}

            {asmSchedules.length === 0 && (
              <p>
                No continuous monitors configured.
              </p>
            )}
          </div>
        </div>
      )}

      {tab === "soc" && (
        <div className={styles.grid}>
          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Siren size={15} />
              SOC / Detection summary
            </div>

            <div className={styles.stats}>
              {securityStats.map(
                ({ icon: Icon, value, label }) => (
                  <div key={label}>
                    <Icon />
                    <b>{String(value)}</b>
                    <span>{label}</span>
                  </div>
                )
              )}
            </div>
          </div>

          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Bell size={15} />
              Security alerts
            </div>

            {alerts.slice(0, 25).map((alert) => (
              <div
                className={styles.row}
                key={alert.alert_id}
              >
                <span>
                  <strong>
                    {alert.title}
                  </strong>

                  <small>
                    {alert.event_id || "event"} ·
                    risk {alert.risk_score}
                  </small>
                </span>

                <b>{alert.severity}</b>

                <span>{alert.status}</span>

                {alert.status !==
                  "resolved" && (
                  <button
                    className={styles.action}
                    onClick={() =>
                      void updateSecurityAlert(
                        alert.alert_id,
                        "acknowledged"
                      ).then(() => load())
                    }
                  >
                    Acknowledge
                  </button>
                )}
              </div>
            ))}
          </div>

          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Siren size={15} />
              Incident Center
            </div>

            {incidents
              .slice(0, 25)
              .map((incident) => (
                <div
                  className={styles.row}
                  key={incident.incident_id}
                >
                  <span>
                    <strong>
                      {incident.title}
                    </strong>

                    <small>
                      {incident.incident_id}
                    </small>
                  </span>

                  <b>{incident.severity}</b>

                  <span>
                    {incident.status}
                  </span>

                  {incident.status !==
                    "resolved" && (
                    <button
                      className={styles.action}
                      onClick={() =>
                        void updateSecurityIncident(
                          incident.incident_id,
                          {
                            status: "resolved",
                          }
                        ).then(() => load())
                      }
                    >
                      Resolve
                    </button>
                  )}
                </div>
              ))}
          </div>

          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Activity size={15} />
              Detection timeline
            </div>

            {securityEvents
              .slice(0, 30)
              .map((event) => (
                <div
                  className={styles.auditRow}
                  key={event.event_id}
                >
                  <b>{event.event_type}</b>

                  <span>
                    {event.severity} · risk{" "}
                    {event.risk_score}
                  </span>

                  <small>
                    {event.created_at}
                  </small>
                </div>
              ))}
          </div>
        </div>
      )}

      {tab === "security" && (
        <div className={styles.grid}>
          <PolicyCard
            title="Security policies"
            icon={<Settings2 />}
            values={sec}
            busy={busy === "security"}
            onToggle={(key, value) =>
              void policy("security", {
                [key]: value,
              })
            }
            onSaveValues={(changed) => void policy("security", changed)}
          />

          <PolicyCard
            title="Scan governance"
            icon={<ShieldCheck />}
            values={scan}
            busy={busy === "scan"}
            onToggle={(key, value) =>
              void policy("scan", {
                [key]: value,
              })
            }
            onSaveValues={(changed) => void policy("scan", changed)}
          />

          <PolicyCard
            title="AI / Gemini"
            icon={<Bot />}
            values={ai}
            busy={busy === "ai"}
            onToggle={(key, value) =>
              void policy("ai", {
                [key]: value,
              })
            }
            onSaveValues={(changed) => void policy("ai", changed)}
          />

          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <ScrollText size={15} />
              Audit
            </div>

            {audit
              .slice(0, 20)
              .map((event) => (
                <div
                  className={styles.auditRow}
                  key={String(event.id)}
                >
                  <b>
                    {String(event.event)}
                  </b>

                  <span>
                    {String(
                      event.target ?? "—"
                    )}
                  </span>

                  <small>
                    {String(
                      event.created_at
                    )}
                  </small>
                </div>
              ))}
          </div>
        </div>
      )}

      {tab === "sessions" && (
        <div className={styles.card}>
          <div className={styles.cardTitle}>
            <LogOut size={15} />

            Sessions

            <button
              className={styles.action}
              onClick={() =>
                void revokeAllAdminSessions().then(
                  () => load()
                )
              }
            >
              Revoke all other sessions
            </button>
          </div>

          {sessions.map((session) => (
            <div
              className={styles.row}
              key={session.id}
            >
              <span>
                <strong>
                  {session.user_id}
                </strong>

                <small>
                  {session.created_at}
                </small>
              </span>

              <span>
                {session.revoked
                  ? "Revoked"
                  : "Active"}
              </span>

              <span>
                {session.expires_at}
              </span>

              <button
                className={styles.action}
                disabled={session.revoked}
                onClick={() =>
                  void revokeAdminSession(
                    session.id
                  ).then(() => load())
                }
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      {tab === "keys" && (
        <div className={styles.card}>
          <div className={styles.cardTitle}>
            <KeyRound size={15} />

            API keys

            <button
              className={styles.action}
              onClick={() => setKeyFormOpen((v) => !v)}
            >
              {keyFormOpen ? "Cancel" : "Create key"}
            </button>
          </div>

          {keyFormOpen && (
            <div className={styles.row}>
              <span>
                <input
                  className={styles.input}
                  placeholder="Key name (e.g. CI pipeline)"
                  value={keyName}
                  onChange={(event) => setKeyName(event.target.value)}
                  maxLength={120}
                  autoFocus
                />
              </span>

              <span>
                <select
                  value={keyExpiryDays}
                  onChange={(event) =>
                    setKeyExpiryDays(Number(event.target.value))
                  }
                >
                  <option value={30}>Expires in 30 days</option>
                  <option value={90}>Expires in 90 days</option>
                  <option value={365}>Expires in 1 year</option>
                  <option value={0}>Never expires</option>
                </select>
              </span>

              <button
                className={styles.action}
                disabled={busy === "new-key" || !keyName.trim()}
                onClick={() => void makeKey()}
              >
                {busy === "new-key" ? "Creating…" : "Confirm"}
              </button>
            </div>
          )}

          {keys.map((key) => (
            <div
              className={styles.row}
              key={key.key_id}
            >
              <span>
                <strong>{key.name}</strong>

                <small>
                  {key.key_id}
                </small>
              </span>

              <span>
                {key.scopes.join(", ")}
              </span>

              <span>
                {key.revoked
                  ? "Revoked"
                  : "Active"}
              </span>

              <button
                className={styles.action}
                disabled={key.revoked}
                onClick={() =>
                  void revokeAdminApiKey(
                    key.key_id
                  ).then(() => load())
                }
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      {tab === "features" && (
        <div className={styles.card}>
          <div className={styles.cardTitle}>
            <ToggleRight size={15} />
            Feature flags
          </div>

          {Object.entries(features).map(
            ([key, value]) => (
              <div
                className={styles.row}
                key={key}
              >
                <span>
                  <strong>{key}</strong>
                </span>

                <span>
                  {value
                    ? "Enabled"
                    : "Disabled"}
                </span>

                <button
                  className={styles.action}
                  onClick={() =>
                    void toggleFeature(key)
                  }
                >
                  {value
                    ? "Disable"
                    : "Enable"}
                </button>
              </div>
            )
          )}
        </div>
      )}

      {tab === "operations" && (
        <div className={styles.grid}>
          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <Server size={15} />
              Operational controls
            </div>

            {Object.entries(scan).map(
              ([key, value]) => (
                <div
                  className={styles.health}
                  key={key}
                >
                  <span>{key}</span>
                  <b>{String(value)}</b>
                </div>
              )
            )}
          </div>

          <div className={styles.card}>
            <div className={styles.cardTitle}>
              <ScrollText size={15} />
              Recent audit events
            </div>

            {audit.map((event) => (
              <div
                className={styles.auditRow}
                key={String(event.id)}
              >
                <b>
                  {String(event.event)}
                </b>

                <span>
                  {String(
                    event.target ?? "—"
                  )}
                </span>

                <small>
                  {String(
                    event.created_at
                  )}
                </small>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function PolicyCard({
  title,
  icon,
  values,
  onToggle,
  onSaveValues,
  busy,
}: {
  title: string;
  icon: ReactNode;
  values: Record<string, unknown>;
  onToggle: (key: string, value: boolean) => void;
  onSaveValues: (changed: Record<string, unknown>) => void;
  busy: boolean;
}) {
  // مسودة محلية للحقول الرقمية/النصية فقط؛ الحقول Boolean تُبدَّل فوراً كما
  // كانت (onToggle) لأنها لا تحتاج تأكيد. هذا يحل مشكلة كانت موجودة سابقاً:
  // القيم غير المنطقية (session_timeout_minutes, max_failed_logins,
  // rate_limit_per_minute...) كانت تُعرض للقراءة فقط بدون أي طريقة لتعديلها.
  const [draft, setDraft] = useState<Record<string, string>>({});

  const editableEntries = Object.entries(values).filter(([, v]) => typeof v !== "boolean");
  const hasChanges = editableEntries.some(
    ([key, value]) => draft[key] !== undefined && draft[key] !== String(value ?? "")
  );

  function fieldValue(key: string, value: unknown): string {
    return draft[key] ?? String(value ?? "");
  }

  function save() {
    const changed: Record<string, unknown> = {};
    for (const [key, value] of editableEntries) {
      const current = draft[key];
      if (current === undefined) continue;
      if (current === String(value ?? "")) continue;
      changed[key] = typeof value === "number" ? Number(current) : current;
    }
    if (Object.keys(changed).length === 0) return;
    onSaveValues(changed);
    setDraft({});
  }

  return (
    <div className={styles.card}>
      <div className={styles.cardTitle}>
        {icon}
        {title}
        {hasChanges && (
          <button className={styles.action} onClick={save} disabled={busy}>
            Save changes
          </button>
        )}
      </div>

      {Object.entries(values).map(([key, value]) => (
        <div className={styles.health} key={key}>
          <span>{key}</span>

          {typeof value === "boolean" ? (
            <button className={styles.action} onClick={() => onToggle(key, !value)} disabled={busy}>
              {value ? "Enabled" : "Disabled"}
            </button>
          ) : (
            <input
              className={styles.numberField}
              type={typeof value === "number" ? "number" : "text"}
              value={fieldValue(key, value)}
              disabled={busy}
              onChange={(e) => setDraft((current) => ({ ...current, [key]: e.target.value }))}
              onKeyDown={(e) => {
                if (e.key === "Enter") save();
              }}
            />
          )}
        </div>
      ))}
    </div>
  );
}