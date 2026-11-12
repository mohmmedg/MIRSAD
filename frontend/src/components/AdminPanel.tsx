import { useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { Outlet, useLocation } from "react-router-dom";
import { Direction } from "radix-ui";
import { useLanguage } from "../i18n/LanguageContext";
import {
  ShieldCheck,
  Users,
  UserCheck,
  KeyRound,
  Activity,
  Server,
  Bell,
  Siren,
  ScrollText,
  X,
} from "lucide-react";

import {
  getAdminOverview,
  listAdminTenants,
  listAdminAudit,
  listAdminUsers,
  createAdminUser,
  updateAdminUser,
  deleteAdminUser,
  resetAdminUserPassword,
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
  type AdminTenant,
  type AdminPolicies,
  type AdminApiKey,
  type AdminSession,
  type SecurityAlert,
  type SecurityIncident,
  type SecurityEvent,
} from "../api/client";

import { getAccessToken, getRole, getAuthMe } from "../auth/supabase";
// Tailwind + shadcn tokens for the administration area only (see src/admin-ui/admin.css).
import "@/admin-ui/admin.css";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TooltipProvider } from "@/components/ui/tooltip";
import { PortalContainerContext } from "@/components/ui/portal-container";
import {
  AdminPanelHeader,
  type AdminStatItem,
} from "./admin/AdminPanelChrome";
import { AdminSecretNotice } from "./admin/AdminSecretNotice";
import { ADMIN_SECTIONS, adminTabFromPath, type AdminTab } from "./admin/adminRoutes";
import type { AdminPanelSectionModel } from "./admin/AdminPanelSectionModel";

type Tab = AdminTab;

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

type StatsItem = AdminStatItem;

type TenantCache = {
  loaded: Set<string>;
  overview?: OverviewData | null;
  users?: AdminUser[];
  audit?: Array<Record<string, unknown>>;
  policies?: AdminPolicies | null;
  features?: Record<string, boolean>;
  keys?: AdminApiKey[];
  sessions?: AdminSession[];
  health?: Record<string, string>;
  backup?: BackupStatus | null;
  permissions?: Record<string, string[]>;
  secSummary?: SecuritySummary | null;
  alerts?: SecurityAlert[];
  incidents?: SecurityIncident[];
  securityEvents?: SecurityEvent[];
  asmSchedules?: Array<Record<string, unknown>>;
};

// In-memory application cache. It survives tab switches and component remounts
// during the session. A resource is fetched once per tenant and stays cached
// until a mutation explicitly invalidates that resource.
const adminTenantCache = new Map<string, TenantCache>();
let ownerTenantsCache: AdminTenant[] | null = null;
let ownerAuthCache: Awaited<ReturnType<typeof getAuthMe>> | null = null;

function getTenantCache(tenantId: string): TenantCache {
  let cache = adminTenantCache.get(tenantId);
  if (!cache) {
    cache = { loaded: new Set<string>() };
    adminTenantCache.set(tenantId, cache);
  }
  return cache;
}

function invalidateTenantResources(tenantId: string | undefined, resources: string[]) {
  if (!tenantId) return;
  const cache = adminTenantCache.get(tenantId);
  if (!cache) return;
  for (const resource of resources) {
    cache.loaded.delete(resource);
  }
}

export function AdminPanel({ ownerMode = false }: { ownerMode?: boolean }) {
  const { language, dir } = useLanguage();
  const isArabic = language === "ar";
  const adminText = (ar: string, en: string) => isArabic ? ar : en;
  // Each administration section is its own route (/admin/users, /tenant-admin/sessions, ...);
  // this component is the shared layout that owns the data, the tenant cache and the role gates.
  const { pathname } = useLocation();
  const tab: Tab = adminTabFromPath(pathname, ownerMode);
  const sectionMeta = ADMIN_SECTIONS.find((section) => section.key === tab) ?? ADMIN_SECTIONS[0];
  const [portalRoot, setPortalRoot] = useState<HTMLElement | null>(null);

  const [users, setUsers] = useState<AdminUser[]>([]);
  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState("");
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);
  // Tenant admins never send tenant_id (the backend scopes them to their own organization),
  // but the client-side cache still needs that id as its key.
  const [ownTenantId, setOwnTenantId] = useState("");
  const [currentUserRole, setCurrentUserRole] = useState<AdminUser["role"]>(getRole());

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
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 4000);
    return () => window.clearTimeout(timer);
  }, [notice]);
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const loadVersion = useRef(0);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [keyFormOpen, setKeyFormOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [keyExpiryDays, setKeyExpiryDays] = useState(90);

  const [userFormOpen, setUserFormOpen] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");

  const [resetPasswordFor, setResetPasswordFor] = useState<string | null>(null);
  const [resetPasswordValue, setResetPasswordValue] = useState("");
  const [newPassword, setNewPassword] = useState<{ email: string; password: string } | null>(null);

  const role = currentUserRole;
  const canManage = ownerMode ? role === "owner" : role === "admin";
  const targetTenantId = ownerMode ? selectedTenantId : undefined;
  const cacheScope = ownerMode ? selectedTenantId : ownTenantId;

  function clearTenantScopedData() {
    setUsers([]);
    setOverview(null);
    setPolicies(null);
    setFeatures({});
    setKeys([]);
    setSessions([]);
    setHealth({});
    setBackup(null);
    setPermissions({});
    setSecSummary(null);
    setAlerts([]);
    setIncidents([]);
    setSecurityEvents([]);
    setAudit([]);
    setAsmSchedules([]);
  }

  function restoreCachedTenant(tenantId: string) {
    const cache = adminTenantCache.get(tenantId);
    if (!cache) {
      clearTenantScopedData();
      return;
    }
    setOverview(cache.overview ?? null);
    setUsers(cache.users ?? []);
    setAudit(cache.audit ?? []);
    setPolicies(cache.policies ?? null);
    setFeatures(cache.features ?? {});
    setKeys(cache.keys ?? []);
    setSessions(cache.sessions ?? []);
    setHealth(cache.health ?? {});
    setBackup(cache.backup ?? null);
    setPermissions(cache.permissions ?? {});
    setSecSummary(cache.secSummary ?? null);
    setAlerts(cache.alerts ?? []);
    setIncidents(cache.incidents ?? []);
    setSecurityEvents(cache.securityEvents ?? []);
    setAsmSchedules(cache.asmSchedules ?? []);
  }

  async function load(force = false) {
    const requestId = ++loadVersion.current;
    if (!getAccessToken()) return;
    setError(null);
    setLoading(true);
    try {
      let tenantId = targetTenantId;
      let scopeId = targetTenantId;
      let actorId = currentUserId;
      let actorRole = currentUserRole;

      if (ownerMode) {
        // /auth/me and the organization registry are session-level data.
        // Do not fetch them again just because the user changed tabs.
        const me = ownerAuthCache ?? await getAuthMe();
        ownerAuthCache = me;
        actorId = me.user_id;
        actorRole = me.role;
        setCurrentUserId(me.user_id);
        setCurrentUserRole(me.role);

        let availableTenants = ownerTenantsCache ?? tenants;
        if (!availableTenants.length) {
          const tr = await listAdminTenants();
          availableTenants = tr.tenants;
          ownerTenantsCache = tr.tenants;
          setTenants(tr.tenants);
        } else if (tenants.length === 0) {
          setTenants(availableTenants);
        }

        if (actorRole !== "owner") return;
        if (!availableTenants.length) {
          setError(adminText("لا توجد مؤسسة متاحة للإدارة.", "No organization is available to manage."));
          return;
        }

        const selected = tenantId && availableTenants.some((t) => t.tenant_id === tenantId)
          ? tenantId
          : availableTenants[0].tenant_id;
        tenantId = selected;
        scopeId = selected;
        if (selectedTenantId !== selected) setSelectedTenantId(selected);
      } else {
        const me = await getAuthMe();
        actorId = me.user_id;
        actorRole = me.role;
        setCurrentUserId(me.user_id);
        setCurrentUserRole(me.role);
        if (actorRole !== "admin") return;
        scopeId = me.tenant_id;
        setOwnTenantId(me.tenant_id);
      }

      if (!scopeId) {
        setError(adminText("يرجى اختيار مؤسسة قبل عرض بيانات الإدارة.", "Select an organization before loading administration data."));
        return;
      }

      const cache = getTenantCache(scopeId);
      const resourceMap: Record<Tab, string[]> = {
        overview: ["overview", "health", "backup"],
        users: ["users", "permissions"],
        security: ["policies", "audit"],
        soc: ["secSummary", "alerts", "incidents", "securityEvents"],
        sessions: ["sessions"],
        keys: ["keys"],
        features: ["features"],
        operations: ["audit", "policies"],
        asm: ["asmSchedules"],
      };
      const resources = resourceMap[tab];
      const wanted = force ? resources : resources.filter((resource) => !cache.loaded.has(resource));

      if (wanted.length === 0) {
        restoreCachedTenant(scopeId);
        return;
      }

      // Requests are now scoped to the visible window. They are intentionally
      // sequential: the page should not create a burst of 15 DB requests.
      for (const resource of wanted) {
        if (requestId !== loadVersion.current) return;

        switch (resource) {
          case "overview": {
            const o = await getAdminOverview(tenantId);
            cache.overview = { ...o.users, api_keys: o.api_keys, active_sessions: o.active_sessions, active_jobs: o.active_jobs };
            setOverview(cache.overview);
            cache.loaded.add(resource);
            break;
          }
          case "users": {
            const u = await listAdminUsers("", tenantId);
            cache.users = u.users.map((item) => item.user_id === actorId ? { ...item, role: actorRole } : item);
            setUsers(cache.users);
            cache.loaded.add(resource);
            break;
          }
          case "audit": {
            const a = await listAdminAudit(100, tenantId);
            cache.audit = a.events;
            setAudit(cache.audit);
            cache.loaded.add(resource);
            break;
          }
          case "policies": {
            const p = await getAdminPolicies(tenantId);
            cache.policies = p;
            setPolicies(p);
            cache.loaded.add(resource);
            break;
          }
          case "features": {
            const f = await getAdminFeatures(tenantId);
            cache.features = f;
            setFeatures(f);
            cache.loaded.add(resource);
            break;
          }
          case "keys": {
            const k = await listAdminApiKeys(tenantId);
            cache.keys = k.keys;
            setKeys(cache.keys);
            cache.loaded.add(resource);
            break;
          }
          case "sessions": {
            const ss = await listAdminSessions(tenantId);
            cache.sessions = ss.sessions;
            setSessions(cache.sessions);
            cache.loaded.add(resource);
            break;
          }
          case "health": {
            const h = await getAdminHealth(tenantId);
            cache.health = h.checks;
            setHealth(cache.health);
            cache.loaded.add(resource);
            break;
          }
          case "backup": {
            const b = await getAdminBackupStatus();
            cache.backup = b;
            setBackup(b);
            cache.loaded.add(resource);
            break;
          }
          case "permissions": {
            const pm = await getAdminPermissions();
            cache.permissions = pm.role_matrix;
            setPermissions(cache.permissions);
            cache.loaded.add(resource);
            break;
          }
          case "secSummary": {
            const ss = await getSecuritySummary(tenantId);
            cache.secSummary = ss;
            setSecSummary(ss);
            cache.loaded.add(resource);
            break;
          }
          case "alerts": {
            const al = await listSecurityAlerts(100, tenantId);
            cache.alerts = al.alerts;
            setAlerts(cache.alerts);
            cache.loaded.add(resource);
            break;
          }
          case "incidents": {
            const inc = await listSecurityIncidents(100, tenantId);
            cache.incidents = inc.incidents;
            setIncidents(cache.incidents);
            cache.loaded.add(resource);
            break;
          }
          case "securityEvents": {
            const ev = await listSecurityEvents(100, tenantId);
            cache.securityEvents = ev.events;
            setSecurityEvents(cache.securityEvents);
            cache.loaded.add(resource);
            break;
          }
          case "asmSchedules": {
            const asm = await listContinuousSchedules(tenantId);
            cache.asmSchedules = asm.schedules;
            setAsmSchedules(cache.asmSchedules);
            cache.loaded.add(resource);
            break;
          }
        }
      }
    } catch (e) {
      if (requestId === loadVersion.current) {
        setError(e instanceof Error ? e.message : adminText("تعذر تحميل بيانات الإدارة.", "Unable to load admin data."));
      }
    } finally {
      if (requestId === loadVersion.current) setLoading(false);
    }
  }

  // Intentionally re-runs only when the selected tenant/tab/mode changes, not on
  // every re-creation of `load`/`restoreCachedTenant` (both close over broader
  // component state used across 15+ call sites in this file). Including them in
  // the dependency array would refetch on unrelated re-renders.
  useEffect(() => {
    if (cacheScope) restoreCachedTenant(cacheScope);
    void load();
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [ownerMode, selectedTenantId, tab]);

  async function createUser() {
    const email = newUserEmail.trim().toLowerCase();
    if (!email || newUserPassword.length < 12) {
      setError(adminText("أدخل بريداً صالحاً وكلمة مرور لا تقل عن 12 محرفاً.", "Enter a valid email and a password of at least 12 characters."));
      return;
    }

    setBusy("new-user");
    setError(null);
    try {
      await createAdminUser(email, newUserPassword, targetTenantId);
      invalidateTenantResources(cacheScope, ["users", "overview"]);
      setNewUserEmail("");
      setNewUserPassword("");
      setUserFormOpen(false);
      await load(true);
      setNotice(adminText("تم إنشاء الحساب.", "Account created."));
    } catch (e) {
      setError(e instanceof Error ? e.message : adminText("تعذر إنشاء الحساب.", "Unable to create the account."));
    } finally {
      setBusy(null);
    }
  }

  async function removeUser(user: AdminUser) {
    // The explicit confirmation is an AlertDialog in AdminUsersSection (it is the only caller).
    setBusy(`delete-${user.user_id}`);
    setError(null);
    try {
      await deleteAdminUser(user.user_id, targetTenantId);
      invalidateTenantResources(cacheScope, ["users", "overview"]);
      await load(true);
      setNotice(adminText("تم حذف الحساب.", "Account deleted."));
    } catch (e) {
      setError(e instanceof Error ? e.message : adminText("تعذر حذف الحساب.", "Unable to delete the account."));
    } finally {
      setBusy(null);
    }
  }

  async function resetPassword(user: AdminUser) {
    const manualPassword = resetPasswordValue.trim();
    if (manualPassword && manualPassword.length < 12) {
      setError(adminText("كلمة المرور الجديدة يجب ألا تقل عن 12 محرفاً، أو اتركها فارغة للتوليد التلقائي.", "The new password must be at least 12 characters, or leave it blank to generate one automatically."));
      return;
    }

    setBusy(`reset-${user.user_id}`);
    setError(null);
    try {
      const result = await resetAdminUserPassword(user.user_id, manualPassword || undefined, targetTenantId);
      setNewPassword({ email: result.email, password: result.new_password });
      setResetPasswordFor(null);
      setResetPasswordValue("");
    } catch (e) {
      setError(e instanceof Error ? e.message : adminText("تعذر إعادة تعيين كلمة المرور.", "Unable to reset the password."));
    } finally {
      setBusy(null);
    }
  }

  async function change(
    user: AdminUser,
    body: {
      role?: AdminUser["role"];
      is_active?: boolean;
    }
  ) {
    setBusy(user.user_id);

    try {
      const updated = await updateAdminUser(user.user_id, body, targetTenantId);
      invalidateTenantResources(cacheScope, ["users", "overview"]);

      setUsers((current) =>
        current.map((item) =>
          item.user_id === updated.user_id ? updated : item
        )
      );

      await load(true);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : adminText("فشل تحديث المستخدم.", "User update failed.")
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
      const updated = await updateAdminPolicy(kind, values, targetTenantId);
      invalidateTenantResources(cacheScope, ["policies", "audit"]);

      setPolicies((current) =>
        current
          ? {
              ...current,
              [kind]: updated,
            }
          : current
      );

      await load(true);
      setNotice(adminText("تم حفظ السياسة.", "Policy saved."));
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : adminText("فشل تحديث السياسة.", "Policy update failed.")
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
      }, targetTenantId);
      invalidateTenantResources(cacheScope, ["features"]);
      if (cacheScope) {
        const cache = getTenantCache(cacheScope);
        cache.features = next;
        cache.loaded.add("features");
      }
    } catch (e) {
      setFeatures(features); // the optimistic flip did not reach the server: restore the real value
      setError(
        e instanceof Error
          ? e.message
          : adminText("فشل تحديث الخاصية.", "Feature update failed.")
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
        asmInterval,
        targetTenantId
      );

      setAsmTarget("");
      invalidateTenantResources(cacheScope, ["asmSchedules"]);
      await load(true);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : adminText("فشل إعداد المراقبة المستمرة.", "Continuous monitoring setup failed.")
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
        String(schedule.schedule_id),
        targetTenantId
      );

      invalidateTenantResources(cacheScope, ["asmSchedules"]);
      await load(true);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : adminText("تعذر حذف جدول المراقبة.", "Unable to delete the monitoring schedule.")
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
      }, targetTenantId);

      setNewSecret(result.secret);
      invalidateTenantResources(cacheScope, ["keys", "overview"]);
      setKeyName("");
      setKeyFormOpen(false);
      await load(true);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : adminText("فشل إنشاء مفتاح API.", "API key creation failed.")
      );
    } finally {
      setBusy(null);
    }
  }

  async function run(busyKey: string, fallback: string, action: () => Promise<void>, done?: string) {
    setBusy(busyKey);
    setError(null);
    try {
      await action();
      if (done) setNotice(done);
    } catch (e) {
      setError(e instanceof Error ? e.message : fallback);
    } finally {
      setBusy(null);
    }
  }

  const onUpdateAlert = (alertId: string) => run(`alert-${alertId}`, adminText("تعذر تحديث التنبيه.", "Unable to update the alert."), async () => {
    await updateSecurityAlert(alertId, "acknowledged", targetTenantId);
    invalidateTenantResources(cacheScope, ["secSummary", "alerts", "incidents", "securityEvents"]);
    await load(true);
  }, adminText("تم تحديث التنبيه.", "Alert updated."));
  const onUpdateIncident = (incidentId: string) => run(`incident-${incidentId}`, adminText("تعذر تحديث الحادث.", "Unable to update the incident."), async () => {
    await updateSecurityIncident(incidentId, { status: "resolved" }, targetTenantId);
    invalidateTenantResources(cacheScope, ["secSummary", "alerts", "incidents", "securityEvents"]);
    await load(true);
  }, adminText("تم تحديث الحادث.", "Incident updated."));
  const onRevokeAllSessions = () => run("revoke-all-sessions", adminText("تعذر إبطال الجلسات.", "Unable to revoke the sessions."), async () => {
    await revokeAllAdminSessions(targetTenantId);
    invalidateTenantResources(cacheScope, ["sessions"]);
    await load(true);
  }, adminText("تم إبطال الجلسات.", "Sessions revoked."));
  const onRevokeSession = (sessionId: string) => run(`session-${sessionId}`, adminText("تعذر إبطال الجلسة.", "Unable to revoke the session."), async () => {
    await revokeAdminSession(sessionId, targetTenantId);
    invalidateTenantResources(cacheScope, ["sessions"]);
    await load(true);
  }, adminText("تم إبطال الجلسة.", "Session revoked."));
  const onRevokeKey = (keyId: string) => run(`key-${keyId}`, adminText("تعذر إبطال المفتاح.", "Unable to revoke the API key."), async () => {
    await revokeAdminApiKey(keyId, targetTenantId);
    invalidateTenantResources(cacheScope, ["keys", "overview"]);
    await load(true);
  }, adminText("تم إبطال المفتاح.", "API key revoked."));

  if (!canManage) {
    return null;
  }

  const scan = policies?.scan || {};

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
      tone: "danger",
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

  const sectionModel = {
    ownerMode, role, currentUserId, busy, targetTenantId,
    overviewStats, securityStats, health, backup, users,
    userFormOpen, setUserFormOpen, newUserEmail, setNewUserEmail,
    newUserPassword, setNewUserPassword, createUser, change, removeUser,
    resetPassword, resetPasswordFor, setResetPasswordFor, resetPasswordValue,
    setResetPasswordValue, permissions, asmTarget, setAsmTarget, asmInterval,
    setAsmInterval, asmSchedules, createAsm, removeAsmSchedule, secSummary,
    alerts, incidents, securityEvents, onUpdateAlert, onUpdateIncident,
    policies, policy, audit, sessions, onRevokeAllSessions, onRevokeSession,
    keys, keyFormOpen, setKeyFormOpen, keyName, setKeyName, keyExpiryDays,
    setKeyExpiryDays, makeKey, onRevokeKey, features, toggleFeature,
    scan, loading,
  } satisfies AdminPanelSectionModel;

  return (
    <Direction.Provider dir={dir}>
      <TooltipProvider delayDuration={200}>
        <PortalContainerContext.Provider value={portalRoot}>
          <div
            ref={setPortalRoot}
            className="admin-ui mx-auto flex w-full max-w-[1400px] flex-col gap-6"
            id="section-admin"
          >
            <AdminPanelHeader
              ownerMode={ownerMode}
              section={sectionMeta}
              tenants={tenants}
              selectedTenantId={selectedTenantId}
              onTenantChange={(nextTenantId) => {
                if (nextTenantId === selectedTenantId) return;
                restoreCachedTenant(nextTenantId);
                setSelectedTenantId(nextTenantId);
              }}
              onRefresh={() => void load(true)}
              refreshDisabled={busy !== null || loading}
              loading={loading}
            />

            {error && (
              <Alert variant="destructive" role="alert" className="border-danger/40 bg-danger-soft">
                <AlertDescription className="flex items-start justify-between gap-3 text-danger">
                  <span>{error}</span>
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    aria-label={adminText("إغلاق الرسالة", "Dismiss message")}
                    onClick={() => setError(null)}
                  >
                    <X aria-hidden="true" />
                  </Button>
                </AlertDescription>
              </Alert>
            )}

            {newSecret && (
              <AdminSecretNotice
                title={adminText("مفتاح API جديد — انسخه الآن، لن يظهر مرة أخرى:", "New API key — copy it now; it will not be shown again:")}
                secret={newSecret}
                onClose={() => setNewSecret(null)}
              />
            )}

            {newPassword && (
              <AdminSecretNotice
                title={adminText(`كلمة مرور جديدة لـ ${newPassword.email} — انسخها الآن، لن تظهر مرة أخرى:`, `New password for ${newPassword.email} — copy it now; it will not be shown again:`)}
                secret={newPassword.password}
                onClose={() => setNewPassword(null)}
              />
            )}

            <main className="min-w-0">
              <Outlet context={sectionModel} />
            </main>

            {notice && (
              <div className="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex justify-center px-4">
                <div role="status" aria-live="polite" className="pointer-events-auto flex items-center gap-2 rounded-lg border bg-card px-4 py-2.5 text-sm font-medium text-foreground shadow-lg">
                  <CheckCircle2 className="size-4 text-success" aria-hidden="true" />
                  {notice}
                </div>
              </div>
            )}
          </div>
        </PortalContainerContext.Provider>
      </TooltipProvider>
    </Direction.Provider>
  );
}
