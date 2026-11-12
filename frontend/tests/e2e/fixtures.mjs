// Mock API payloads for the admin e2e suite (no real backend needed).
const now = Date.now();
const iso = (m) => new Date(now - m * 60000).toISOString();
const uid = (n) => `7f3c2a1e-0000-4000-8000-${String(n).padStart(12, "0")}`;
export function buildData(role) {
  return {
  "auth/setup-status": { self_service_signup_enabled: false },
  "auth/me": { user_id: uid(1), tenant_id: "t1", tenant_name: "الشركة الأولى", email: role + "@mirsad.test", role, aal: "aal2", amr: [], auth_provider: "email", mfa_required: false },
  "platform/tools/status": { tools: [{ key: "network", name: "Network", status: "UP", enabled: true }, { key: "web", name: "Web crawler", status: "UP", enabled: true }, { key: "api", name: "API security", status: "DOWN", enabled: true }], all_defaults_enabled: true },
  "admin/tenants": { tenants: [{ tenant_id: "t1", name: "الشركة الأولى", created_at: iso(9999) }, { tenant_id: "t2", name: "Acme Security Ltd", created_at: iso(9999) }] },
  "admin/overview": { tenant_id: "t1", actor: {}, users: { total: 24, active: 21, admins: 3 }, api_keys: 5, active_sessions: 12, active_jobs: 2 },
  "admin/health": { checks: { database: "ok", worker: "ok", scheduler: "degraded", zap_engine: "down", redis_cache: "ok" }, environment: "production", target_scope_enforced: true },
  "admin/backup": { status: "healthy", note: "Daily PostgreSQL dump verified 3 hours ago; retention 14 days.", application_triggered_backup: false },
  "admin/users": { users: [
    { user_id: uid(1), email: "owner@mirsad.test", role: "owner", is_active: true, created_at: iso(9000), tenant_id: "t1", tenant_name: "الشركة الأولى" },
    { user_id: uid(2), email: "very.long.administrator.email.address.for.layout.testing@subdomain.example-organization.com", role: "admin", is_active: true, created_at: iso(900), tenant_id: "t1", tenant_name: "الشركة الأولى" },
    { user_id: uid(3), email: "analyst@mirsad.test", role: "analyst", is_active: true, created_at: iso(500), tenant_id: "t1", tenant_name: "الشركة الأولى" },
    { user_id: uid(4), email: "viewer@mirsad.test", role: "viewer", is_active: false, created_at: iso(300), tenant_id: "t1", tenant_name: "الشركة الأولى" },
  ], total: 4 },
  "admin/permissions": { permissions: [], role_matrix: { viewer: ["findings:read", "reports:read"], analyst: ["findings:read", "scans:run", "compliance:read"], admin: ["users:manage", "keys:manage", "policies:write"], owner: ["*"] } },
  "admin/policies": { security: { session_timeout_minutes: 60, max_failed_logins: 5, require_mfa_for_admins: true, allow_self_signup: false }, scan: { max_concurrent_scans: 4, require_scope_approval: true, safe_mode: true }, ai: { enable_gemini: true, redact_pii: true }, notifications: {} },
  "admin/audit": { events: Array.from({ length: 8 }, (_, i) => ({ id: i, event: i === 7 ? "=HYPERLINK(\"http://x\")" : ["user.create", "policy.update", "apikey.revoke", "session.revoke_all"][i % 4], target: i % 2 ? uid(i) : "tenant:t1", created_at: iso(i * 37 + 3) })) },
  "admin/features": { network_scan: true, web_scan: true, api_security: false, gemini_analysis: true, continuous_monitoring: false },
  "admin/api-keys": { keys: [
    { key_id: "key_8f2a91c4", name: "CI pipeline", user_id: uid(2), scopes: ["scans:run", "reports:read"], expires_at: iso(-60 * 24 * 40), last_used_at: iso(25), revoked: false, created_at: iso(5000) },
    { key_id: "key_77d0be12", name: "Legacy export", user_id: uid(3), scopes: ["reports:read"], expires_at: null, last_used_at: null, revoked: true, created_at: iso(9000) },
  ] },
  "admin/sessions": { sessions: Array.from({ length: 5 }, (_, i) => ({ id: `s${i}`, user_id: uid(i + 1), created_at: iso(i * 90), expires_at: iso(-60 * 8), revoked: i === 3 })) },
  "admin/security/summary": { open_alerts: 7, critical_alerts: 2, open_incidents: 3, events_24h: 148 },
  "admin/security/alerts": { alerts: [
    { alert_id: "a1", event_id: "evt_91", title: "Repeated failed logins from a single IP address", severity: "high", status: "open", risk_score: 78, data: {}, created_at: iso(14), acknowledged_at: null },
    { alert_id: "a2", event_id: "evt_44", title: "New public admin endpoint exposed", severity: "critical", status: "acknowledged", risk_score: 93, data: {}, created_at: iso(120), acknowledged_at: iso(60) },
    { alert_id: "a3", event_id: null, title: "TLS certificate expiring", severity: "medium", status: "resolved", risk_score: 40, data: {}, created_at: iso(900), acknowledged_at: iso(800) },
  ] },
  "admin/incidents": { incidents: [
    { incident_id: "inc_1021", title: "Possible credential stuffing campaign", description: "", severity: "high", status: "open", assignee_user_id: null, sla_due_at: null, related_asset_id: null, related_scan_id: null, related_finding_id: null, related_user_id: null, evidence: [], timeline: [], ai_explanation: null, created_at: iso(200), updated_at: iso(100) },
  ] },
  "admin/security/events": { events: Array.from({ length: 6 }, (_, i) => ({ event_id: `e${i}`, event_type: ["auth.failed", "scan.started", "asset.discovered", "policy.violation"][i % 4], severity: ["high", "info", "low", "medium"][i % 4], actor_user_id: null, target: null, data: {}, risk_score: 20 + i * 11, detected: true, created_at: iso(i * 53 + 4) })) },
  "continuous/schedules": { schedules: [
    { schedule_id: "sch_01", target: "https://shop.example.com", interval_seconds: 3600, last_status: "completed" },
    { schedule_id: "sch_02", target: "https://api.example.com", interval_seconds: 900, last_status: "" },
  ] },
};
}
