// Single source of truth for the administration sections: route path, icon, group and
// bilingual copy. Imported by the (main-bundle) Sidebar AND the lazy admin area, so it
// must stay dependency-light: lucide icons and types only, no Tailwind / shadcn imports.
import type { LucideIcon } from "lucide-react";
import { Activity, Blocks, KeyRound, LayoutDashboard, ListChecks, LogOut, ScanSearch, ShieldAlert, Users } from "lucide-react";

export type AdminTab =
  | "overview"
  | "soc"
  | "security"
  | "users"
  | "sessions"
  | "keys"
  | "features"
  | "operations"
  | "asm";

export type AdminGroupId = "command" | "security" | "identity" | "platform";

type Bilingual = { ar: string; en: string };

export type AdminSectionMeta = {
  key: AdminTab;
  /** Path segment under the base path; "" is the index route. */
  path: string;
  icon: LucideIcon;
  group: AdminGroupId;
  label: Bilingual;
  title: Bilingual;
  description: Bilingual;
};

export const ADMIN_GROUPS: Record<AdminGroupId, Bilingual> = {
  command: { ar: "مركز القيادة", en: "Command" },
  security: { ar: "الأمن والمراقبة", en: "Security operations" },
  identity: { ar: "الهوية والوصول", en: "Identity & access" },
  platform: { ar: "إعدادات المنصة", en: "Platform configuration" },
};

// Order here is the order shown in the sidebar and on the overview hub.
export const ADMIN_SECTIONS: AdminSectionMeta[] = [
  {
    key: "overview", path: "", icon: LayoutDashboard, group: "command",
    label: { ar: "نظرة عامة", en: "Overview" },
    title: { ar: "نظرة عامة على الإدارة", en: "Administration overview" },
    description: { ar: "مؤشرات المنصة وصحة الخدمات وحالة النسخ الاحتياطي.", en: "Platform indicators, service health and backup status." },
  },
  {
    key: "soc", path: "soc", icon: Activity, group: "security",
    label: { ar: "مركز SOC", en: "SOC center" },
    title: { ar: "مركز عمليات الأمن SOC", en: "Security operations center" },
    description: { ar: "التنبيهات والحوادث والخط الزمني لأحداث الاكتشاف.", en: "Alerts, incidents and the detection event timeline." },
  },
  {
    key: "security", path: "security", icon: ShieldAlert, group: "security",
    label: { ar: "الأمن والسياسات", en: "Security & policies" },
    title: { ar: "الأمن والسياسات", en: "Security & policies" },
    description: { ar: "سياسات الأمان وحوكمة الفحص وإعدادات الذكاء الاصطناعي وسجل التدقيق.", en: "Security policies, scan governance, AI settings and the audit log." },
  },
  {
    key: "users", path: "users", icon: Users, group: "identity",
    label: { ar: "المستخدمون", en: "Users" },
    title: { ar: "المستخدمون والصلاحيات", en: "Users & permissions" },
    description: { ar: "إنشاء الحسابات وإدارة الأدوار والحظر وإعادة تعيين كلمات المرور.", en: "Create accounts, manage roles, block users and reset passwords." },
  },
  {
    key: "sessions", path: "sessions", icon: LogOut, group: "identity",
    label: { ar: "الجلسات", en: "Sessions" },
    title: { ar: "الجلسات", en: "Sessions" },
    description: { ar: "مراقبة جلسات الدخول وإبطالها عند الحاجة.", en: "Monitor sign-in sessions and revoke them when needed." },
  },
  {
    key: "keys", path: "keys", icon: KeyRound, group: "identity",
    label: { ar: "مفاتيح API", en: "API keys" },
    title: { ar: "مفاتيح API", en: "API keys" },
    description: { ar: "إنشاء مفاتيح الوصول البرمجي ومتابعة استخدامها وإبطالها.", en: "Issue programmatic access keys, track their use and revoke them." },
  },
  {
    key: "features", path: "features", icon: Blocks, group: "platform",
    label: { ar: "الخصائص", en: "Features" },
    title: { ar: "مفاتيح الخصائص", en: "Feature flags" },
    description: { ar: "تفعيل أو تعطيل خصائص المنصة لكل مؤسسة.", en: "Enable or disable platform capabilities per organization." },
  },
  {
    key: "operations", path: "operations", icon: ListChecks, group: "platform",
    label: { ar: "العمليات", en: "Operations" },
    title: { ar: "العمليات", en: "Operations" },
    description: { ar: "عناصر التحكم التشغيلية وأحدث أحداث التدقيق.", en: "Operational controls and the latest audit events." },
  },
  {
    key: "asm", path: "asm", icon: ScanSearch, group: "platform",
    label: { ar: "مراقبة ASM", en: "ASM monitoring" },
    title: { ar: "المراقبة المستمرة لسطح الهجوم", en: "Continuous attack-surface monitoring" },
    description: { ar: "جدولة مراقبة التغييرات في سطح الهجوم وربطها بمركز SOC.", en: "Schedule attack-surface change monitoring feeding the SOC pipeline." },
  },
];

export const adminBasePath = (ownerMode: boolean): string => (ownerMode ? "/admin" : "/tenant-admin");

export const adminSectionPath = (ownerMode: boolean, section: AdminSectionMeta): string =>
  section.path ? `${adminBasePath(ownerMode)}/${section.path}` : adminBasePath(ownerMode);

export function adminTabFromPath(pathname: string, ownerMode: boolean): AdminTab {
  const base = adminBasePath(ownerMode);
  const rest = pathname.startsWith(base) ? pathname.slice(base.length).replace(/^\/+|\/+$/g, "") : "";
  const first = rest.split("/")[0];
  return ADMIN_SECTIONS.find((section) => section.path === first && first !== "")?.key ?? "overview";
}
