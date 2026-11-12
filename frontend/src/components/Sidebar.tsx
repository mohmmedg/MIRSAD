import { NavLink, useLocation } from "react-router-dom";
import {
  Activity,
  History,
  Bot,
  Boxes,
  ChartNoAxesCombined,
  FileText,
  LayoutDashboard,
  Network,
  Settings,
  ShieldCheck,
  Siren,
  Waypoints,
  FileCode2,
  ListChecks,
} from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import { useEffect, useState } from "react";
import { getToolStatus, type ToolStatus } from "../api/client";
import { MirsadMark } from "./MirsadMark";
import { SidebarAdminGroup } from "./SidebarAdminGroup";
import shell from "../App.module.css";

export interface NavEntry {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  /** Extra path prefixes that should also mark this entry active (sub-pages not in the sidebar itself). */
  match?: string[];
}

export function Sidebar({ role }: { role: string | null }) {
  const { language } = useLanguage();
  const location = useLocation();
  const canManageTenant = role === "admin";
  const canManagePlatform = role === "owner";
  const [tools, setTools] = useState<ToolStatus[]>([]);
  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const result = await getToolStatus();
        if (!cancelled) setTools(result.tools);
      } catch {
        if (!cancelled) setTools([]);
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, []);

  const primaryNav: NavEntry[] = [
    { to: "/", label: language === "ar" ? "نظرة عامة" : "Overview", icon: LayoutDashboard },
    { to: "/scans", label: language === "ar" ? "الفحوصات" : "Scans", icon: Activity },
    { to: "/scan-progress", label: language === "ar" ? "تقدم الفحص" : "Scan progress", icon: Activity },
    { to: "/findings", label: language === "ar" ? "الاكتشافات" : "Findings", icon: Siren },
    { to: "/risk", label: language === "ar" ? "المخاطر" : "Risk", icon: ChartNoAxesCombined },
    { to: "/reports", label: language === "ar" ? "التقارير" : "Reports", icon: FileText },
    { to: "/scan-history", label: language === "ar" ? "سجل الفحوصات" : "Scan history", icon: History },
  ];
  const advancedNav: NavEntry[] = [
    { to: "/assets", label: language === "ar" ? "الأصول" : "Assets", icon: Boxes },
    { to: "/attack-surface", label: language === "ar" ? "سطح الهجوم" : "Attack Surface", icon: Waypoints },
    { to: "/attack-surface-intelligence", label: language === "ar" ? "ذكاء سطح الهجوم" : "Attack surface graph", icon: Network },
    { to: "/ai", label: language === "ar" ? "ذكاء Gemini" : "AI Intelligence", icon: Bot },
    { to: "/defectdojo", label: "DefectDojo", icon: ShieldCheck },
    { to: "/scan-execution", label: language === "ar" ? "تنفيذ الفحص" : "Scan execution", icon: ListChecks, match: ["/scan-execution/"] },
    { to: "/raw-results", label: language === "ar" ? "البيانات الخام" : "Raw data", icon: FileCode2, match: ["/scan-history/"] },
  ];

  const governanceNav: NavEntry[] = [
    { to: "/security", label: language === "ar" ? "الأمان والوصول" : "Security", icon: ShieldCheck },
  ];
  if (role === "admin" || role === "owner" || role === "analyst") {
    governanceNav.push({ to: "/compliance", label: language === "ar" ? "الامتثال و CI/CD" : "Compliance & CI/CD", icon: ShieldCheck });
  }

  return (
    <aside className={shell.sidebar} aria-label="Primary navigation">
      <div className={shell.brandBlock}>
        <span className={shell.brandMark}>
          <MirsadMark size={68} />
        </span>
        <div>
          <strong>مرصاد</strong>
          <span>MIRSAD</span>
        </div>
      </div>

      <nav className={shell.nav}>
        <div className={shell.navLabel}>{language === "ar" ? "أساسي" : "Primary"}</div>
        {primaryNav.map(({ to, label, icon: Icon, match }) => {
          const path = location.pathname;
          const isActive =
            to === "/"
              ? path === "/"
              : path === to || path.startsWith(`${to}/`) ||
                (match ?? []).some((m) => path === m || path.startsWith(`${m}/`));
          return (
            <NavLink
              key={to}
              to={to}
              className={`${shell.navItem} ${isActive ? shell.navActive : ""}`}
            >
              <Icon size={16} />
              <span>{label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className={shell.sidebarDivider} />

      <nav className={shell.nav}>
        <div className={shell.navLabel}>{language === "ar" ? "متقدّم" : "Advanced"}</div>
        {advancedNav.map(({ to, label, icon: Icon, match }) => {
          const path = location.pathname;
          const isActive = to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`) || (match ?? []).some((m) => path === m || path.startsWith(`${m}/`));
          return <NavLink key={to} to={to} className={`${shell.navItem} ${isActive ? shell.navActive : ""}`}><Icon size={16} /><span>{label}</span></NavLink>;
        })}
      </nav>

      <div className={shell.sidebarDivider} />
      <nav className={shell.nav}>
        <div className={shell.navLabel}>{language === "ar" ? "الأمان والامتثال" : "Security & compliance"}</div>
        {governanceNav.map(({ to, label, icon: Icon, match }) => {
          const path = location.pathname;
          const isActive = to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`) || (match ?? []).some((m) => path === m || path.startsWith(`${m}/`));
          return <NavLink key={to} to={to} className={`${shell.navItem} ${isActive ? shell.navActive : ""}`}><Icon size={16} /><span>{label}</span></NavLink>;
        })}
      </nav>

      {(canManagePlatform || canManageTenant) && (
        <>
          <nav className={shell.nav}>
            <div className={shell.navLabel}>{language === "ar" ? "الإدارة" : "Administration"}</div>
            <SidebarAdminGroup ownerMode={canManagePlatform} />
          </nav>
        </>
      )}

      <div className={shell.sidebarDivider} />
      <nav className={shell.nav}>
        <NavLink
          to="/settings"
          className={({ isActive }) => `${shell.navItem} ${isActive ? shell.navActive : ""}`}
        >
          <Settings size={16} />
          <span>{language === "ar" ? "الإعدادات" : "Settings"}</span>
        </NavLink>
      </nav>

      <div className={shell.sidebarDivider} />
      <div className={shell.engineStatus}>
        <div className={shell.engineTitle}>
          <Network size={14} /> {language === "ar" ? "محركات وأدوات الفحص" : "Scan engines & tools"}
        </div>
        {(tools.length ? tools : [
          { key: "network", name: "Network", status: "DOWN" as const, enabled: false, status_reason: undefined },
          { key: "web", name: "Web crawler", status: "DOWN" as const, enabled: false, status_reason: undefined },
          { key: "api", name: "API security", status: "DOWN" as const, enabled: false, status_reason: undefined },
        ]).map((tool) => (
          <span key={tool.key} title={tool.status_reason || (tool.status === "UP" ? "Ready / enabled" : (tool.enabled ? "Enabled but unavailable" : "Disabled"))}>
            <i className={tool.status === "UP" ? shell.engineUp : shell.engineDown} />
            {tool.name}
          </span>
        ))}
      </div>
    </aside>
  );
}
