import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { ChevronDown, ShieldCheck } from "lucide-react";
import { useLanguage } from "../i18n/LanguageContext";
import { ADMIN_GROUPS, ADMIN_SECTIONS, adminBasePath, adminSectionPath } from "./admin/adminRoutes";
import shell from "../App.module.css";

/**
 * Collapsible "Platform administration" entry. Each child is a real route (/admin/users, ...),
 * so the browser back button, deep links and the active highlight all work per page.
 * Kept free of Tailwind/shadcn on purpose: the sidebar lives in the main bundle.
 */
export function SidebarAdminGroup({ ownerMode }: { ownerMode: boolean }) {
  const { language } = useLanguage();
  const lang = language === "ar" ? "ar" : "en";
  const { pathname } = useLocation();
  const base = adminBasePath(ownerMode);
  const inside = pathname === base || pathname.startsWith(`${base}/`);
  // null = follow the route (open while inside the admin area); a click pins an explicit state.
  const [pinned, setPinned] = useState<boolean | null>(null);
  const open = pinned ?? inside;
  const label = ownerMode ? (lang === "ar" ? "إدارة المنصة" : "Platform administration") : (lang === "ar" ? "إدارة المؤسسة" : "Organization administration");
  const panelId = `admin-nav-${ownerMode ? "platform" : "tenant"}`;

  return (
    <div className={shell.navGroup} data-open={open}>
      <button
        type="button"
        className={`${shell.navItem} ${shell.navGroupToggle} ${inside ? shell.navGroupActive : ""}`}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setPinned(!open)}
      >
        <ShieldCheck size={16} />
        <span>{label}</span>
        <ChevronDown size={14} className={shell.navChevron} aria-hidden="true" />
      </button>
      <div className={shell.navSubWrap} id={panelId}>
        <ul className={shell.navSub}>
          {ADMIN_SECTIONS.map((section, index) => {
            const heading = section.group !== ADMIN_SECTIONS[index - 1]?.group ? ADMIN_GROUPS[section.group][lang] : null;
            const Icon = section.icon;
            return (
              <li key={section.key}>
                {heading && <span className={shell.navSubLabel}>{heading}</span>}
                <NavLink
                  to={adminSectionPath(ownerMode, section)}
                  end={section.path === ""}
                  className={({ isActive }) => `${shell.navSubItem} ${isActive ? shell.navSubActive : ""}`}
                >
                  <Icon size={14} />
                  <span>{section.label[lang]}</span>
                </NavLink>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
