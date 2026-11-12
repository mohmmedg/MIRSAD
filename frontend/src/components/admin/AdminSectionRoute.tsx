import { Suspense, lazy } from "react";
import { useOutletContext } from "react-router-dom";
import type { AdminPanelSectionModel } from "./AdminPanelSectionModel";
import type { AdminTab } from "./adminRoutes";
import { RowsSkeleton } from "./AdminPrimitives";

// One lazy chunk per administration page: opening /admin/users never downloads the SOC code.
const sections = {
  overview: lazy(() => import("./sections/AdminOverviewSection").then((m) => ({ default: m.AdminOverviewSection }))),
  soc: lazy(() => import("./sections/AdminSocSection").then((m) => ({ default: m.AdminSocSection }))),
  security: lazy(() => import("./sections/AdminSecuritySection").then((m) => ({ default: m.AdminSecuritySection }))),
  users: lazy(() => import("./sections/AdminUsersSection").then((m) => ({ default: m.AdminUsersSection }))),
  sessions: lazy(() => import("./sections/AdminSessionsSection").then((m) => ({ default: m.AdminSessionsSection }))),
  keys: lazy(() => import("./sections/AdminKeysSection").then((m) => ({ default: m.AdminKeysSection }))),
  features: lazy(() => import("./sections/AdminFeaturesSection").then((m) => ({ default: m.AdminFeaturesSection }))),
  operations: lazy(() => import("./sections/AdminOperationsSection").then((m) => ({ default: m.AdminOperationsSection }))),
  asm: lazy(() => import("./sections/AdminAsmSection").then((m) => ({ default: m.AdminAsmSection }))),
} satisfies Record<AdminTab, unknown>;

/** Route element for one admin page; the data model comes from the AdminPanel layout route. */
export function AdminSectionRoute({ section }: { section: AdminTab }) {
  const model = useOutletContext<AdminPanelSectionModel>();
  const Section = sections[section];
  return (
    <Suspense fallback={<RowsSkeleton />}>
      <Section model={model} />
    </Suspense>
  );
}
