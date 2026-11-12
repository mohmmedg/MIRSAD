# MIRSAD Enterprise SOC Admin Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose and redesign all nine MIRSAD administration sections into a responsive bilingual Enterprise Security + SOC Command Center without changing domain behavior.

**Architecture:** Keep API orchestration, tenant cache, and authorization as the stable domain boundary. Extract the page chrome, grouped navigation, KPI primitives, then extract each tab body into a typed section component. Shared styling and translation dictionaries live beside the administration UI.

**Tech Stack:** React 19, TypeScript 6, CSS Modules, lucide-react, existing `LanguageContext`, Node built-in test runner.

**Spec:** `docs/superpowers/specs/2026-11-04-admin-enterprise-soc-design.md`

## Global Constraints

- No backend/API/database/schema changes.
- No changes to `.env`, secrets, Docker volumes, or scan data.
- Preserve all existing authorization guards, tenant scoping, API payloads, and cache invalidation.
- No new runtime dependencies.
- Use existing MIRSAD design tokens and `LanguageContext`.

## Review Focus

- Owner switching across cached and uncached tenants → verify cache restore and selected tenant callback behavior.
- Admin versus owner role boundaries → run existing security regression tests and inspect all moved action guards.
- One-time API key/password reveal → verify secret remains transient and copy/close actions remain functional.
- Arabic/English direction and long IDs → verify logical CSS and responsive wrapping.
- Empty/loading/error states → verify they remain visible and do not hide actionable content.

---

### Task 1: Extract page chrome and grouped navigation

**Files:**
- Create: `src/components/admin/AdminPanelChrome.tsx`
- Create: `src/components/admin/AdminPanelChrome.module.css`
- Modify: `src/components/AdminPanel.tsx`
- Modify: `src/components/AdminPanel.module.css`
- Test: `tests/admin-panel-architecture.test.mjs`

**Interfaces:**
- `AdminPanelHeader` receives owner mode, tenant options, selected tenant ID, tenant change callback, refresh callback, disabled state, and loading state.
- `AdminPanelNavigation` receives current tab and `onTabChange`.
- `AdminPanelStats` receives typed stat items `{ icon: LucideIcon; value: number; label: string }[]`.

- [x] Write failing architecture tests for the chrome exports and all nine grouped navigation entries.
- [x] Run `node --test tests/admin-panel-architecture.test.mjs` and confirm the expected missing-module failure.
- [x] Implement the chrome components using the existing language context.
- [x] Replace inline header/navigation/KPI markup in `AdminPanel.tsx` with extracted components.
- [x] Run focused tests and inspect authorization/data-flow diff. (Focused architecture tests and frontend security regression passed; full build remains blocked by missing dependencies.)

### Task 2: Extract Overview section

**Files:** Create `src/components/admin/sections/AdminOverviewSection.tsx`; modify `AdminPanel.tsx`; tests in `tests/admin-panel-sections.test.mjs`.
- [x] Add failing tests for health and backup content contracts.
- [x] Move overview-only presentation into the section component; retain data fetching and cache ownership in the parent.
- [x] Verify loading/empty data states and existing health/backup values.

### Task 3: Extract Users section

**Files:** Create `src/components/admin/sections/AdminUsersSection.tsx`; modify `AdminPanel.tsx`.
- [x] Add regression tests for role options and action guard inputs.
- [x] Move user list/forms/role controls/password reset presentation with explicit typed callbacks.
- [x] Verify owner/admin hierarchy and self-delete restrictions remain unchanged.

### Task 4: Extract Security and SOC sections

**Files:** Create `AdminSecuritySection.tsx`, `AdminSocSection.tsx`; modify `AdminPanel.tsx`.
- [x] Add tests for alert/incident/event state and update callback wiring.
- [x] Move each section's presentation without changing endpoint calls or payloads.
- [x] Verify empty states and severity/status semantics.

### Task 5: Extract Sessions and Keys sections

**Files:** Create `AdminSessionsSection.tsx`, `AdminKeysSection.tsx`; modify `AdminPanel.tsx`.
- [x] Add tests for revoke actions and one-time key reveal contract.
- [x] Move session/key presentation and forms into independent components.
- [x] Verify secrets are not persisted and revocation still invalidates the correct cache resources.

### Task 6: Extract Features, Operations, and ASM sections

**Files:** Create `AdminFeaturesSection.tsx`, `AdminOperationsSection.tsx`, `AdminAsmSection.tsx`; modify `AdminPanel.tsx`.
- [x] Add tests for feature toggles, operational status, and ASM schedule callbacks.
- [x] Move section presentation while preserving mutation and cache behavior.
- [x] Verify all existing actions and forms remain reachable.

### Task 7: Bilingual polish and responsive/accessibility pass

**Files:** admin component CSS modules and localization dictionary.
- [x] Add tests for Arabic/English labels and navigation grouping.
- [ ] Complete responsive layout, focus states, accessible labels, empty/loading states, and logical CSS properties.
- [x] Verify desktop/tablet/mobile widths and RTL/LTR behavior.

### Task 8: Full verification and security review

**Files:** tests and final docs only if required.
- [x] Run focused architecture and section tests.
- [x] Attempt existing `npm test`, `npm run lint`, and `npm run build`; build/test blocked by unavailable `vite/client` and `@types/node`, lint blocked because `oxlint` is not installed. `npm ci` could not download packages because registry DNS returned `EAI_AGAIN`.
- [x] Run security regression tests and review diff for API/auth/cache changes.
- [x] Report exact commands, exit codes, limitations, and changed files.


## Implementation completion record (2026-11-04)

- All nine section bodies now live in independent files under `src/components/admin/sections/`.
- `AdminPanel.tsx` remains the domain orchestrator: API calls, tenant cache, authorization, loading/error state, and mutation callbacks.
- `AdminPolicyCard.tsx` is a separate reusable policy editor.
- Section callbacks keep tenant-scoped cache invalidation and reload behavior in the parent.
- All new section headings/actions and common empty states use the existing `LanguageContext` (Arabic/English); global direction remains controlled by the provider.
- Responsive CSS now uses fluid section/KPI grids, wrapping rows, and small-screen single-column layouts.
- Focused tests: 10/10 passed. Security regression test passed. Temporary-stub TypeScript check for the changed admin component graph passed with no unused locals/parameters. Syntax transpilation passed for 14 changed admin TS/TSX modules.
- Full production build and Oxlint remain unverified because frontend dependencies could not be installed in this environment (`EAI_AGAIN` to registry.npmjs.org); exact failed commands are recorded in the delivery report.
