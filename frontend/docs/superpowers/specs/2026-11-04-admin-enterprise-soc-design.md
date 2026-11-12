# MIRSAD Enterprise SOC Control Center — Design Specification

## Intent

Rebuild the platform administration experience as a bilingual (Arabic/English), responsive Enterprise Security + SOC Command Center. The current `AdminPanel.tsx` owns nine administrative views and all API/state workflows in one 1,800-line component. The redesign must improve hierarchy, navigation, density, and responsive behavior without changing the security or business semantics.

## Goals

- Decompose the administration UI into focused layout, navigation, shared primitives, and nine independently maintained section modules.
- Present all nine sections: Overview, Users, Security, SOC, Sessions, Keys, Features, Operations, and ASM.
- Provide bilingual labels through the existing `LanguageContext`; Arabic uses RTL and English uses LTR.
- Use a responsive enterprise shell: clear header and tenant context, grouped navigation, responsive KPI cards, and consistent section surfaces.
- Retain existing API functions, request payloads, tenant cache semantics, loading/error behavior, and permission gates.
- Preserve one-time display of newly created API keys/passwords and existing copy/close behavior.
- Keep existing MIRSAD tokens and severity semantics; no new runtime dependencies.

## Non-goals

- No backend/API/schema changes, auth model changes, permission changes, data migrations, or new admin capabilities.
- No changes to `.env`, secrets, database contents, Docker volumes, or scan data.
- No replacement of the global language provider or application-wide localization architecture.

## Anti-goals / safety invariants

- Never weaken `canManage`, role hierarchy, per-user action guards, or tenant scoping.
- Never expose API secrets except in the existing post-creation one-time reveal flow.
- Never change cache invalidation or mutate API result shapes as part of visual refactoring.
- Do not remove any of the nine sections or existing actions.
- Do not introduce hard-coded layout widths that clip content at common desktop/tablet/mobile sizes.

## Current architecture and evidence

- `frontend/src/components/AdminPanel.tsx` contains the nine tab branches, tenant selection, API calls, in-memory tenant cache, role checks, mutation handlers, and `PolicyCard` (about 1,800 lines).
- `frontend/src/components/AdminPanel.module.css` provides the page styles; `.stats` is hard-coded to six columns and `.grid` to two columns, explaining the cramped KPI layout at constrained widths.
- The owner tenant selector is embedded in a generic `.row`, while the nine tabs are rendered as a single ungrouped horizontal list.
- The project already has `LanguageProvider`, `useLanguage()`, and global `dir` handling in `src/i18n/LanguageContext.tsx`; the redesign should consume it rather than duplicate language state.
- Existing API and role logic remains in `AdminPanel` during the first extraction boundary, then moves with section ownership only where props/interfaces can be made explicit and tested.

## Approaches considered

1. **CSS-only reskin:** lowest effort but leaves the 1,800-line component and mixed concerns intact; rejected because the user selected full component decomposition.
2. **Full rewrite of data flows and admin domain logic:** offers a clean slate but risks permission/cache/API regressions; rejected as unsafe and unnecessary.
3. **Incremental UI decomposition around stable domain logic (selected):** extract chrome/navigation/KPI primitives first, then move each section into focused components with typed props while keeping API orchestration and authorization behavior unchanged. This delivers the selected architecture with reviewable, testable boundaries.

## Experience architecture

- **Admin shell:** page identity, bilingual title/subtitle, tenant context selector (owner mode), refresh action, error/loading/secret notices.
- **Grouped navigation:**
  - Command: Overview.
  - Security Operations: SOC, Security.
  - Identity & Access: Users, Sessions, Keys.
  - Platform Configuration: Features, Operations, ASM.
- **Overview:** KPI strip, platform health, backup/recovery.
- **Users:** user lifecycle, role selection, password reset, permissions; retain current role gates.
- **Security:** policies, audit, security events/alerts/incidents as currently wired.
- **SOC:** detection summary and alerts/incidents/events with existing update actions.
- **Sessions:** active/revoked session list and revoke actions.
- **Keys:** create/revoke keys and one-time secret reveal.
- **Features:** feature flag toggles.
- **Operations:** operational health and audit events.
- **ASM:** continuous schedules and target/interval controls.

## Visual system

- Reuse existing MIRSAD CSS variables (`--bg-panel`, `--bg-panel-raised`, `--line`, `--accent-action`, typography and radius tokens).
- Enterprise surfaces with restrained borders, layered panel backgrounds, compact metadata, consistent 12–16px radii, and clear focus states.
- SOC emphasis uses semantic status colors only for health/severity; avoid using severity colors as decoration.
- KPI grid uses `repeat(auto-fit, minmax(min(100%, 190px), 1fr))`; section grids collapse based on available width.
- Tables/lists must allow long identifiers to wrap or truncate safely; no fixed-width overflow.

## Localization and accessibility

- Use `useLanguage()` from the existing provider for `language` and `dir`.
- All new chrome labels must have Arabic and English values in one typed dictionary.
- Buttons have accessible names; selected navigation exposes `aria-current="page"` or an equivalent tab semantic; focus indicators remain visible.
- Use logical CSS properties (`margin-inline`, `padding-inline`, `inset-inline`) and avoid direction-specific assumptions.

## Data and security boundaries

- Existing API client calls and payloads are invariant.
- Existing `ownerMode`, `role`, `canManage`, `targetTenantId`, `selectedTenantId`, cache restore/invalidation, and mutation handlers remain authoritative.
- Section components receive only the data and callbacks they need; do not pass auth tokens or secret material except the current one-time reveal view.
- No localStorage persistence for sensitive admin state.

## Acceptance criteria

1. All nine sections remain reachable and preserve their current actions.
2. All existing role checks and tenant boundaries are unchanged (verified by regression tests and diff review).
3. Arabic/English labels switch with the existing language toggle; page direction follows the provider.
4. Header, navigation, KPI grid, and section content do not clip at desktop, tablet, or mobile widths.
5. Empty, loading, and error states are explicit and accessible.
6. Frontend typecheck/build and existing test suite pass; any unavailable verification is explicitly reported.
