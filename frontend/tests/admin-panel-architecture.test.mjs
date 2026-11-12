import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (rel) => readFile(new URL(`../src/${rel}`, import.meta.url), 'utf8');
const TABS = ['overview', 'users', 'security', 'soc', 'sessions', 'keys', 'features', 'operations', 'asm'];

test('admin chrome exports the header and KPI components', async () => {
  const source = await read('components/admin/AdminPanelChrome.tsx');
  for (const component of ['AdminPanelHeader', 'AdminPanelStats']) {
    assert.match(source, new RegExp(`export function ${component}\\b`));
  }
});

test('route metadata declares all nine admin sections with bilingual copy', async () => {
  const source = await read('components/admin/adminRoutes.ts');
  for (const tab of TABS) assert.match(source, new RegExp(`key: "${tab}"`));
  assert.match(source, /label: \{ ar:/);
  assert.match(source, /title: \{ ar:/);
  // The sidebar lives in the main bundle: the shared metadata must not pull in Tailwind/shadcn.
  assert.doesNotMatch(source, /@\/components\/ui|admin\.css|tailwind/);
});

test('admin chrome consumes the existing language provider', async () => {
  const source = await read('components/admin/AdminPanelChrome.tsx');
  assert.match(source, /useLanguage\(\)/);
  assert.match(source, /language === "ar"/);
});

test('KPI grid is fluid instead of fixed at six columns', async () => {
  const source = await read('components/admin/AdminPanelChrome.tsx');
  assert.match(source, /repeat\(auto-fit,minmax\(min\(100%,[\d.]+rem\),1fr\)\)/);
});

test('overview and SOC share the same bilingual responsive KPI component', async () => {
  const overview = await read('components/admin/sections/AdminOverviewSection.tsx');
  const soc = await read('components/admin/sections/AdminSocSection.tsx');
  assert.match(overview, /<AdminPanelStats items=/);
  assert.match(soc, /<AdminPanelStats items=/);
  const chrome = await read('components/admin/AdminPanelChrome.tsx');
  assert.match(chrome, /statLabels:/);
  assert.match(chrome, /المستخدمون/);
});

test('every admin page is a nested route under /admin and /tenant-admin', async () => {
  const app = await read('App.tsx');
  assert.match(app, /<Route path="\/admin" element=\{<AdminPage \/>\}>/);
  assert.match(app, /<Route path="\/tenant-admin" element=\{<TenantAdminPage \/>\}>/);
  assert.match(app, /ADMIN_SECTIONS\.map/);
  assert.match(app, /<Navigate to="\/admin" replace \/>/);
  const route = await read('components/admin/AdminSectionRoute.tsx');
  for (const tab of TABS) assert.match(route, new RegExp(`\\b${tab}: lazy\\(`));
});

test('sidebar exposes a collapsible administration group with per-page links', async () => {
  const sidebar = await read('components/Sidebar.tsx');
  assert.match(sidebar, /<SidebarAdminGroup ownerMode=\{canManagePlatform\} \/>/);
  const group = await read('components/SidebarAdminGroup.tsx');
  assert.match(group, /aria-expanded=\{open\}/);
  assert.match(group, /adminSectionPath\(ownerMode, section\)/);
  assert.doesNotMatch(group, /@\/components\/ui|admin\.css/);
});

test('privileged re-validation in AuthGate covers every /admin/* page', async () => {
  const gate = await read('auth/AuthGate.tsx');
  assert.match(gate, /pathname === "\/admin" \|\| pathname\.startsWith\("\/admin\/"\)/);
  assert.doesNotMatch(gate, /location\.pathname !== "\/admin"/);
});

test('Tailwind is scoped to the admin area: no preflight, utilities loaded only by AdminPanel', async () => {
  const css = await read('admin-ui/admin.css');
  assert.doesNotMatch(css, /tailwindcss\/preflight|@import "tailwindcss";/);
  const panel = await read('components/AdminPanel.tsx');
  assert.match(panel, /import "@\/admin-ui\/admin\.css"/);
  for (const main of ['main.tsx', 'App.tsx', 'components/Sidebar.tsx', 'components/TopBar.tsx']) {
    assert.doesNotMatch(await read(main), /admin\.css/, `${main} must not load the admin stylesheet`);
  }
});
