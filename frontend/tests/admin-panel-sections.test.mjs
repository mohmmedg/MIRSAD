import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const sectionsDir = fileURLToPath(new URL('../src/components/admin/sections/', import.meta.url));
const panelUrl = new URL('../src/components/AdminPanel.tsx', import.meta.url);
const routeUrl = new URL('../src/components/admin/AdminSectionRoute.tsx', import.meta.url);
const names = [
  'AdminOverviewSection', 'AdminUsersSection', 'AdminSecuritySection',
  'AdminSocSection', 'AdminSessionsSection', 'AdminKeysSection',
  'AdminFeaturesSection', 'AdminOperationsSection', 'AdminAsmSection',
];

test('all nine administration sections are independent component modules', async () => {
  const files = await readdir(sectionsDir);
  for (const component of names) {
    assert.ok(files.includes(`${component}.tsx`), `${component} must have its own module`);
    const source = await readFile(join(sectionsDir, `${component}.tsx`), 'utf8');
    assert.match(source, new RegExp(`export function ${component}\\b`));
  }
});

test('AdminPanel is a layout route; section bodies are rendered by nested routes', async () => {
  const source = await readFile(panelUrl, 'utf8');
  assert.match(source, /<Outlet context=\{sectionModel\} \/>/);
  assert.match(source, /adminTabFromPath\(pathname, ownerMode\)/);
  for (const component of names) assert.doesNotMatch(source, new RegExp(`<${component}\\b`));
  assert.doesNotMatch(source, /\{tab === "overview" && \(/);
  assert.doesNotMatch(source, /\{tab === "users" && \(/);
});

test('section modules use the existing language provider and shared bilingual helper', async () => {
  const files = await readdir(sectionsDir);
  for (const file of files.filter((name) => name.endsWith('.tsx'))) {
    const source = await readFile(join(sectionsDir, file), 'utf8');
    assert.match(source, /useLanguage\(\)/, `${file} must read the active language`);
    assert.match(source, /adminSectionText/, `${file} must use bilingual labels`);
  }
});

test('presentation modules keep API orchestration out of section components', async () => {
  const files = await readdir(sectionsDir);
  for (const file of files.filter((name) => name.endsWith('.tsx'))) {
    const source = await readFile(join(sectionsDir, file), 'utf8');
    assert.doesNotMatch(source, /import\s+(?!type\b).*from\s+["'].*api\/client/);
    assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/);
    assert.doesNotMatch(source, /window\.confirm/, `${file} must use ConfirmDialog, not window.confirm`);
  }
  const users = await readFile(join(sectionsDir, 'AdminUsersSection.tsx'), 'utf8');
  assert.match(users, /canChangeRole/);
  assert.match(users, /canDelete/);
  assert.match(users, /canResetPassword/);
  const keys = await readFile(join(sectionsDir, 'AdminKeysSection.tsx'), 'utf8');
  assert.match(keys, /makeKey/);
  assert.match(keys, /onRevokeKey/);
});

test('destructive actions are confirmed before they run', async () => {
  for (const [file, handler] of [
    ['AdminUsersSection.tsx', 'removeUser'],
    ['AdminKeysSection.tsx', 'onRevokeKey'],
    ['AdminSessionsSection.tsx', 'onRevokeAllSessions'],
    ['AdminAsmSection.tsx', 'removeAsmSchedule'],
  ]) {
    const source = await readFile(join(sectionsDir, file), 'utf8');
    assert.match(source, /<ConfirmDialog/, `${file} must confirm`);
    assert.match(source, new RegExp(`onConfirm=\\{[^}]*${handler}`), `${file} must call ${handler} only from onConfirm`);
  }
});

test('domain authorization and tenant-scoped cache orchestration stay in AdminPanel', async () => {
  const source = await readFile(panelUrl, 'utf8');
  assert.match(source, /const canManage = ownerMode \? role === "owner" : role === "admin"/);
  assert.match(source, /const targetTenantId = ownerMode \? selectedTenantId : undefined/);
  assert.match(source, /const resourceMap: Record<Tab, string\[]>/);
  assert.match(source, /invalidateTenantResources\(cacheScope, \["keys", "overview"\]\)/);
  assert.match(source, /const \[newSecret, setNewSecret\] = useState<string \| null>/);
  assert.doesNotMatch(source, /localStorage\.setItem\([^\n]*(?:secret|password|api.?key)/i);
});

test('each section is lazy-loaded from its own module (no barrel re-export)', async () => {
  const route = await readFile(routeUrl, 'utf8');
  for (const component of names) assert.match(route, new RegExp(`import\\("\\./sections/${component}"\\)`));
  const panel = await readFile(panelUrl, 'utf8');
  assert.doesNotMatch(panel, /from "\.\/admin\/sections"/);
});

test('admin validation and confirmation messages are bilingual', async () => {
  const source = await readFile(panelUrl, 'utf8');
  assert.match(source, /const adminText = \(ar: string, en: string\) => isArabic \? ar : en/);
  assert.match(source, /adminText\("لا توجد مؤسسة متاحة للإدارة\.", "No organization is available to manage\."\)/);
  const users = await readFile(join(sectionsDir, 'AdminUsersSection.tsx'), 'utf8');
  assert.match(users, /حذف الحساب \$\{deleteTarget\?\.email \?\? ""\} نهائيًا من منصة MIRSAD؟/);
  assert.match(users, /Permanently delete the account \$\{deleteTarget\?\.email \?\? ""\} from MIRSAD\?/);
});
