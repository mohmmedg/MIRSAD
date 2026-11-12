// Browser e2e for the administration area: owner vs admin access, tenant-scoped loading,
// audit-log filtering and CSV export. Runs against `vite preview` with a mocked API,
// so it needs no backend, database or Supabase.
//
//   npm i && npx playwright install chromium   # once
//   npm run e2e:ui
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { after, before, describe, it } from "node:test";
import { buildData } from "./fixtures.mjs";

const { chromium } = createRequire(import.meta.url)("playwright");
const PORT = Number(process.env.E2E_UI_PORT ?? 4179);
const BASE = `http://127.0.0.1:${PORT}`;
const API = "http://127.0.0.1:8000/api/v1";

let server;
let browser;

async function openAs(role, path, mutate) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  await ctx.addInitScript((r) => {
    localStorage.setItem("mirsad_supabase_session", JSON.stringify({ access_token: "x.eyJhYWwiOiJhYWwyIn0.y", refresh_token: "r", expires_in: 99999, expires_at: Math.floor(Date.now() / 1000) + 99999, token_type: "bearer", user: { id: "u" } }));
    localStorage.setItem("mirsad_app_role", r);
    localStorage.setItem("mirsad_theme", "light");
  }, role);
  const data = buildData(role);
  mutate?.(data);
  const page = await ctx.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(e.message));
  await page.route("**/*", (route) => {
    const url = route.request().url();
    if (url.startsWith(API)) {
      const key = url.slice(API.length + 1).split("?")[0];
      const body = key === "jobs/active" ? [] : (data[key] ?? {});
      return route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
    }
    if (url.startsWith(BASE)) return route.continue();
    return route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: "{}" });
  });
  await page.goto(BASE + path, { waitUntil: "networkidle" });
  return { ctx, page, pageErrors };
}

before(async () => {
  server = spawn("npx", ["vite", "preview", "--host", "127.0.0.1", "--port", String(PORT), "--strictPort"], { stdio: "ignore" });
  for (let i = 0; i < 60; i += 1) {
    try { if ((await fetch(BASE)).ok) break; } catch { /* still starting */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  server?.kill();
});

describe("owner", () => {
  it("sees the platform admin area with the tenant selector", async () => {
    const { ctx, page, pageErrors } = await openAs("owner", "/admin/users");
    await page.locator(".admin-ui").waitFor();
    assert.ok(await page.getByText("المؤسسة المستهدفة").count() > 0, "tenant selector missing");
    assert.equal(await page.locator('nav a[href^="/admin"]').count() > 0, true, "sidebar admin links missing");
    assert.deepEqual(pageErrors, []);
    await ctx.close();
  });

  it("cannot reach the tenant-admin area", async () => {
    const { ctx, page } = await openAs("owner", "/tenant-admin/users");
    assert.equal(await page.locator(".admin-ui").count(), 0);
    await ctx.close();
  });

  it("filters the audit log and exports a CSV that defuses formulas", async () => {
    const { ctx, page } = await openAs("owner", "/admin/security");
    const search = page.getByLabel("بحث في سجل التدقيق");
    await search.waitFor();
    const rows = () => page.locator(".admin-ui table tbody tr").count();
    const all = await rows();
    assert.ok(all >= 8, `expected audit rows, got ${all}`);
    await search.fill("policy.update");
    assert.ok((await rows()) < all, "search did not narrow the table");
    await search.fill("zzz-no-match");
    assert.ok(await page.getByText("لا توجد أحداث مطابقة").count() > 0);
    await search.fill("");
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "تصدير CSV" }).click(),
    ]);
    const { readFile } = await import("node:fs/promises");
    const csv = await readFile(await download.path(), "utf8");
    assert.match(csv, /"event","target","created_at"/);
    assert.match(csv, /"'=HYPERLINK/, "formula cell must be prefixed with an apostrophe");
    assert.doesNotMatch(csv, /(^|,)"=HYPERLINK/m);
    await ctx.close();
  });

  it("requires typing the email before deleting an account, then confirms with a toast", async () => {
    const { ctx, page } = await openAs("owner", "/admin/users");
    const row = page.locator(".admin-ui table tbody tr", { hasText: "analyst@mirsad.test" });
    await row.getByRole("button").last().click();
    await page.getByRole("menuitem", { name: "حذف نهائي" }).click();
    const confirm = page.getByRole("alertdialog").getByRole("button", { name: "حذف الحساب" });
    assert.equal(await confirm.isDisabled(), true, "delete must stay locked until the email is typed");
    await page.getByRole("alertdialog").getByRole("textbox").fill("wrong@mirsad.test");
    assert.equal(await confirm.isDisabled(), true);
    await page.getByRole("alertdialog").getByRole("textbox").fill("Analyst@mirsad.test");
    assert.equal(await confirm.isDisabled(), false, "typing the email (any case) unlocks the button");
    await confirm.click();
    await page.getByRole("status").filter({ hasText: "تم حذف الحساب" }).waitFor();
    await ctx.close();
  });

  it("paginates long user lists and resets to page 1 when searching", async () => {
    const { ctx, page } = await openAs("owner", "/admin/users", (data) => {
      for (let i = 0; i < 22; i += 1) {
        data["admin/users"].users.push({ user_id: `bulk-${i}`, email: `bulk${i}@mirsad.test`, role: "analyst", is_active: true, created_at: new Date().toISOString(), tenant_id: "t1", tenant_name: "الشركة الأولى" });
      }
    });
    const rows = () => page.locator(".admin-ui table tbody tr").count();
    const pager = page.getByRole("navigation", { name: "ترقيم الصفحات" });
    await pager.waitFor();
    assert.equal(await rows(), 10);
    await pager.getByText("1 / 3").waitFor();
    await pager.getByRole("button", { name: "الصفحة التالية" }).click();
    await pager.getByText("2 / 3").waitFor();
    await page.locator(".admin-ui").getByRole("searchbox").or(page.locator(".admin-ui input[type=search], .admin-ui input[placeholder]").first()).first().fill("bulk1");
    await pager.getByText("1 / 2").waitFor(); // bulk1, bulk10..bulk19 = 11 matches
    assert.equal(await rows(), 10);
    await ctx.close();
  });

  it("sorts the users table by clicking a column header (asc, desc, original)", async () => {
    const { ctx, page } = await openAs("owner", "/admin/users");
    const first = () => page.locator(".admin-ui table tbody tr").first().innerText();
    const head = page.locator(".admin-ui th", { hasText: "المستخدم" });
    await head.waitFor();
    const original = await first();
    await head.getByRole("button").click();
    await page.locator('.admin-ui th[aria-sort="ascending"]').waitFor();
    assert.match(await first(), /analyst@mirsad\.test/); // alphabetical first email in the mock
    await head.getByRole("button").click();
    await page.locator('.admin-ui th[aria-sort="descending"]').waitFor();
    assert.match(await first(), /viewer@mirsad\.test/);
    await head.getByRole("button").click();
    await page.locator('.admin-ui th[aria-sort="ascending"], .admin-ui th[aria-sort="descending"]').waitFor({ state: "detached" });
    assert.equal(await first(), original);
    await ctx.close();
  });
});

describe("admin", () => {
  it("loads its own tenant data without choosing an organization", async () => {
    const { ctx, page, pageErrors } = await openAs("admin", "/tenant-admin/users");
    await page.locator(".admin-ui").waitFor();
    assert.equal(await page.getByText("المؤسسة المستهدفة").count(), 0, "admins must not see the tenant selector");
    assert.equal(await page.getByText("يرجى اختيار مؤسسة").count(), 0, "regression: admin mode asked for an organization");
    assert.ok(await page.locator(".admin-ui table tbody tr").count() >= 3, "users table is empty");
    assert.deepEqual(pageErrors, []);
    await ctx.close();
  });

  it("cannot reach the platform admin area", async () => {
    const { ctx, page } = await openAs("admin", "/admin/users");
    assert.equal(await page.locator(".admin-ui").count(), 0);
    await ctx.close();
  });
});
