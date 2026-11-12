import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const dist = join(root, "dist");

test("production build exists and contains an entry document", () => {
  assert.equal(existsSync(join(dist, "index.html")), true);
  const html = readFileSync(join(dist, "index.html"), "utf8");
  assert.match(html, /<script[^>]+type="module"/);
});

test("production bundle is non-empty", () => {
  const assets = join(dist, "assets");
  assert.equal(existsSync(assets), true);
  assert.ok(readdirSync(assets).some((name) => /\.(js|css)$/.test(name)));
});

test("API client uses bearer sessions and keeps credentials out of query strings", () => {
  const source = readFileSync(join(root, "src", "api", "client.ts"), "utf8");
  assert.match(source, /X-API-Key/);
  assert.match(source, /Authorization/);
  assert.match(source, /getAccessToken/);
  assert.doesNotMatch(source, /[?&]api[_-]?key=/i);
  assert.doesNotMatch(source, /console\.log\([^)]*getApiKey/i);
  assert.doesNotMatch(source, /service_role/i);
});

test("raw-results polling stops after a terminal scan status", () => {
  const source = readFileSync(join(root, "src", "pages", "RawScanResultsPage.tsx"), "utf8");
  assert.match(source, /isTerminal\s*=\s*terminal\.has\(String\(jr\.status\)\.toLowerCase\(\)\)/);
  assert.match(source, /if\s*\(isTerminal\)\s*\{[\s\S]*?clearTimeout\(timer\)[\s\S]*?\}\s*else if\s*\(!stopped/);
});
