import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const tokens = readFileSync(new URL("../src/styles/tokens.css", import.meta.url), "utf8");
const dashboard = readFileSync(new URL("../src/components/UnifiedDashboard.module.css", import.meta.url), "utf8");
const severityStats = readFileSync(new URL("../src/components/SeverityStats.module.css", import.meta.url), "utf8");
const statsComponent = readFileSync(new URL("../src/components/SeverityStats.tsx", import.meta.url), "utf8");
const overview = readFileSync(new URL("../src/pages/OverviewPage.tsx", import.meta.url), "utf8");
const riskPage = readFileSync(new URL("../src/pages/RiskPage.tsx", import.meta.url), "utf8");

const vivid = {
  critical: "#ff3b4f",
  high: "#ff941f",
  medium: "#ffd43b",
  low: "#22d17a",
  info: "#32bfff",
};

test("defines a vivid severity color palette shared by dashboard themes", () => {
  for (const [severity, color] of Object.entries(vivid)) {
    assert.match(tokens, new RegExp(`--sev-${severity}-vivid:\\s*${color.replace("#", "#")}`, "i"));
  }
});

test("risk chart dots and fills use vivid severity colors, not dim badge backgrounds", () => {
  for (const severity of Object.keys(vivid)) {
    assert.match(dashboard, new RegExp(`\\.sevDot\\.${severity}[^}]*background:\\s*var\\(--sev-${severity}-vivid\\)`, "s"));
    assert.match(dashboard, new RegExp(`\\.barFill\\.${severity}[^}]*background:\\s*var\\(--sev-${severity}-vivid\\)`, "s"));
  }
});

test("severity cards and distribution segments stay vivid even when a severity count is zero", () => {
  assert.doesNotMatch(severityStats, /\.statCard\.dimmed\s*\{\s*opacity:\s*0\.[0-9]+/);
  assert.doesNotMatch(statsComponent, /count\s*===\s*0\s*\?\s*styles\.dimmed/);
  for (const severity of Object.keys(vivid)) {
    assert.match(severityStats, new RegExp(`\\.seg${severity[0].toUpperCase()}${severity.slice(1)}\\s*\\{[^}]*background:\\s*var\\(--sev-${severity}-vivid\\)`, "s"));
  }
});

test("home and risk pages render severity labels with their vivid category color", () => {
  assert.match(dashboard, /\.severityLabel\[data-severity="critical"\]\s*\{\s*color:\s*var\(--sev-critical-vivid\)/);
  assert.match(overview, /className=\{styles\.severityLabel\}\s+data-severity=\{sev\.toLowerCase\(\)\}/);
  assert.match(riskPage, /className=\{styles\.severityLabel\}\s+data-severity=\{sev\.toLowerCase\(\)\}/);
});
