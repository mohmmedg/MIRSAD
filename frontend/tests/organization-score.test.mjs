import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const component = readFileSync(`${root}/src/pages/OverviewPage.tsx`, "utf8");
const styles = readFileSync(`${root}/src/components/UnifiedDashboard.module.css`, "utf8");

test("organization score uses a dedicated summary layout, not the four-column dashboard metric grid", () => {
  const start = component.indexOf("function OrganizationScoreCard()");
  const end = component.indexOf("\nexport function OverviewPage()", start);
  assert.notEqual(start, -1);
  const card = component.slice(start, end);
  assert.match(card, /organizationScoreSummary/);
  assert.doesNotMatch(card, /styles\.metricGrid/);
});

test("organization asset rows use a dedicated overflow-safe layout", () => {
  assert.match(component, /organizationAssetRow/);
  assert.match(component, /organizationAssetTarget/);
  assert.match(styles, /\.organizationAssetRow\s*\{[^}]*minmax\(0/);
  assert.match(styles, /\.organizationAssetTarget\s*\{[^}]*min-width:\s*0/);
});

test("organization risk score explains that higher values mean greater risk", () => {
  assert.match(component, /كلما ارتفعت الدرجة زادت المخاطر/);
});
