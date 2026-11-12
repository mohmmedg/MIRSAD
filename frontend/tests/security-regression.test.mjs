import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const SRC = path.resolve(new URL("../src", import.meta.url).pathname);
const CODE_EXT = /\.(tsx?|jsx?|mjs|css)$/;

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const p = path.join(dir, entry.name);
    return entry.isDirectory() ? files(p) : CODE_EXT.test(entry.name) ? [p] : [];
  });
}

test("frontend security regression checks", () => {
  const sourceFiles = files(SRC);
  assert.ok(sourceFiles.length >= 56, `expected at least 56 source files, found ${sourceFiles.length}`);

  const forbidden = [
    /dangerouslySetInnerHTML/,
    /\.innerHTML\s*=/,
    /insertAdjacentHTML\s*\(/,
    /\beval\s*\(/,
    /\bnew\s+Function\s*\(/,
    /document\.write\s*\(/,
  ];
  for (const file of sourceFiles) {
    const text = fs.readFileSync(file, "utf8");
    for (const pattern of forbidden) {
      assert.doesNotMatch(text, pattern, `${pattern} found in ${file}`);
    }
  }

  const security = fs.readFileSync(path.join(SRC, "utils/security.ts"), "utf8");
  for (const symbol of ["safeUserError", "safeDiagnosticText", "validateTarget"]) {
    assert.match(security, new RegExp(`export function ${symbol}\\b`), `${symbol} is missing`);
  }

  const boundary = fs.readFileSync(path.join(SRC, "components/ErrorBoundary.tsx"), "utf8");
  assert.doesNotMatch(boundary, /this\.state\.error\?\.message/);

  const client = fs.readFileSync(path.join(SRC, "api/client.ts"), "utf8");
  assert.match(client, /httpStatusMessage/);
  assert.doesNotMatch(client, /detail\s*=\s*errorBody\.detail/);

  console.log(`Frontend security regression checks passed for ${sourceFiles.length} source files.`);
});
