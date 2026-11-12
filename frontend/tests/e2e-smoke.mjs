import assert from "node:assert/strict";

const backend = process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000";
const frontend = process.env.E2E_FRONTEND_URL ?? "http://127.0.0.1:5173";
const apiKey = process.env.E2E_API_KEY ?? "e2e-test-key";
const bearerToken = process.env.E2E_BEARER_TOKEN ?? "";
const authHeaders = bearerToken ? { Authorization: `Bearer ${bearerToken}` } : { "X-API-Key": apiKey };

async function get(url, headers = {}) {
  const response = await fetch(url, { headers });
  const text = await response.text();
  return { response, text };
}

const health = await get(`${backend}/health`);
assert.equal(health.response.status, 200, health.text);
assert.match(health.text, /"status"\s*:\s*"ok"/);

const readiness = await get(`${backend}/readiness`);
assert.equal(readiness.response.status, 200, readiness.text);
assert.match(readiness.text, /"status"\s*:\s*"ready"/);

const unauthenticated = await fetch(`${backend}/api/v1/network/scan`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ target: "127.0.0.1", scan_type: "quick" }),
});
assert.equal(unauthenticated.status, 401);

const frontendResponse = await fetch(frontend);
assert.equal(frontendResponse.status, 200);
const frontendHtml = await frontendResponse.text();
assert.match(frontendHtml, /<script[^>]+type="module"/);

const authenticated = await fetch(`${backend}/api/v1/network/scan`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    ...authHeaders,
  },
  body: JSON.stringify({ target: "127.0.0.1", scan_type: "quick" }),
});
assert.ok([200, 400, 403, 500].includes(authenticated.status));
assert.notEqual(authenticated.status, 401);

console.log("E2E smoke checks passed");
