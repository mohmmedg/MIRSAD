import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import handler from '../api/backend-proxy.js'

const previous = process.env.MIRSAD_BACKEND_URL
const oldFetch = globalThis.fetch
after(() => {
  if (previous === undefined) delete process.env.MIRSAD_BACKEND_URL
  else process.env.MIRSAD_BACKEND_URL = previous
  globalThis.fetch = oldFetch
})

function reply() {
  return {
    code: 200, headers: {}, payload: undefined,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; return this },
    status(code) { this.code = code; return this },
    json(data) { this.payload = data; return this },
    send(data) { this.payload = data; return this },
  }
}

test('missing or insecure backend fails closed', async () => {
  delete process.env.MIRSAD_BACKEND_URL
  const res = reply()
  await handler({ method: 'GET', query: { route: '/health' }, headers: {} }, res)
  assert.equal(res.code, 503)
  process.env.MIRSAD_BACKEND_URL = 'http://localhost:8000'
  await handler({ method: 'GET', query: { route: '/health' }, headers: {} }, res)
  assert.equal(res.code, 503)
})

test('proxy allows only scoped API routes and preserves auth but not Host', async () => {
  process.env.MIRSAD_BACKEND_URL = 'https://api.example.test'
  let captured
  globalThis.fetch = async (url, options) => {
    captured = { url: String(url), options }
    return new Response(JSON.stringify({ ok: true }), { status: 201, headers: { 'content-type': 'application/json' } })
  }
  const blocked = reply()
  await handler({ method: 'GET', query: { route: '//external.example/' }, headers: {} }, blocked)
  assert.equal(blocked.code, 404)
  const escaped = reply()
  await handler({ method: 'GET', query: { route: '/api/v1/%2e%2e/private' }, headers: {} }, escaped)
  assert.equal(escaped.code, 404)
  const res = reply()
  await handler({ method: 'POST', query: { route: '/api/v1/jobs', name: 'sample' }, headers: { authorization: 'Bearer example-token', host: 'attacker.example', 'content-type': 'application/json' }, body: { target: 'example.com' } }, res)
  assert.equal(res.code, 201)
  assert.equal(captured.url, 'https://api.example.test/api/v1/jobs?name=sample')
  assert.equal(captured.options.headers.get('authorization'), 'Bearer example-token')
  assert.equal(captured.options.headers.get('host'), null)
  assert.equal(captured.options.body, JSON.stringify({ target: 'example.com' }))
  assert.equal(JSON.parse(res.payload.toString()).ok, true)
})

test('network failures are explicit and do not expose upstream errors', async () => {
  process.env.MIRSAD_BACKEND_URL = 'https://api.example.test'
  globalThis.fetch = async () => { throw new Error('backend internal hostname') }
  const res = reply()
  await handler({ method: 'GET', query: { route: '/health' }, headers: {} }, res)
  assert.equal(res.code, 502)
  assert.doesNotMatch(JSON.stringify(res.payload), /hostname/)
})
