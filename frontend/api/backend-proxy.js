// Same-origin gateway for the separately hosted MIRSAD FastAPI service.
// MIRSAD_BACKEND_URL is server-only; do not prefix it with VITE_.
const FORWARD_REQUEST_HEADERS = [
  'accept', 'authorization', 'content-type', 'x-api-key',
  'if-none-match', 'if-match', 'idempotency-key', 'range',
];
const FORWARD_RESPONSE_HEADERS = [
  'content-type', 'content-disposition', 'cache-control',
  'etag', 'last-modified', 'retry-after', 'x-request-id',
  'accept-ranges', 'content-range',
];

function backendOrigin() {
  const raw = process.env.MIRSAD_BACKEND_URL?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    // Reject credentials, path prefixes, fragments and non-TLS public origins.
    if (url.protocol !== 'https:' || url.username || url.password ||
        url.pathname !== '/' || url.search || url.hash) return null;
    return url;
  } catch {
    return null;
  }
}

function routeFrom(query) {
  const route = query?.route;
  if (typeof route !== 'string' || route.length > 2000 ||
      !/^\/(?:health|api\/v1(?:\/|$))/.test(route) ||
      (route !== '/health' && !route.startsWith('/api/v1/')) ||
      /[\\?#\x00-\x1f]/.test(route) || route.split('/').includes('..')) return null;
  return route;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const origin = backendOrigin();
  if (!origin) {
    return res.status(503).json({ error: 'MIRSAD backend is not configured.' });
  }
  const route = routeFrom(req.query);
  if (!route) return res.status(404).json({ error: 'Not found.' });
  const method = req.method || 'GET';
  if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method)) {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const url = new URL(route, origin);
  // URL normalization can turn encoded dot segments into a different path.
  if (url.pathname !== '/health' && !url.pathname.startsWith('/api/v1/')) {
    return res.status(404).json({ error: 'Not found.' });
  }
  for (const [key, value] of Object.entries(req.query || {})) {
    if (key === 'route') continue;
    if (Array.isArray(value)) for (const item of value) url.searchParams.append(key, String(item));
    else if (value !== undefined) url.searchParams.append(key, String(value));
  }
  const headers = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const value = req.headers[name];
    if (typeof value === 'string') headers.set(name, value);
  }

  let body;
  if (!['GET', 'HEAD'].includes(method)) {
    const input = req.body;
    if (Buffer.isBuffer(input) || typeof input === 'string') body = input;
    else if (input === undefined || input === null) body = undefined;
    else if (headers.get('content-type')?.toLowerCase().includes('application/json')) body = JSON.stringify(input);
    else return res.status(415).json({ error: 'Unsupported body. Uploads should use the direct backend endpoint.' });
  }
  try {
    const upstream = await fetch(url, {
      method,
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(55000),
    });
    for (const name of FORWARD_RESPONSE_HEADERS) {
      const value = upstream.headers.get(name);
      if (value !== null) res.setHeader(name, value);
    }
    // Do not expose the upstream Location header: redirects may point to an
    // internal hostname, and our public API expects machine-readable responses.
    const bytes = Buffer.from(await upstream.arrayBuffer());
    return res.status(upstream.status).send(bytes);
  } catch {
    return res.status(502).json({ error: 'MIRSAD backend is unavailable.' });
  }
}
