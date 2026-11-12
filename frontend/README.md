# MIRSAD Frontend on Vercel

The Vercel project uses **Root Directory: `frontend`**, **Framework: Vite**, and **Output Directory: `dist`**.

- `VITE_SUPABASE_URL=https://<your-project>.supabase.co` — public Supabase API URL.
- `VITE_SUPABASE_ANON_KEY=<publishable-key>` — public browser key (not a service-role/secret key).
- `MIRSAD_BACKEND_URL=https://<your-fastapi-host>` — **server-only**, deployed FastAPI origin without a trailing path. Only HTTPS is accepted. Keep this value private to Vercel functions; never prefix it `VITE_`.
- `VITE_API_BASE_URL=` — leave empty for same-origin `/api/v1/*` and `/health` through `api/backend-proxy.js`. Set to an external HTTPS backend origin to bypass the proxy (requires FastAPI CORS configuration).
- `VITE_WS_BASE_URL=wss://<your-fastapi-host>` — optional direct WebSocket origin. When omitted, scan progress falls back to polling if the same-origin gateway cannot upgrade WebSockets.

The gateway is a **forwarder, not a scanner**: it passes the existing user Bearer token to FastAPI, which must enforce authorization, target scope and rate limits. It only forwards `/api/v1/` and `/health` to the fixed `MIRSAD_BACKEND_URL`. It intentionally does not proxy arbitrary destinations, follow redirects or publish server credentials. JSON API requests are supported. Large/multipart uploads and extended streaming operations should use a direct backend URL and CORS; Vercel Functions have request/response size and duration limits.

**Important:** PostgreSQL/Supabase is already used by MIRSAD's backend and browser login. The background scan worker, Redis, ZAP/DefectDojo, Nmap and Docker-capability scanners do not run inside this frontend Vercel Function. Keep the backend + worker stack on a properly isolated Docker/container host with persistent Redis and durable storage. Configure backend `DATABASE_URL`, `SUPABASE_URL`, issuer/JWKS, `REDIS_URL`, and `CORS_ORIGINS` on that host. `SUPABASE_SERVICE_ROLE_KEY` must never be exposed to the frontend bundle. Never deploy `.env`, `.git` or database exports.

Without `MIRSAD_BACKEND_URL`, the gateway responds with an explicit **503** instead of silently loading the SPA or targeting the visitor's `localhost`. Check `GET /health` after configuring the backend.
