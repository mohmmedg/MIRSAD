# MIRSAD

**MIRSAD** is a full-stack security operations platform (Security SaaS) that scans networks and websites, correlates findings, and produces AI-assisted and rule-based security reports for different audiences — technical, managerial, and non-technical.

Built as a graduation/portfolio project demonstrating secure API design, multi-tenant SaaS architecture, and applied offensive-security tooling.

> An Arabic version of this document is available at [`README.ar.md`](./README.ar.md).

---

## What it does

- **Network scanning** — wraps `nmap` to discover hosts, open ports, and services on authorized targets only.
- **Web scanning** — crawls and inspects websites (TLS config, security headers, basic XSS/SQLi checks) via `httpx`.
- **Finding correlation** — links related findings across scans into unified security incidents.
- **Dual analysis engines** — a Gemini-powered AI analyzer and a fully deterministic rule-based analyzer examine the same findings independently.
- **Audience-specific reporting** — the same findings are formatted into technical, managerial, or non-technical reports.
- **Continuous Attack Surface Monitoring (ASM)** — a durable, multi-replica scheduler that re-scans registered assets on a recurring basis.
- **Compliance Center** — tracks compliance posture and includes a CI/CD security gate that can fail builds on policy violations.
- **Security Center** — MFA/AAL-aware session handling, security events, alerts, and incident management.
- **Multi-tenant isolation** — every tenant's data is isolated at the database level via Postgres Row-Level Security (RLS).

## Architecture

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   Frontend (Vercel)         │        │   Backend (self-hosted)       │
│   React 19 + TypeScript     │  HTTP  │   FastAPI + Uvicorn            │
│   Vite, React Router v7     │───────▶│   nmap / httpx scanners         │
│   Supabase Auth (browser)   │        │   Celery worker + Redis queue  │
└─────────────────────────────┘        │   PostgreSQL (via Supabase)    │
                                        └──────────────────────────────┘
                                                     │
                                          ┌──────────┴──────────┐
                                          │   Gemini API          │
                                          │   (AI analysis)       │
                                          └────────────────────────┘
```

- **Frontend** — deployed on Vercel, root directory `frontend/`. Talks to Supabase directly for auth, and to the FastAPI backend for scans/findings/reports.
- **Backend** — FastAPI service with independent modules under `backend/app/modules/` (network scan, web scan, correlator, risk engine, AI analysis, rule-based analysis, reporting, compliance, asset inventory, API security). Requires a host that supports long-running processes and Docker (e.g. Render, Railway, a VPS) — **not** deployable on Vercel serverless.
- **Database** — Supabase Postgres, with all schema/RLS policies defined as versioned SQL migrations in `supabase/migrations/`.
- **Job queue** — Redis + Celery worker for scan scheduling and the Continuous ASM scheduler.

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript, Vite, React Router v7, Tailwind |
| Backend | FastAPI, Uvicorn, Pydantic v2, SQLAlchemy |
| Database / Auth | Supabase (Postgres + RLS + Auth) |
| Queue | Redis, Celery |
| AI | Google Gemini API |
| Scanning | nmap, httpx |
| Reports | ReportLab (PDF) |

## Project structure

```
frontend/          React dashboard (deployed on Vercel)
  src/pages/        Overview, Scans, Findings, Risk, Assets, Attack Surface,
                     Compliance, Security, Reports, AI, Admin
  api/               Vercel serverless functions (auth/user/health)
backend/            FastAPI service
  app/api/routes/    HTTP endpoints (scans, findings, analysis, compliance, admin, ...)
  app/modules/       Independent domain modules (scanners, analyzers, correlator, ...)
  tests/             Unit + integration test suite
supabase/
  migrations/        Versioned SQL schema + RLS policies (0001–0007)
scripts/             Deployment, security-gate, and CI helper scripts
```

## Running locally

### Backend

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your own values
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
cp .env.example .env   # fill in your own Supabase project values
npm run dev
```

### Full stack (Docker)

```bash
docker compose up --build
```

## Deployment

- **Frontend** → Vercel (root directory: `frontend/`)
- **Backend** → any Docker-capable host with a persistent process (Render, Railway, a VPS). Vercel cannot run the backend — it only runs the frontend and a few lightweight serverless functions.
- **Database** → Supabase project (apply migrations from `supabase/migrations/` in order)

## Security notes

- Scans only run against targets explicitly allow-listed via `ALLOWED_TARGETS` / tenant scope guards.
- Every tenant's data is isolated at the database level via Postgres RLS — see `supabase/migrations/`.
- API keys and service-role credentials are never exposed to the frontend bundle; they're only used server-side.
- This project is a portfolio/thesis demonstration of secure API and SaaS design — not a replacement for professional penetration-testing tools (Burp Suite, sqlmap, OWASP ZAP, Nessus, etc.).

## License

See [LICENSE](./LICENSE) if present, or contact the repository owner.
