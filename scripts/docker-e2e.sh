#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export POSTGRES_PASSWORD="e2e-postgres-password"
export POSTGRES_DB="security_scanner"
export POSTGRES_USER="scanner"

TMP_DIR="$(mktemp -d)"
ORIGINAL_BACKEND_ENV_PRESENT=false
ORIGINAL_FRONTEND_ENV_PRESENT=false
if [[ -f backend/.env ]]; then ORIGINAL_BACKEND_ENV_PRESENT=true; cp backend/.env "$TMP_DIR/backend.env.original"; fi
if [[ -f frontend/.env ]]; then ORIGINAL_FRONTEND_ENV_PRESENT=true; cp frontend/.env "$TMP_DIR/frontend.env.original"; fi
cleanup() {
  docker compose -f docker-compose.yml -f docker-compose.e2e.yml down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$ORIGINAL_BACKEND_ENV_PRESENT" == true ]]; then cp "$TMP_DIR/backend.env.original" backend/.env; else rm -f backend/.env; fi
  if [[ "$ORIGINAL_FRONTEND_ENV_PRESENT" == true ]]; then cp "$TMP_DIR/frontend.env.original" frontend/.env; else rm -f frontend/.env; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "$TMP_DIR/backend.env" <<EOF
ENVIRONMENT=development
API_KEY=e2e-test-key
ENFORCE_TARGET_SCOPE=false
GEMINI_API_KEY=
CORS_ORIGINS=http://localhost:5173
DATABASE_URL=postgresql+psycopg://scanner:e2e-postgres-password@postgres:5432/security_scanner
REDIS_URL=redis://redis:6379/0
JOB_QUEUE_ENABLED=true
EOF
cat > "$TMP_DIR/frontend.env" <<EOF
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_API_KEY=e2e-test-key
EOF

# Compose's env_file paths are relative to the compose file, so create temporary
# project env files and remove them in cleanup.
cp "$TMP_DIR/backend.env" backend/.env
cp "$TMP_DIR/frontend.env" frontend/.env

docker compose -f docker-compose.yml -f docker-compose.e2e.yml up -d --build

for i in {1..60}; do
  if curl -fsS http://127.0.0.1:8000/readiness >/tmp/sgm-readiness.json 2>/dev/null; then break; fi
  sleep 2
done

curl -fsS http://127.0.0.1:8000/health >/dev/null
curl -fsS http://127.0.0.1:8000/readiness >/dev/null
curl -fsS http://127.0.0.1:5173/ >/tmp/sgm-frontend.html

test "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/api/v1/network/scan -H 'Content-Type: application/json' -d '{"target":"127.0.0.1","scan_type":"quick"}')" = "401"

test "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/api/v1/network/scan -H 'Content-Type: application/json' -H 'X-API-Key: e2e-test-key' -d '{"target":"127.0.0.1","scan_type":"quick"}')" != "401"

echo "Docker E2E smoke checks passed"
