$ErrorActionPreference='Stop'
Write-Host '== Backend compile =='
python -m compileall -q .\backend\app
Write-Host '== Backend tests =='
Push-Location .\backend
pytest -q
Pop-Location
Write-Host '== Frontend install + build + smoke =='
Push-Location .\frontend
npm ci
npm run build
node --test tests/smoke.test.mjs
Pop-Location
Write-Host '== Production configuration sanity =='
if (-not (Test-Path .\.env)) { throw 'Root .env is required for Docker Compose. Copy .env.example to .env and set POSTGRES_PASSWORD.' }
Write-Host '== Docker E2E =='
docker compose -f .\docker-compose.yml -f .\docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from backend-test
