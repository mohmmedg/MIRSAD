# Tests Supabase connectivity from INSIDE the Docker backend network.
# Run with the VPN enabled:
#   .\scripts\test-vpn-supabase.ps1
$ErrorActionPreference = 'Stop'
Write-Host "Testing Supabase connectivity from the backend container..." -ForegroundColor Cyan
docker compose run --rm --no-deps backend python -c "import os,socket; from urllib.parse import urlparse; u=urlparse(os.environ['DATABASE_URL']); print('DB host:',u.hostname); print('DB port:',u.port); print('DNS:',socket.gethostbyname_ex(u.hostname)); import psycopg2; c=psycopg2.connect(os.environ['DATABASE_URL'],connect_timeout=15,sslmode='require'); print('PostgreSQL: CONNECTED'); c.close()"
