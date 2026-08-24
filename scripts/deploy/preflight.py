#!/usr/bin/env python3
import os, sys
required = ["SUPABASE_URL", "DATABASE_URL", "ENFORCE_TARGET_SCOPE", "ALLOWED_TARGETS", "CORS_ORIGINS"]
missing = [k for k in required if not os.getenv(k)]
if missing:
    print("Missing:", ", ".join(missing)); sys.exit(1)
if os.getenv("ENVIRONMENT") == "production" and os.getenv("ENFORCE_TARGET_SCOPE", "").lower() != "true":
    print("ENFORCE_TARGET_SCOPE must be true in production"); sys.exit(1)
if os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() == os.getenv("VITE_SUPABASE_ANON_KEY", "__never__"):
    print("Refusing to use the same Supabase service-role and browser key"); sys.exit(1)
print("Production environment preflight: PASS")
