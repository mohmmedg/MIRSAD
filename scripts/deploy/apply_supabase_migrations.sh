#!/usr/bin/env bash
set -euo pipefail
: "${SUPABASE_PROJECT_REF:?Set SUPABASE_PROJECT_REF}"
if ! command -v supabase >/dev/null 2>&1; then
  echo 'Supabase CLI is required.' >&2
  exit 1
fi
supabase link --project-ref "$SUPABASE_PROJECT_REF"
supabase db push
