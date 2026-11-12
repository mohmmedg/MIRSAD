#!/bin/sh
# Remove truncated/corrupt ZAP add-on files (".zap" = zip) before starting ZAP.
# They produce "Invalid add-on ... zip END header not found" on every start; ZAP then falls back to the
# add-on versions bundled in the image. Only files that fail the zip check are deleted.
python3 - <<'PY'
import glob, os, zipfile
for f in glob.glob("/home/zap/.ZAP/plugin/*.zap"):
    try:
        ok = zipfile.is_zipfile(f)
        if ok:
            with zipfile.ZipFile(f) as z:
                ok = z.testzip() is None
    except Exception:
        ok = False
    if not ok:
        print(f"[start-zap] removing corrupt add-on: {f}", flush=True)
        try:
            os.remove(f)
        except OSError as e:
            print(f"[start-zap] could not remove {f}: {e}", flush=True)
PY
# API key (2026-10-17): the ZAP REST API is no longer open. The key is generated once by the
# zap-key-init service into a shared volume; refuse to start without it (fail closed).
KEY_FILE="${ZAP_API_KEY_FILE:-/zap-secrets/zap_api_key}"
i=0
while [ ! -s "$KEY_FILE" ] && [ "$i" -lt 30 ]; do i=$((i+1)); sleep 1; done
if [ ! -s "$KEY_FILE" ]; then
  echo "[start-zap] FATAL: ZAP API key file $KEY_FILE is missing; refusing to start with an unauthenticated API" >&2
  exit 1
fi
ZAP_KEY="$(cat "$KEY_FILE")"
# The Compose API address allow-list explicitly permits the internal service host "zap".
exec zap.sh -config "api.key=${ZAP_KEY}" "$@"
