#!/bin/sh
set -eu

# Runtime guard only. The Trivy vulnerability DB is intentionally downloaded
# during the backend image build, never when a worker starts.
if [ "${ENABLE_TRIVY:-true}" != "true" ]; then
    exec "$@"
fi

CACHE_DIR="${TRIVY_CACHE_DIR:-/opt/trivy-cache}"
if ! find "$CACHE_DIR" -type f -name 'trivy.db' -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: Trivy DB is missing from the image at $CACHE_DIR." >&2
    echo "Rebuild the backend image; runtime registry downloads are disabled by design." >&2
    if [ "${TRIVY_DB_REQUIRED:-false}" = "true" ]; then
        exit 1
    fi
fi

exec "$@"
