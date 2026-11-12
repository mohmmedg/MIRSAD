FROM zaproxy/zap-stable:2.17.0

# Build-time only. The pinned zap-stable image already bundles the release add-ons
# (spider, AJAX spider, client, active/passive scan rules), and runtime starts with
# autoupdate.autodownload=false, so nothing is downloaded at runtime.
#
# `zap.sh -cmd -addonupdate` is only an optional refresh. On a slow or filtered
# network it hung for the full 3600s and failed the whole `docker compose up`
# (exit 124, 2026-10-05). It is now best-effort: bounded to 3 hours and never
# fatal. Run with --build-arg ZAP_ADDON_UPDATE=false to skip it entirely.
ARG ZAP_ADDON_UPDATE=false
USER zap
RUN set -u; \
    mkdir -p /home/zap/.ZAP; \
    if [ "$ZAP_ADDON_UPDATE" = "true" ]; then \
      echo "== BUILD TOOL START: zap-addons (best-effort, timeout 10800s) =="; \
      timeout 10800 sh -c 'zap.sh -cmd -addonupdate' \
        && echo "== zap add-on update finished ==" \
        || echo "== WARNING: zap add-on update failed or timed out (exit $?); continuing with bundled add-ons =="; \
    else \
      echo "== zap add-on update skipped =="; \
    fi; \
    test -d /home/zap/.ZAP

# Startup wrapper: removes corrupt add-on files, then execs zap.sh.
COPY --chmod=0755 start-zap.sh /usr/local/bin/start-zap.sh
