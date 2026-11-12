# AI-Powered Security Scanner — Backend Dockerfile
#
# يشمل nmap مثبّت بالـ image (مطلوب لمحرك network_scan)، بالإضافة لمكتبات
# النظام اللازمة لبناء بعض حزم بايثون. صورة الإنتاج نهائية (single-stage
# كافٍ هون؛ المشروع صغير بما يكفي إن over-engineering بـ multi-stage build
# ما يستاهل التعقيد الإضافي حالياً).

FROM python:3.12-slim
ARG TARGETARCH=amd64
ARG NUCLEI_VERSION=3.11.1
ARG FFUF_VERSION=2.3.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRUFFLEHOG_VERSION=3.97.9
ARG SEMGREP_VERSION=1.178.0
ARG SUBFINDER_VERSION=2.16.0
ARG HTTPX_VERSION=1.12.0
ARG TRIVY_VERSION=0.74.0
ARG TESTSSL_VERSION=3.2.4
ARG GHAURI_VERSION=1.4.3
ARG NMAP_VERSION=7.991
ARG NMAP_SHA256=A5D507F29437BEF3BEDD4771FF9AAA8FC1C2A109DDBA1F5B1CF12027456929BE

# nmap: أداة فحص الشبكات الأساسية اللي يعتمد عليها network_scan/scanner.py
# ca-certificates: مطلوبة لطلبات HTTPS الصادرة (web_scan، Gemini API)
# libcap2-bin: يوفر setcap — نحتاجه أدناه عشان نعطي nmap صلاحية raw sockets
# لمستخدم غير-root بدل ما نشغّل الحاوية كاملة كـ root (OS detection عبر -O
# يحتاج CAP_NET_RAW/CAP_NET_ADMIN وإلا يفشل بصمت لمستخدم عادي)
# ---------------------------------------------------------------------------
# مقسَّمة إلى طبقات منفصلة: أي فشل تنزيل (شبكة بطيئة/متقطعة) لا يُضيّع الطبقات
# الناجحة السابقة، وتُخزَّن مؤقتاً فلا تُعاد عند إعادة `docker compose build`.
# curl: HTTP/1.1 (تفادي خطأ HTTP/2 PROTOCOL_ERROR) + إعادة المحاولة دون استئناف byte ranges.
# ---------------------------------------------------------------------------
ENV TOOL_STAGE_TIMEOUT=3600
ENV CURL_OPTS="-fsSL --http1.1 --retry 20 --retry-all-errors --retry-delay 10 --retry-max-time 3600 --connect-timeout 120 --speed-time 60 --speed-limit 1024"

# 1) Runtime/build dependencies. Nmap is installed from the pinned Debian base
# repository instead of compiling it from source; the scanner only requires a
# real nmap binary, while compiling Nmap here made every rebuild spend minutes
# downloading and compiling a large toolchain. The container already receives
# NET_RAW/NET_ADMIN from Compose for the probes that require them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates openssl bsdmainutils dnsutils procps libcap2-bin curl git unzip tar bzip2 \
        nmap openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Common build-stage guard: every individual tool download/install stage gets a hard 1-hour wall-clock limit.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'label="$1"; shift' \
    'echo "== BUILD TOOL START: ${label} (hard timeout: 3600s) =="' \
    'if timeout 3600 "$@"; then :; else status=$?; echo "BUILD FAILED: ${label} did not complete successfully within 3600s (exit ${status})" >&2; exit "$status"; fi' \
    'echo "== BUILD TOOL VERIFIED STAGE COMPLETE: ${label} =="' \
    > /usr/local/bin/mirsad-build-tool \
    && chmod +x /usr/local/bin/mirsad-build-tool

# ---------------------------------------------------------------------------
# mirsad-fetch <asset-name> <url> <out-path>   (الحل الجذري لمشكلة التنزيل البطيء)
#  1) إن وُجد الملف مسبقاً في backend/vendor/ يُستخدم مباشرة دون تنزيل جديد.
#  2) وإلا يُنزَّل إلى كاش BuildKit (/dl) مع استئناف: لو فشل البناء أو انقطع الاتصال،
#     المحاولة التالية تعيد التنزيل من البداية؛ لا تستخدم استئناف byte ranges لأن بعض الخوادم لا تدعمه.
# ---------------------------------------------------------------------------
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'name="$1"; url="$2"; out="$3"' \
    'if [ -s "/vendor/$name" ]; then echo "== using vendored $name =="; cp "/vendor/$name" "$out"; exit 0; fi' \
    'mkdir -p /dl' \
    'if [ ! -f "/dl/$name.done" ]; then' \
    '  curl $CURL_OPTS "$url" -o "/dl/$name"' \
    '  touch "/dl/$name.done"' \
    'fi' \
    'cp "/dl/$name" "$out"' \
    > /usr/local/bin/mirsad-fetch \
    && chmod +x /usr/local/bin/mirsad-fetch

COPY vendor/ /vendor/

# Nmap is provided by the OS package above and verified by the global tool gate.

# 2) sqlmap — same pinned release (1.10) as before, but fetched like every other
# tool here: resumable curl through the BuildKit cache (or backend/vendor/sqlmap-1.10.tar.gz
# when present), instead of a bare `git clone` that restarts from zero when the
# connection drops mid-transfer ("RPC failed; curl 56 ... early EOF"). If the
# tarball cannot be fetched, fall back to the original git clone, retried.
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool sqlmap sh -c '''set -eu; \
    rm -rf /opt/sqlmap /tmp/sqlmap-src; \
    if mirsad-fetch "sqlmap-1.10.tar.gz" "https://github.com/sqlmapproject/sqlmap/archive/refs/tags/1.10.tar.gz" /tmp/sqlmap.tgz \
       && mkdir -p /tmp/sqlmap-src && tar -xzf /tmp/sqlmap.tgz -C /tmp/sqlmap-src --strip-components=1 && test -f /tmp/sqlmap-src/sqlmap.py; then \
        mv /tmp/sqlmap-src /opt/sqlmap; rm -f /tmp/sqlmap.tgz; \
    else \
        echo "== sqlmap tarball unavailable, falling back to git clone (with retries) =="; \
        rm -rf /opt/sqlmap /tmp/sqlmap-src /tmp/sqlmap.tgz; \
        ok=0; for i in 1 2 3 4 5 6; do \
            rm -rf /opt/sqlmap; \
            if git -c http.version=HTTP/1.1 -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=300 clone --depth 1 --branch 1.10 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap; then ok=1; break; fi; \
            echo "git clone attempt $i failed; retrying in 15s"; sleep 15; \
        done; \
        [ "$ok" = 1 ]; \
    fi; \
    test -f /opt/sqlmap/sqlmap.py; \
    printf "%s\n" "#!/bin/sh" "exec python3 /opt/sqlmap/sqlmap.py \"\$@\"" > /usr/local/bin/sqlmap; chmod +x /usr/local/bin/sqlmap; \
    sqlmap --version | head -1'''

# 3) Nuclei — download, extract, verify before FFUF starts.
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool nuclei sh -c '''set -eu; \
    NARCH=amd64; [ "$TARGETARCH" = arm64 ] && NARCH=arm64; \
    mirsad-fetch "nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" /tmp/nuclei.zip; \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin; chmod +x /usr/local/bin/nuclei; \
    command -v nuclei >/dev/null; nuclei -version 2>&1 | head -1; rm -f /tmp/nuclei.zip'''

# 4) FFUF — only starts after Nuclei has completed and verified.
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool ffuf sh -c '''set -eu; \
    NARCH=amd64; [ "$TARGETARCH" = arm64 ] && NARCH=arm64; \
    mirsad-fetch "ffuf_${FFUF_VERSION}_linux_${NARCH}.tar.gz" "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${NARCH}.tar.gz" /tmp/ffuf.tgz; \
    tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf; chmod +x /usr/local/bin/ffuf; \
    command -v ffuf >/dev/null; ffuf -V 2>&1 | head -1; rm -f /tmp/ffuf.tgz'''

# 5) Gitleaks
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool gitleaks sh -c '''set -eu; GLARCH=x64; [ "$TARGETARCH" = arm64 ] && GLARCH=arm64; \
    mirsad-fetch "gitleaks_${GITLEAKS_VERSION}_linux_${GLARCH}.tar.gz" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GLARCH}.tar.gz" /tmp/gitleaks.tgz; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; chmod +x /usr/local/bin/gitleaks; \
    command -v gitleaks >/dev/null; gitleaks version; rm -f /tmp/gitleaks.tgz'''

# 6) TruffleHog
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool trufflehog sh -c '''set -eu; THARCH=amd64; [ "$TARGETARCH" = arm64 ] && THARCH=arm64; \
    mirsad-fetch "trufflehog_${TRUFFLEHOG_VERSION}_linux_${THARCH}.tar.gz" "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${THARCH}.tar.gz" /tmp/trufflehog.tgz; \
    tar -xzf /tmp/trufflehog.tgz -C /usr/local/bin trufflehog; chmod +x /usr/local/bin/trufflehog; \
    command -v trufflehog >/dev/null; trufflehog --version; rm -f /tmp/trufflehog.tgz'''

# 7) Subfinder
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool subfinder sh -c '''set -eu; PDARCH=amd64; [ "$TARGETARCH" = arm64 ] && PDARCH=arm64; \
    mirsad-fetch "subfinder_${SUBFINDER_VERSION}_linux_${PDARCH}.zip" "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${PDARCH}.zip" /tmp/subfinder.zip; \
    unzip -q /tmp/subfinder.zip -d /tmp/subfinder; install -m 0755 /tmp/subfinder/subfinder /usr/local/bin/subfinder; \
    command -v subfinder >/dev/null; subfinder -version; rm -rf /tmp/subfinder /tmp/subfinder.zip'''

# 8) ProjectDiscovery httpx
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool pd-httpx sh -c '''set -eu; PDARCH=amd64; [ "$TARGETARCH" = arm64 ] && PDARCH=arm64; \
    mirsad-fetch "httpx_${HTTPX_VERSION}_linux_${PDARCH}.zip" "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${PDARCH}.zip" /tmp/httpx.zip; \
    unzip -q /tmp/httpx.zip -d /tmp/httpx; install -m 0755 /tmp/httpx/httpx /usr/local/bin/pd-httpx; \
    command -v pd-httpx >/dev/null; pd-httpx -version; rm -rf /tmp/httpx /tmp/httpx.zip'''

# 9) Trivy binary
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool trivy sh -c '''set -eu; TRIVY_ARCH=64bit; [ "$TARGETARCH" = arm64 ] && TRIVY_ARCH=ARM64; \
    mirsad-fetch "trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" /tmp/trivy.tgz; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; chmod +x /usr/local/bin/trivy; \
    command -v trivy >/dev/null; trivy --version | head -1; mkdir -p /opt/trivy-cache; rm -f /tmp/trivy.tgz'''

# 10) testssl.sh — same pinned tag as before, fetched as a resumable tarball (or
# backend/vendor/testssl.sh-v${TESTSSL_VERSION}.tar.gz when present) instead of a bare
# `git clone` that restarts from zero on every dropped connection; git clone
# (retried) is kept only as a fallback.
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool testssl sh -c '''set -eu; \
    rm -rf /opt/testssl /tmp/testssl-src; \
    if mirsad-fetch "testssl.sh-v${TESTSSL_VERSION}.tar.gz" "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" /tmp/testssl.tgz \
       && mkdir -p /tmp/testssl-src && tar -xzf /tmp/testssl.tgz -C /tmp/testssl-src --strip-components=1 && test -f /tmp/testssl-src/testssl.sh; then \
        mv /tmp/testssl-src /opt/testssl; rm -f /tmp/testssl.tgz; chmod +x /opt/testssl/testssl.sh; \
    else \
        echo "== testssl tarball unavailable, falling back to git clone (with retries) =="; \
        rm -rf /opt/testssl /tmp/testssl-src /tmp/testssl.tgz; \
        ok=0; for i in 1 2 3 4 5 6; do \
            rm -rf /opt/testssl; \
            if git -c http.version=HTTP/1.1 -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=300 clone --depth 1 --branch "v${TESTSSL_VERSION}" --single-branch https://github.com/testssl/testssl.sh.git /opt/testssl; then ok=1; break; fi; \
            echo "git clone attempt $i failed; retrying in 15s"; sleep 15; \
        done; \
        [ "$ok" = 1 ]; \
    fi; \
    test -x /opt/testssl/testssl.sh; ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh; \
    command -v testssl.sh >/dev/null; testssl.sh --version | head -1'''

# 11) Nuclei templates
ARG NUCLEI_TEMPLATES_VERSION=10.4.9
RUN --mount=type=cache,target=/dl,sharing=locked mirsad-build-tool nuclei-templates sh -c '''set -eu; rm -rf /opt/nuclei-templates; mkdir -p /opt/nuclei-templates; \
    mirsad-fetch "nuclei-templates-v${NUCLEI_TEMPLATES_VERSION}.tar.gz" "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz" /tmp/nt.tgz; \
    tar -xzf /tmp/nt.tgz -C /opt/nuclei-templates --strip-components=1; rm -f /tmp/nt.tgz; \
    test -d /opt/nuclei-templates/http; chmod -R a+rX /opt/nuclei-templates'''

# 4) ملاحظة معمارية: ZAP نفسه غير مثبَّت هنا — لا يُثبَّت داخل صورة backend/
# worker إطلاقاً. سكربتات zap-full-scan.py/zap-baseline.py الرسمية غير
# موجودة أصلاً داخل أرشيف "ZAP_x.y.z_Linux.tar.gz" (هي جزء من صور Docker
# الرسمية فقط)، وتعتمد داخلياً على مسار ثابت مبرمج `/zap/zap-x.sh` مع
# اعتماديات بايثون إضافية (zapv2, six) — محاولة تقليدها هنا هشة وغير
# موثوقة. بدلاً من ذلك: خدمة `zap` في docker-compose.yml (الصورة الرسمية
# zaproxy/zap-stable) تقلع تلقائياً كـ daemon منفصل، ويتحدث معها الباك-إند
# عبر REST API مباشرة (انظر run_zap_service في
# app/modules/external_scanners/engines.py) — تشمل الآن spider + active
# scan حقيقي عند maximum/destructive، وليس enrichment سلبي فقط.

WORKDIR /app

# نسخ requirements أولاً لوحدها عشان طبقة Docker الخاصة بـ pip install
# تُخزَّن مؤقتاً (cache) وما تُعاد إلا لو requirements.txt تغيّر فعلياً —
# أسرع بكثير لإعادة البناء المتكررة أثناء التطوير
COPY requirements.txt .
# Keep dependency resolution deterministic. google-genai 2.25.0 requires
# websockets>=13,<17, so requirements.txt pins the compatible websockets line.
# Installing requirements in one transaction prevents a later requirements.txt
# install from silently replacing a separately preinstalled dependency.
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_DEFAULT_TIMEOUT=600
ENV PIP_RETRIES=20
RUN mirsad-build-tool python-dependencies python -m pip install --no-cache-dir --retries 20 --timeout 3600 -r requirements.txt

# semgrep: مُثبّت بشكل منفصل عن requirements.txt عمداً — شجرة اعتمادات semgrep
# ثقيلة ومستقلة عن اعتمادات التطبيق، وفصلها هنا يمنع أي تعارض إصدارات مستقبلي
# من كسر تثبيت FastAPI/SQLAlchemy الأساسي.
# ملاحظة: كانت هذه الطبقة سابقاً "soft-fail" (|| echo WARNING) بحيث فشل
# التثبيت لا يوقف البناء — لكن هذا بالضبط ما يسبب مفاجآت NOT_INSTALLED
# صامتة أثناء الفحص الفعلي. الآن الفشل هنا يوقف البناء بالكامل، بما
# ينسجم مع خطوة التحقق الشاملة أدناه: لو نجح `docker build`، فكل أداة
# مفعّلة تكون فعلاً موجودة وقابلة للاستدعاء وقت الفحص.
RUN mirsad-build-tool semgrep python -m pip install --no-cache-dir --retries 20 --timeout 3600 "semgrep==${SEMGREP_VERSION}" && semgrep --version

# SQLMap final installation guard: keep the verified wrapper explicitly materialized
# immediately before the global tool verification stage. This is intentionally
# fail-closed: if the source script disappeared or the wrapper is not executable,
# the image build stops instead of producing an image with a hidden missing tool.
RUN set -eu; \
    test -f /opt/sqlmap/sqlmap.py; \
    printf '%s\n' '#!/bin/sh' 'exec python3 /opt/sqlmap/sqlmap.py "$@"' > /usr/local/bin/sqlmap; \
    chmod 0755 /usr/local/bin/sqlmap; \
    test -x /usr/local/bin/sqlmap; \
    /usr/local/bin/sqlmap --version | head -1; \
    command -v sqlmap >/dev/null

# Ghauri (second SQL-injection engine, cross-checks sqlmap): pinned release tag cloned from GitHub (git is
# already in the image for the sqlmap fallback) and installed with pip. Fail-closed like every other tool.
RUN set -eu; \
    rm -rf /tmp/ghauri-src; \
    git -c http.version=HTTP/1.1 clone --depth 1 --branch "${GHAURI_VERSION}" https://github.com/r0oth3x49/ghauri.git /tmp/ghauri-src; \
    python -m pip install --no-cache-dir --retries 20 --timeout 600 /tmp/ghauri-src; \
    rm -rf /tmp/ghauri-src; \
    command -v ghauri >/dev/null; \
    ghauri --version | grep -q "Ghauri"

# ── تحقّق إلزامي: كل أداة فحص خارجي يجب أن تكون قابلة للتنفيذ فعلياً هنا ──
# هذا يمنع أي تكرار لمشكلة "NOT_INSTALLED" المكتشفة فقط منتصف فحص حقيقي:
# لو أي أداة من القائمة غير موجودة أو لا تُشغَّل، البناء يفشل فورًا وبرسالة
# واضحة، بدل أن ينتهي البناء "بنجاح" بصورة ناقصة تُكتشف لاحقاً بالصدفة.
RUN set -e; \
    echo "== Verifying all already-installed scanner tools before browser/DB stages =="; \
    for bin in nmap sqlmap ghauri nuclei ffuf gitleaks trufflehog semgrep subfinder pd-httpx trivy testssl.sh; do \
        path="$(command -v "$bin" || true)"; \
        if [ -z "$path" ]; then echo "BUILD FAILED: required tool '$bin' is not on PATH" >&2; exit 1; fi; \
        test -x "$path"; echo "OK $bin -> $path"; \
    done; \
    testssl.sh --help | grep -q -- '--jsonfile'; \
    testssl.sh --help | grep -q -- '--warnings'; \
    testssl.sh --help | grep -q -- '--color'; \
    echo "== All pre-Playwright tools verified =="

# Trivy database policy
# ---------------------
# The scanner binary is always baked into the image. The vulnerability DB is
# intentionally NOT a hard Docker-build dependency: it is a 100+ MiB OCI
# artifact and transient GHCR/HTTP2 failures previously made an otherwise
# healthy image impossible to build. A release pipeline may provide a DB cache
# explicitly with TRIVY_DB_REQUIRED=true; local/default builds remain
# deterministic and the runtime reports TRIVY as UNAVAILABLE when no verified
# database exists instead of crashing the worker or falsely producing results.
ARG TRIVY_DB_REQUIRED=false
# Keep Trivy's OCI layer/blob cache in BuildKit across failed builds. The final
# verified database is copied into the image only after both DB files exist.
RUN --mount=type=cache,target=/var/cache/trivy,sharing=locked \
    if [ "${TRIVY_DB_REQUIRED}" = "true" ]; then \
      mirsad-build-tool trivy-db sh -c 'set -eu; \
        for repository in ghcr.io/aquasecurity/trivy-db:2 mirror.gcr.io/aquasec/trivy-db:2 ghcr.io/aquasecurity/trivy-db:2 mirror.gcr.io/aquasec/trivy-db:2; do \
          if trivy --timeout 12m image --download-db-only --db-repository "$repository" --cache-dir /var/cache/trivy \
            && test -s /var/cache/trivy/db/trivy.db \
            && test -s /var/cache/trivy/db/metadata.json; then \
              mkdir -p /opt/trivy-cache; \
              rm -rf /opt/trivy-cache/db; \
              cp -a /var/cache/trivy/db /opt/trivy-cache/; \
              test -s /opt/trivy-cache/db/trivy.db; \
              test -s /opt/trivy-cache/db/metadata.json; \
              exit 0; \
          fi; \
          echo "Trivy DB attempt failed for $repository; retrying without clearing the BuildKit cache" >&2; \
          sleep 20; \
        done; echo "BUILD FAILED: TRIVY_DB_REQUIRED=true but no verified Trivy DB source was reachable after retries" >&2; exit 1'; \
    else \
      echo "Trivy DB download disabled for default build; binary remains installed and runtime will report UNAVAILABLE without a verified DB"; \
    fi

# Playwright (headless Chromium) — needed because the crawler alone reads
# raw server HTML and can't see anything rendered client-side. Modern SPA
# frameworks (Angular/React/Vue) return an almost-empty index.html and build
# the real page, links, forms, and API calls only after JS executes; without
# a real browser the scanner is effectively blind on those targets. Browsers
# are installed to a shared, world-writable path so the non-root `scanner`
# user (set below) can actually launch them.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers
# Chromium is a ~160MB download; Playwright's default 30s connection timeout
# is far too short on a slower/unstable connection, so raise it generously
# and retry a few times with a short backoff in case a mirror drops
# mid-download (as seen happening on Azure/Akamai/Verizon CDN edges above).
ENV PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT=1800000
RUN mirsad-build-tool playwright-chromium sh -c '''set -eu; rm -rf /opt/playwright-browsers; mkdir -p /opt/playwright-browsers; \
    playwright install chromium; \
    test -n "$(find /opt/playwright-browsers -type f \( -name chrome -o -name chromium \) -print -quit)"; \
    apt-get update; \
    ( apt-get install -y --no-install-recommends libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libatspi2.0-0 libx11-6 libxcb1 libxext6 fonts-liberation fonts-unifont libasound2t64 \
      || apt-get install -y --no-install-recommends libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libatspi2.0-0 libx11-6 libxcb1 libxext6 fonts-liberation fonts-unifont libasound2 ); \
    rm -rf /var/lib/apt/lists/*; chmod -R a+rX /opt/playwright-browsers'''

COPY app/ ./app/
COPY scripts/ensure_trivy_db.sh ./scripts/ensure_trivy_db.sh
# Wordlists live outside /app/data on purpose: compose mounts the
# scanner-data volume there, which would hide files baked into the image.
COPY wordlists/ ./wordlists/

# nmap raw-socket privileges (SYN scan -sS, UDP -sU, OS detection -O) for the
# non-root `scanner` user: file capabilities on the real nmap binary only, so no
# other tool in the image gains privileges. Requires NET_RAW/NET_ADMIN in the
# container's cap_add (docker-compose) and no `no-new-privileges`.
# NMAP_PRIVILEGED=1 tells nmap to trust those capabilities instead of insisting on uid 0.
RUN NMAP_REAL="$(readlink -f "$(command -v nmap)")" \
    && setcap cap_net_raw,cap_net_admin+eip "$NMAP_REAL" \
    && getcap "$NMAP_REAL" \
    || echo "WARNING: could not set nmap capabilities; nmap will fall back to a TCP connect scan"
ENV NMAP_PRIVILEGED=1

# مستخدم غير-root لتشغيل التطبيق (نمنع صلاحيات root غير الضرورية بالحاوية)
RUN useradd --create-home --shell /bin/bash scanner \
    && chmod +x /app/scripts/ensure_trivy_db.sh \
    && mkdir -p /app/data /app/logs \
    && chown -R scanner:scanner /app /opt/nuclei-templates /opt/trivy-cache
USER scanner

# Run the lightweight Trivy cache guard for both API and worker containers.
# It fails startup only when TRIVY_DB_REQUIRED=true; optional local builds
# remain healthy and the detector reports UNAVAILABLE without a verified DB.
ENTRYPOINT ["/app/scripts/ensure_trivy_db.sh"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
