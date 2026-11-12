"""Persist every log line of this process to a rotating file on the host.

Docker's own json-file log is capped (see x-logging in docker-compose.yml) so
`docker compose logs`/Docker Desktop do not hang on huge logs. The complete
history lives here instead: ./logs on the host is bind-mounted to /app/logs.

Environment (all optional):
  MIRSAD_LOG_DIR      default /app/logs
  MIRSAD_LOG_MAX_MB   size of each file before rotating, default 50
  MIRSAD_LOG_BACKUPS  rotated files kept per service, default 40 (~2 GB)
  MIRSAD_LOG_LEVEL    default INFO
  MIRSAD_LOG_CLEAN_ON_START  default 1: delete this service's previous
                      <service>.log and <service>.log.N files when the service
                      starts, so every run begins with empty logs. Set to 0 to
                      keep history across restarts.
  MIRSAD_HTTP_CLIENT_LOG_LEVEL  httpx/httpcore/urllib3 level, default WARNING
                      (their INFO lines print full request URLs, which can carry
                      ?key=... secrets; every line is also redacted regardless)

Never raises: if the directory is not writable the app keeps running and a
warning is printed to stderr.
"""
from __future__ import annotations

import logging
import logging.handlers
import glob
import os
import sys

_installed: set[str] = set()


def setup_file_logging(service: str) -> str | None:
    """Attach a rotating file handler to the root and uvicorn loggers. Returns the file path."""
    if service in _installed:
        return None
    # Secrets must never reach any handler: install redaction FIRST, before the
    # file handler exists and before any third-party library logs a URL.
    try:
        from app.core.log_redaction import harden_handler, install_log_redaction
        install_log_redaction()
        http_level = getattr(
            logging, os.environ.get("MIRSAD_HTTP_CLIENT_LOG_LEVEL", "WARNING").upper(), logging.WARNING)
        for noisy in ("httpx", "httpcore", "urllib3"):
            logging.getLogger(noisy).setLevel(http_level)
    except Exception as exc:  # noqa: BLE001 - never stop the service over logging
        harden_handler = None  # type: ignore[assignment]
        print(f"[file_logging] log redaction unavailable for {service}: {exc}", file=sys.stderr)
    try:
        log_dir = os.environ.get("MIRSAD_LOG_DIR", "/app/logs")
        path = os.path.join(log_dir, f"{service}.log")
        try:
            os.makedirs(log_dir, exist_ok=True)
            # Opening the file here detects bind-mount ACL/ownership problems
            # before constructing RotatingFileHandler. If the host-mounted
            # directory is not writable (common on Windows bind mounts), use
            # a writable container-local fallback rather than disabling file
            # logging entirely. Docker's stdout logging remains available too.
            with open(path, "a", encoding="utf-8"):
                pass
        except OSError as exc:
            fallback_dir = os.path.join(os.environ.get("TMPDIR", "/tmp"), "mirsad-logs")
            os.makedirs(fallback_dir, exist_ok=True)
            path = os.path.join(fallback_dir, f"{service}.log")
            with open(path, "a", encoding="utf-8"):
                pass
            print(
                f"[file_logging] configured log directory is not writable for {service}; "
                f"using container-local fallback {path} ({exc})",
                file=sys.stderr,
            )
        if os.environ.get("MIRSAD_LOG_CLEAN_ON_START", "1").strip().lower() not in ("0", "false", "no", "off"):
            # Only this service's own files: backend and worker share the folder.
            for old in [path, *glob.glob(glob.escape(path) + ".*")]:
                try:
                    os.remove(old)
                except FileNotFoundError:
                    pass
                except OSError as exc:  # noqa: BLE001 - keep starting even if a file is locked
                    print(f"[file_logging] could not remove old log {old}: {exc}", file=sys.stderr)
        max_bytes = int(float(os.environ.get("MIRSAD_LOG_MAX_MB", "50")) * 1024 * 1024)
        backups = int(os.environ.get("MIRSAD_LOG_BACKUPS", "40"))
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8", delay=False)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        level = getattr(logging, os.environ.get("MIRSAD_LOG_LEVEL", "INFO").upper(), logging.INFO)
        handler.setLevel(level)
        root = logging.getLogger()
        if root.level == logging.NOTSET or root.level > level:
            root.setLevel(level)
        root.addHandler(handler)
        # uvicorn configures its own loggers with propagate=False.
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            lg = logging.getLogger(name)
            if handler not in lg.handlers:
                lg.addHandler(handler)
        if harden_handler is not None:
            # Also redact tracebacks/exception text (formatted after record creation)
            # on the file handler and on every console handler already attached.
            for h in [handler, *root.handlers,
                      *(h for n in ("uvicorn", "uvicorn.error", "uvicorn.access")
                        for h in logging.getLogger(n).handlers)]:
                harden_handler(h)
        _installed.add(service)
        logging.getLogger("mirsad.file_logging").info("Writing %s logs to %s", service, path)
        return path
    except Exception as exc:  # noqa: BLE001 - logging setup must never stop the service
        print(f"[file_logging] disabled for {service}: {exc}", file=sys.stderr)
        return None
