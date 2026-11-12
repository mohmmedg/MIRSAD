"""Scrub credentials from every log record before any handler sees it.

Why this exists: httpx/httpcore/urllib3 log full request URLs at INFO level.
Third-party APIs such as Shodan only accept the key as a query parameter
(``?key=...``), so the secret ended up verbatim in ``worker.log`` and in
``docker compose logs``.

How it works: a global ``logging`` record factory redacts the *formatted*
message once, at record creation. Because it runs before the record reaches
any logger or handler, it covers the rotating file handler, the console
handler, uvicorn's own handlers and any handler added later. It never
raises: a failure to redact must not break logging.

Nothing here touches ``.env`` or any configured secret value; it only masks
what would otherwise be printed.
"""
from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

# Query-string / form parameter names whose value is a credential. This list
# is broad on purpose: inside a URL query string a bare "key" is a credential.
_QUERY_PARAM = (
    r"key|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|token|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|auth|authorization|secret|client[_-]?secret|"
    r"password|passwd|pwd|signature|sig|session|sessionid|jwt|credential|private[_-]?key"
)
# Narrower list for free text / JSON, where words like "key" or "session" are
# ordinary vocabulary ("cache key: x", "session: running") and must not be masked.
_TEXT_KEY = (
    r"api[_-]?key|apikey|access[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|auth[_-]?token|token|client[_-]?secret|secret|password|passwd|private[_-]?key"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ?key=VALUE / &token=VALUE (URL query strings and form bodies)
    (re.compile(rf"(?i)([?&;](?:{_QUERY_PARAM})=)[^&\s\"'#<>]+"), r"\1" + REDACTED),
    # key=VALUE / "api_key": "VALUE" / token: VALUE in free text and JSON
    (re.compile(
        # "key=value" (no spaces around "=") or "key: value" / "key": "value".
        # An empty value followed by a space (access_token= "HTTP/1.1 401")
        # must NOT swallow the next token.
        rf"(?i)(\b(?:{_TEXT_KEY})\b[\"']?(?:=|[ \t]*:[ \t]*)[\"']?)"
        r"(?!\[REDACTED\])[^\s,;&\"'}\]]{4,}"), r"\1" + REDACTED),
    # Authorization / Proxy-Authorization / X-API-Key headers
    (re.compile(r"(?i)((?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|token)?\s*)[^\s,;\"']+"),
     r"\1" + REDACTED),
    (re.compile(r"(?i)(x-api-key\s*[:=]\s*)[^\s,;\"']+"), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1" + REDACTED),
    # Cookies
    (re.compile(r"(?i)((?:set-)?cookie\s*:\s*)[^\r\n]+"), r"\1" + REDACTED),
    # Credentials embedded in URLs: scheme://user:password@host
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)"), r"\1" + REDACTED + r"\2"),
    # Well-known token formats, redacted wherever they appear
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), REDACTED),  # JWT
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), REDACTED),                                      # Google API key
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),                                       # sk-... style keys
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), REDACTED),                                  # GitHub tokens
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),                                # Slack tokens
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),                                            # AWS access key id
    (re.compile(r"\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{10,}\b"), REDACTED),                # Supabase keys
]


def redact_text(text: str) -> str:
    """Return ``text`` with credentials masked. Safe on any input."""
    if not text or not isinstance(text, str):
        return text
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def harden_handler(handler: logging.Handler) -> None:
    """Redact the final formatted output of ``handler`` (covers tracebacks and
    exception messages, which are formatted after the record factory runs)."""
    if getattr(handler, "_mirsad_redacting", False):
        return
    original = handler.format

    def format_redacted(record):  # noqa: ANN001
        try:
            return redact_text(original(record))
        except Exception:  # noqa: BLE001
            return original(record)

    handler.format = format_redacted  # type: ignore[method-assign]
    handler._mirsad_redacting = True  # type: ignore[attr-defined]


_installed = False


def install_log_redaction() -> None:
    """Install the global record factory once per process (idempotent)."""
    global _installed
    if _installed:
        return
    previous = logging.getLogRecordFactory()

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003
        record = previous(*args, **kwargs)
        try:
            message = record.getMessage()
            cleaned = redact_text(message)
            if cleaned != message:
                record.msg = cleaned
                record.args = ()
        except Exception:  # noqa: BLE001 - logging must never raise
            pass
        return record

    logging.setLogRecordFactory(factory)
    _installed = True
