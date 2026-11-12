import logging

from app.core.log_redaction import harden_handler, install_log_redaction, redact_text
from app.core.secret_redaction import redact


def test_shodan_style_url_key_is_masked():
    line = 'GET https://api.shodan.io/shodan/host/127.0.0.1?key=4Fy62YHyI4mEHFwNFIJrgnflTElIuEYI "HTTP/1.1 404"'
    out = redact_text(line)
    assert "4Fy62YHy" not in out
    assert "?key=[REDACTED]" in out


def test_tokens_headers_urls_and_known_formats():
    assert "abc12345" not in redact_text("https://x.test/a?b=1&token=abc12345&c=2")
    assert "b=1" in redact_text("https://x.test/a?b=1&token=abc12345&c=2")
    assert "eyJhbGci" not in redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdEFGH")
    assert "SuperSecret" not in redact_text("postgresql://u:SuperSecret@host:6543/db")
    assert "AIzaSyA1234567890abcdefghijklmnopqrstuv" not in redact_text(
        "k=AIzaSyA1234567890abcdefghijklmnopqrstuv")


def test_ordinary_text_is_untouched():
    for text in ("cache key: abc123", "session: running", "scan 6e2ec268 finished in 12s"):
        assert redact_text(text) == text


def test_persistence_helper_also_masks_query_secrets():
    assert redact("GET https://a.b/x?key=ABCDEF123456&a=1") == "GET https://a.b/x?key=[REDACTED]&a=1"


def test_record_factory_and_handler_redact_message_and_traceback(caplog):
    install_log_redaction()
    install_log_redaction()  # idempotent
    stream = []

    class Capture(logging.Handler):
        def emit(self, record):
            stream.append(self.format(record))

    handler = Capture()
    handler.setFormatter(logging.Formatter("%(message)s"))
    harden_handler(handler)
    logger = logging.getLogger("redaction-test")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    logger.info("GET %s", "https://api.shodan.io/h?key=SECRETKEY1234567890")
    try:
        raise RuntimeError("failed for https://x.test/?api_key=TOPSECRET99999")
    except RuntimeError:
        logger.exception("boom")
    joined = "\n".join(stream)
    assert "SECRETKEY1234567890" not in joined
    assert "TOPSECRET99999" not in joined
    assert "[REDACTED]" in joined


def test_empty_value_does_not_swallow_next_token():
    line = 'GET https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token= "HTTP/1.1 401 Unauthorized"'
    assert redact_text(line) == line


def test_json_and_colon_forms_still_masked():
    assert "sk-abcdefghijklmnopqrstuvwxyz123" not in redact_text('{"api_key": "sk-abcdefghijklmnopqrstuvwxyz123"}')
    assert "hunter2hunter2" not in redact_text("password: hunter2hunter2")
    assert "hunter2hunter2" not in redact_text("password=hunter2hunter2")
