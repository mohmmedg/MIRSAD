"""Optional notifications using administrator-configured destinations only."""
import os, json, time, urllib.request, smtplib, logging
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger(__name__)


def _to_cef(message: str, event: dict[str, Any] | None) -> str:
    """Minimal CEF (Common Event Format) encoding for SIEM ingestion
    (ArcSight/Splunk/QRadar/etc. all accept CEF over a generic HTTP
    collector). CEF header: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Only a conservative, always-safe subset of fields is emitted from
    `event` - unknown/missing fields degrade to sane defaults rather than
    raising, since a malformed notification must never crash the caller
    (continuous.py's scan-completion path, most importantly).
    """
    event = event or {}
    severity_word = str(event.get("severity", "Low")).title()
    cef_severity = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 0}.get(severity_word, 3)
    name = str(event.get("name", message))[:512].replace("|", "\\|")
    ext_parts = []
    for key, cef_key in (("target", "dst"), ("scan_id", "cs1"), ("finding_count", "cnt")):
        if event.get(key) is not None:
            ext_parts.append(f"{cef_key}={event[key]}")
    ext_parts.append(f"msg={message[:1000].replace('=', chr(92)+'=')}")
    extension = " ".join(ext_parts)
    return f"CEF:0|MIRSAD|SecurityScanner|1.0|scan-event|{name}|{cef_severity}|{extension}"


def _send_generic_webhook(message: str, event: dict[str, Any] | None) -> bool:
    """2.6: a destination-agnostic webhook for SIEM/ticketing/automation
    integrations that don't speak Slack's/Discord's specific payload shape.
    GENERIC_WEBHOOK_FORMAT controls the body: "json" (default - structured,
    for n8n/Zapier/custom receivers) or "cef" (text/plain CEF line, for
    SIEM HTTP collectors). Any other value falls back to "json" rather than
    silently sending nothing."""
    url = os.getenv("GENERIC_WEBHOOK_URL")
    if not url:
        return False
    fmt = (os.getenv("GENERIC_WEBHOOK_FORMAT", "json") or "json").lower()
    try:
        if fmt == "cef":
            body = _to_cef(message, event).encode()
            headers = {"Content-Type": "text/plain"}
        else:
            payload = {"message": message, "source": "mirsad", "timestamp": time.time(), **(event or {})}
            body = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=5):
            pass
        return True
    except Exception:
        return False


def notify(message: str, event: dict[str, Any] | None = None) -> list[str]:
    """`event` is an optional structured payload (severity/target/scan_id/
    finding_count/name) used only by richer destinations (currently the
    generic webhook's CEF/JSON bodies); Slack/Discord/email keep using the
    plain-text `message` unchanged, so existing single-argument callers
    (e.g. continuous.py) keep working with no changes required."""
    sent=[]
    for name in ('SLACK_WEBHOOK_URL','DISCORD_WEBHOOK_URL'):
        url=os.getenv(name)
        if not url: continue
        try:
            data=json.dumps({'content':message} if 'DISCORD' in name else {'text':message}).encode()
            req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=5): pass
            sent.append(name)
        except Exception:
            logger.warning("Notification webhook %s failed to send", name, exc_info=True)
    if _send_generic_webhook(message, event):
        sent.append('GENERIC_WEBHOOK_URL')
    host=os.getenv('SMTP_HOST'); to=os.getenv('NOTIFY_EMAIL_TO')
    if host and to:
        try:
            msg=EmailMessage(); msg['Subject']='Security Scanner notification'; msg['From']=os.getenv('SMTP_FROM','scanner@localhost'); msg['To']=to; msg.set_content(message)
            with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','25')),timeout=5) as smtp:
                if os.getenv('SMTP_STARTTLS','false').lower()=='true': smtp.starttls()
                if os.getenv('SMTP_USER'): smtp.login(os.getenv('SMTP_USER'),os.getenv('SMTP_PASSWORD',''))
                smtp.send_message(msg)
            sent.append('email')
        except Exception:
            logger.warning("Notification email to %s failed to send", to, exc_info=True)
    return sent
