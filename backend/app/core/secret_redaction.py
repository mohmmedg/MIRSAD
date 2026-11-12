"""Central redaction for credentials before logs, persistence or AI prompts."""
import re

PATTERNS=[
 re.compile(r'(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+'),
 re.compile(r'(?i)(cookie\s*:\s*)[^\r\n]+'),
 re.compile(r'(?i)((?:api[_-]?key|token|password|secret|credential)\s*[=:]\s*)[^\s,;]+'),
 re.compile(r'(?i)(set-cookie\s*:\s*)[^\r\n]+'),
]
def redact(value):
    if value is None: return value
    if isinstance(value,dict): return {k:("[REDACTED]" if any(x in k.lower() for x in ("authorization","cookie","token","secret","password","api_key","apikey","credential")) else redact(v)) for k,v in value.items()}
    if isinstance(value,list): return [redact(v) for v in value]
    text=str(value)
    for p in PATTERNS: text=p.sub(lambda m:m.group(1)+"[REDACTED]",text)
    # Also mask URL query secrets (?key=...), JWTs, bearer tokens and well-known
    # API-key formats - the same rules the log filter applies.
    try:
        from app.core.log_redaction import redact_text
        text=redact_text(text)
    except Exception:
        pass
    return text
