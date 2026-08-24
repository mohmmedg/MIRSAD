import re

def analyze_js(urls: list[str], bodies: list[str] | None = None):
    patterns=[r"(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*[\"']([^\"']+)",r"[\"'](\/[^\"']*(?:api|graphql|swagger|openapi)[^\"']*)[\"']",r"[\"'](https?://[^\"']+)[\"']"]
    endpoints=set()
    for body in bodies or []:
        for pat in patterns:
            endpoints.update(m for m in re.findall(pat,body,re.I) if len(m)<500)
    secrets=[]
    secret_pat=re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\"']([^\"']{12,})[\"']")
    for body in bodies or []:
        for key,_ in secret_pat.findall(body):secrets.append({"type":key,"value":"<redacted>"})
    return {"endpoints":sorted(endpoints)[:500],"secret_indicators":secrets[:50]}
