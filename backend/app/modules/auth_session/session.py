import base64, json, re

def redact(value: str | None) -> str | None:
    if not value:return value
    return "<redacted>"

def analyze_jwt(value: str | None) -> dict:
    result={"present":False,"algorithm":None,"issuer_present":False,"audience_present":False,"expiry_present":False,"expiry_status":None,"not_before_present":False,"sensitive_claims":[],"warnings":[]}
    if not value:return result
    m=re.search(r"Bearer\s+([^\s]+)",value,re.I)
    token=m.group(1) if m else value.strip()
    parts=token.split('.')
    if len(parts)!=3:return result
    try:
        head=json.loads(base64.urlsafe_b64decode(parts[0]+'='*((4-len(parts[0])%4)%4)))
        claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((4-len(parts[1])%4)%4)))
    except Exception:return result
    result["present"]=True; result["algorithm"]=head.get("alg"); result["issuer_present"]="iss" in claims; result["audience_present"]="aud" in claims; result["expiry_present"]="exp" in claims; result["not_before_present"]="nbf" in claims
    if str(head.get("alg","" )).lower()=="none":result["warnings"].append("JWT declares alg=none; verify the server rejects unsigned tokens.")
    sensitive=[k for k in claims if any(x in k.lower() for x in ("role","admin","scope","permission","email","user","tenant"))]
    result["sensitive_claims"]=sensitive
    return result
