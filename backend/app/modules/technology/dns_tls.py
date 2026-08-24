import socket, ssl
from urllib.parse import urlparse

def dns_snapshot(target: str):
    host=urlparse(target).hostname or target
    try:
        infos=socket.getaddrinfo(host,None)
        return {"hostname":host,"addresses":sorted({x[4][0] for x in infos}),"error":None}
    except Exception as exc:return {"hostname":host,"addresses":[],"error":str(exc)}

def tls_snapshot(target: str):
    p=urlparse(target if "://" in target else "https://"+target)
    if p.scheme!="https":return {"enabled":False}
    host=p.hostname; port=p.port or 443
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=5) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as s:
                cert=s.getpeercert()
                return {"enabled":True,"protocol":s.version(),"cipher":s.cipher()[0] if s.cipher() else None,"subject":cert.get("subject"),"issuer":cert.get("issuer"),"notAfter":cert.get("notAfter")}
    except Exception as exc:return {"enabled":True,"error":str(exc)}
