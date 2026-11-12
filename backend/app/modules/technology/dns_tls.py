import asyncio, socket, ssl
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
                san = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS" and value]
                return {"enabled":True,"protocol":s.version(),"cipher":s.cipher()[0] if s.cipher() else None,"subject":cert.get("subject"),"issuer":cert.get("issuer"),"notAfter":cert.get("notAfter"),"subject_alt_names": sorted(set(san))}
    except Exception as exc:return {"enabled":True,"error":str(exc)}

# --- async, timeout-bounded variants -----------------------------------
# socket.getaddrinfo() (used by dns_snapshot) accepts no timeout at all, and
# both functions above are plain sync code. Called directly from an async
# scan pipeline they can freeze the *entire* worker event loop - not just
# the current job - for as long as a broken/blackholed DNS resolver takes
# to give up (which can be "forever"). Run them in a thread and bound that
# thread with asyncio.wait_for so a hung resolver/handshake turns into a
# fast, clearly-labeled timeout instead of stalling every job on the worker.
async def dns_snapshot_async(target: str, timeout: float):
    try:
        return await asyncio.wait_for(asyncio.to_thread(dns_snapshot, target), timeout=timeout)
    except asyncio.TimeoutError:
        host = urlparse(target).hostname or target
        return {"hostname": host, "addresses": [], "error": f"DNS lookup timed out after {int(timeout)}s"}

async def tls_snapshot_async(target: str, timeout: float):
    try:
        return await asyncio.wait_for(asyncio.to_thread(tls_snapshot, target), timeout=timeout)
    except asyncio.TimeoutError:
        return {"enabled": True, "error": f"TLS handshake timed out after {int(timeout)}s"}
