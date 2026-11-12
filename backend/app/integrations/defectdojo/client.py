from __future__ import annotations
import time
import httpx
from app.core.config import settings

import logging as _logging
logger = _logging.getLogger(__name__)
class DefectDojoError(RuntimeError):
    def __init__(self, code:str, message:str, retryable:bool=True): self.code=code; self.retryable=retryable; super().__init__(message)
class DefectDojoClient:
    def __init__(self):
        base=(settings.DEFECTDOJO_API_URL or settings.DEFECTDOJO_URL or "").rstrip("/"); self.base=base; self.timeout=settings.DEFECTDOJO_TIMEOUT; self.verify=settings.DEFECTDOJO_VERIFY_TLS
    def _headers(self, multipart: bool = False):
        h={"Authorization":f"Token {settings.DEFECTDOJO_API_TOKEN}"} if settings.DEFECTDOJO_API_TOKEN else {}
        if not multipart: h["Content-Type"]="application/json"
        return h
    async def request(self, method:str, path:str, **kwargs):
        if not self.base: raise DefectDojoError("DISABLED","DefectDojo URL is not configured",False)
        try:
            multipart = "files" in kwargs or "data" in kwargs
            async with httpx.AsyncClient(timeout=self.timeout,verify=self.verify,headers=self._headers(multipart)) as c:
                _t0=time.monotonic()
                r=await c.request(method,self.base+path,**kwargs)
                try:
                    from app.core import execution_trace as _t
                    _t.emit_http(method=method,url=self.base+path+("?"+str(r.request.url.query.decode()) if r.request.url.query else ""),request_headers=r.request.headers,
                                 request_body=kwargs.get("json") and __import__("json").dumps(kwargs.get("json"))[:2000],status=r.status_code,reason=r.reason_phrase,
                                 response_headers=r.headers,response_body=r.content[:4096],response_content_type=r.headers.get("content-type",""),
                                 duration_ms=(time.monotonic()-_t0)*1000,source="defectdojo-api")
                except Exception: logger.debug("suppressed non-fatal error", exc_info=True)
        except httpx.TimeoutException as e: raise DefectDojoError("TIMEOUT","DefectDojo request timed out",True) from e
        except httpx.HTTPError as e: raise DefectDojoError("CONNECTION","DefectDojo connection failed",True) from e
        if r.status_code in (401,403): raise DefectDojoError("AUTH_ERROR",f"DefectDojo returned HTTP {r.status_code}",False)
        if r.status_code==404: raise DefectDojoError("NOT_FOUND","DefectDojo endpoint not found",False)
        if r.status_code==429 or r.status_code>=500: raise DefectDojoError("RETRYABLE_HTTP",f"DefectDojo returned HTTP {r.status_code}",True)
        if r.status_code>=400: raise DefectDojoError("HTTP_ERROR",f"DefectDojo returned HTTP {r.status_code} on {method} {path}: {r.text[:300]}",False)
        try: return r.json()
        except ValueError: return {}
    async def health(self):
        if not settings.DEFECTDOJO_ENABLED: return "DISABLED"
        try: await self.request("GET","/api/v2/system_settings/" ); return "AVAILABLE"
        except DefectDojoError as e: return e.code if e.code in {"AUTH_ERROR","TIMEOUT"} else "UNAVAILABLE"
