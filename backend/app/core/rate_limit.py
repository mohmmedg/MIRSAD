import hashlib
from starlette.requests import Request
from app.core.config import settings
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
except ImportError:  # local/test environments may intentionally omit optional dependency
    class Limiter:
        def __init__(self, *a, **k): pass
        def limit(self, *_a, **_k):
            return lambda fn: fn
    def get_remote_address(request): return request.client.host if request.client else 'unknown'

def _rate_limit_key(request: Request) -> str:
    # 2026-10-21: the bucket used to be keyed by whatever X-API-Key the client sent, so a random
    # value per request gave every call a fresh bucket (limit bypass). The key is now the network
    # peer only; behind a reverse proxy set uvicorn --forwarded-allow-ips to the proxy so the real
    # client address is used.
    return 'ip:'+get_remote_address(request)
limiter=Limiter(key_func=_rate_limit_key, storage_uri=settings.REDIS_URL or "memory://")
def scan_rate_limit(): return f'{settings.RATE_LIMIT_PER_MINUTE}/minute'
