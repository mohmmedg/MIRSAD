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
    api_key=request.headers.get('x-api-key')
    if api_key: return 'apikey:'+hashlib.sha256(api_key.encode()).hexdigest()
    return 'ip:'+get_remote_address(request)
limiter=Limiter(key_func=_rate_limit_key, storage_uri=settings.REDIS_URL or "memory://")
def scan_rate_limit(): return f'{settings.RATE_LIMIT_PER_MINUTE}/minute'
