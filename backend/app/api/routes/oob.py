from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from app.core.oob import mark
from app.core.rate_limit import limiter

router = APIRouter(prefix="/oob", tags=["oob"])

@router.api_route("/callback/{token}", methods=["GET", "POST", "HEAD", "OPTIONS"], response_class=PlainTextResponse)
@limiter.limit("120/minute")
async def callback(token: str, request: Request):
    # Deliberately discard all inbound data. The random token is the only correlation key.
    mark(token)
    return PlainTextResponse("ok", status_code=204 if request.method == "HEAD" else 200)
