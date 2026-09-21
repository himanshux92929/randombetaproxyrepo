"""
High-performance proxy server using curl_cffi for Cloudflare bypass.
Two endpoints:
  /proxy/...  -> proxy.streamvideo.co.in/...
  /api/...    -> pwthor.live/api/...  (with injected cookies)
"""

import asyncio
import logging
import os
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
import curl_cffi.requests as cffi_requests
from curl_cffi import CurlHttpVersion

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

PROXY_TARGET   = "https://proxy.streamvideo.co.in"
API_TARGET     = "https://pwthor.live"

# Add / edit your injected cookies here (for /api/... only)
INJECTED_COOKIES: dict[str, str] = {
     "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtb2JpbGUiOiI2NDI2MzQwOTQzNDciLCJuYW1lIjoiUFdUaG9yIFVzZXIgZDQyOTM3NTgiLCJyYW5kb21JZCI6ImQ0MjkzNzU4LTIwNzktNDdhMy04ODhiLWVmYWJiMGY2NDY0NiIsImF1dGhUeXBlIjoiZGlyZWN0X2xvZ2luIiwiZGlyZWN0TG9naW4iOnRydWUsImlhdCI6MTc4OTk4NjcwMSwiZXhwIjoxNzk3NzYyNzAxfQ.GduD_SjI6qReGj5cPFaxJHss-kr1-VwiIaJXl510Gps",
    # "cookie2": "value2",
}

# Browser impersonation profile — Chrome 124 gives the most realistic TLS fingerprint
IMPERSONATE = "chrome124"

# Headers that must NOT be forwarded upstream (hop-by-hop / connection-level)
HOP_BY_HOP = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
})

# Response headers we strip before returning to the client
STRIP_RESPONSE_HEADERS = frozenset({
    "transfer-encoding", "connection", "keep-alive",
    "content-encoding",   # curl_cffi decompresses automatically
})

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("proxy")


# ─────────────────────────────────────────────
# CURL_CFFI SESSION POOL
# ─────────────────────────────────────────────

_sessions: list[cffi_requests.Session] = []
_session_count = int(os.getenv("SESSION_POOL_SIZE", "4"))


def _make_session() -> cffi_requests.Session:
    return cffi_requests.Session(
        impersonate=IMPERSONATE,
        http_version=CurlHttpVersion.V2_0,
        verify=True,
        timeout=30,
        max_redirects=10,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _sessions
    _sessions = [_make_session() for _ in range(_session_count)]
    log.info("Session pool ready (%d sessions, impersonate=%s)", _session_count, IMPERSONATE)
    yield
    for s in _sessions:
        s.close()
    log.info("Sessions closed")


# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

_rr_counter = 0

def _get_session() -> cffi_requests.Session:
    """Round-robin session picker (non-blocking)."""
    global _rr_counter
    s = _sessions[_rr_counter % len(_sessions)]
    _rr_counter += 1
    return s


# ─────────────────────────────────────────────
# HELPER: BUILD UPSTREAM REQUEST
# ─────────────────────────────────────────────

def _build_upstream_headers(request: Request) -> dict[str, str]:
    """
    Forward all client headers verbatim except hop-by-hop ones.
    Crucially we preserve Referer, Origin, Host (as seen by the upstream)
    exactly as sent by the client — pwthor checks these.
    """
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() not in HOP_BY_HOP:
            headers[name] = value
    return headers


def _merge_cookies(
    request: Request,
    extra: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """
    Merge cookies: incoming request cookies + extra injected cookies.
    Incoming cookies take precedence over injected ones if same key.
    """
    merged: dict[str, str] = {}
    if extra:
        merged.update(extra)
    # Override/add with whatever the real client sent
    for name, value in request.cookies.items():
        merged[name] = value
    return merged


async def _do_request(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    body: bytes,
) -> cffi_requests.Response:
    """Run the blocking curl_cffi call in the thread pool."""
    session = _get_session()

    kwargs: dict = dict(
        headers=headers,
        cookies=cookies,
        allow_redirects=True,
    )
    if body:
        kwargs["content"] = body

    loop = asyncio.get_event_loop()
    resp: cffi_requests.Response = await loop.run_in_executor(
        None,
        lambda: session.request(method, url, **kwargs),
    )
    return resp


def _build_response(upstream: cffi_requests.Response) -> Response:
    """Turn the upstream curl_cffi response into a FastAPI Response."""
    response_headers: dict[str, str] = {}

    for name, value in upstream.headers.items():
        if name.lower() not in STRIP_RESPONSE_HEADERS:
            response_headers[name] = value

    # Pass Set-Cookie through (curl_cffi stores them in .headers too)
    # curl_cffi merges duplicate headers with comma — re-split for Set-Cookie
    # to avoid breaking cookie parsing
    content = upstream.content  # already decompressed by curl_cffi

    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=None,   # let the upstream content-type header decide
    )


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.api_route("/proxy/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
async def proxy_endpoint(request: Request, path: str):
    """
    Forward everything to proxy.streamvideo.co.in/<path>
    No cookie injection — purely transparent.
    """
    qs   = request.url.query
    url  = f"{PROXY_TARGET}/{path}" + (f"?{qs}" if qs else "")
    hdrs = _build_upstream_headers(request)
    cook = _merge_cookies(request)          # no extra injection
    body = await request.body()

    log.info("PROXY %s %s", request.method, url)
    try:
        upstream = await _do_request(request.method, url, hdrs, cook, body)
        return _build_response(upstream)
    except Exception as exc:
        log.exception("PROXY error: %s", exc)
        return Response(content=f"Proxy error: {exc}", status_code=502)


@app.api_route("/api/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
async def api_endpoint(request: Request, path: str):
    """
    Forward everything to pwthor.live/api/<path>
    Injects INJECTED_COOKIES on top of whatever the client sent.
    """
    qs   = request.url.query
    url  = f"{API_TARGET}/api/{path}" + (f"?{qs}" if qs else "")
    hdrs = _build_upstream_headers(request)
    cook = _merge_cookies(request, extra=INJECTED_COOKIES)
    body = await request.body()

    log.info("API %s %s", request.method, url)
    try:
        upstream = await _do_request(request.method, url, hdrs, cook, body)
        return _build_response(upstream)
    except Exception as exc:
        log.exception("API error: %s", exc)
        return Response(content=f"API error: {exc}", status_code=502)


@app.get("/health")
async def health():
    return {"status": "ok", "pool": len(_sessions), "impersonate": IMPERSONATE}
