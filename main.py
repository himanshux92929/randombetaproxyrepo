"""
CF-Proxy  —  Cloudflare-bypass reverse proxy
  /proxy/<path>  →  https://proxy.streamvideo.co.in/<path>
  /api/<path>    →  https://pwthor.live/api/<path>  (+ injected cookies)

Bypass strategy:
  • curl_cffi chrome124 impersonation  (TLS/JA3 + HTTP/2 fingerprint)
  • GREASE tokens enabled
  • TLS extension permutation enabled
  • Brotli cert compression (matches Chrome)
  • Full ordered Chrome 124 browser-header stack injected before user headers
  • Persistent per-session cookie jar so CF clearance cookies survive across requests
  • Round-robin session pool for throughput
"""

import asyncio
import logging
import os
import random

from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager

import curl_cffi.requests as cffi_requests
from curl_cffi.requests.session import ExtraFingerprints
from curl_cffi import CurlHttpVersion, CurlSslVersion

# ──────────────────────────────────────────────────────────────
# ▌ CONFIG  — edit here
# ──────────────────────────────────────────────────────────────

PROXY_TARGET = "https://proxy.streamvideo.co.in"
API_TARGET   = "https://pwthor.live"

# Injected cookies for /api/... requests (add as many as you need)
INJECTED_COOKIES: dict[str, str] = {
    "auth_token": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJtb2JpbGUiOiI2NDI2MzQwOTQzNDciLCJuYW1lIjoiUFdUaG9yIFVzZXIgZDQyOTM3"
        "NTgiLCJyYW5kb21JZCI6ImQ0MjkzNzU4LTIwNzktNDdhMy04ODhiLWVmYWJiMGY2NDY0Ni"
        "IsImF1dGhUeXBlIjoiZGlyZWN0X2xvZ2luIiwiZGlyZWN0TG9naW4iOnRydWUsImlhdCI6"
        "MTc4OTk4NjcwMSwiZXhwIjoxNzk3NzYyNzAxfQ"
        ".GduD_SjI6qReGj5cPFaxJHss-kr1-VwiIaJXl510Gps"
    ),
    # "cookie2": "value2",   ← add more here
}

SESSION_POOL_SIZE = int(os.getenv("SESSION_POOL_SIZE", "6"))
IMPERSONATE       = "chrome124"

# ──────────────────────────────────────────────────────────────
# ▌ BROWSER HEADER STACK  (Chrome 124 exact order & values)
# ──────────────────────────────────────────────────────────────

CHROME_ACCEPT          = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
CHROME_ACCEPT_ENCODING = "gzip, deflate, br, zstd"
CHROME_ACCEPT_LANGUAGE = "en-US,en;q=0.9"

# Base headers injected on every request (overridden/merged with client headers below)
BASE_HEADERS: dict[str, str] = {
    "sec-ch-ua":          '"Google Chrome";v="124", "Chromium";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile":   "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "accept":             CHROME_ACCEPT,
    "sec-fetch-site":     "none",
    "sec-fetch-mode":     "navigate",
    "sec-fetch-user":     "?1",
    "sec-fetch-dest":     "document",
    "accept-encoding":    CHROME_ACCEPT_ENCODING,
    "accept-language":    CHROME_ACCEPT_LANGUAGE,
}

# Extra fingerprint options for maximum CF bypass
EXTRA_FP = ExtraFingerprints(
    tls_min_version=CurlSslVersion.TLSv1_2,
    tls_grease=True,                  # GREASE tokens in TLS ClientHello
    tls_permute_extensions=True,      # randomise extension order like real Chrome
    tls_cert_compression="brotli",    # Chrome uses brotli cert compression
    http2_stream_weight=256,
    http2_stream_exclusive=1,
)

# Akamai HTTP/2 fingerprint matching Chrome 124
# Format: SETTINGS|WINDOW_UPDATE|PRIORITY_FRAMES|PSEUDO_HEADER_ORDER
AKAMAI_FP = "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"

# ──────────────────────────────────────────────────────────────
# ▌ HEADER FILTERING
# ──────────────────────────────────────────────────────────────

# Never forward these to upstream (hop-by-hop)
HOP_BY_HOP_REQ = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
})

# Strip from upstream response before returning to client
HOP_BY_HOP_RESP = frozenset({
    "transfer-encoding", "connection", "keep-alive",
    "content-encoding",   # curl_cffi decompresses automatically
})

# Headers that must be forwarded exactly as the client sent — never override
CLIENT_CONTROLLED = frozenset({
    "referer", "origin", "authorization", "x-forwarded-for",
    "x-real-ip", "content-type",
})

log = logging.getLogger("cf-proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s")


# ──────────────────────────────────────────────────────────────
# ▌ SESSION POOL
# ──────────────────────────────────────────────────────────────

_sessions: list[cffi_requests.Session] = []
_rr = 0


def _new_session() -> cffi_requests.Session:
    return cffi_requests.Session(
        impersonate=IMPERSONATE,
        http_version=CurlHttpVersion.V2_0,
        verify=True,
        timeout=30,
        max_redirects=10,
        # Persistent cookie jar per session — crucial for CF clearance cookies
    )


@asynccontextmanager
async def lifespan(_app):
    global _sessions
    _sessions = [_new_session() for _ in range(SESSION_POOL_SIZE)]
    log.info("Pool ready: %d sessions, impersonate=%s, grease=True, permute=True",
             SESSION_POOL_SIZE, IMPERSONATE)
    yield
    for s in _sessions:
        try:
            s.close()
        except Exception:
            pass
    log.info("Sessions closed")


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


def _pick() -> cffi_requests.Session:
    global _rr
    s = _sessions[_rr % len(_sessions)]
    _rr += 1
    return s


# ──────────────────────────────────────────────────────────────
# ▌ REQUEST / RESPONSE HELPERS
# ──────────────────────────────────────────────────────────────

def _build_headers(request: Request) -> dict[str, str]:
    """
    Merge BASE_HEADERS (browser defaults) with client-sent headers.
    Client headers take priority, EXCEPT for sec-* / ua headers which
    must always reflect the impersonated browser.
    Headers in CLIENT_CONTROLLED are always passed verbatim.
    Hop-by-hop headers are dropped.
    """
    # Start with browser defaults
    merged: dict[str, str] = dict(BASE_HEADERS)

    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP_REQ:
            continue
        if kl in CLIENT_CONTROLLED:
            # Always honour — pwthor checks Origin/Referer
            merged[k] = v
        elif kl.startswith("sec-"):
            # Keep our spoofed sec- headers; don't let client pollute them
            pass
        else:
            merged[k] = v

    return merged


def _merge_cookies(request: Request, extra: dict[str, str] | None = None) -> dict[str, str]:
    merged: dict[str, str] = {}
    if extra:
        merged.update(extra)
    for k, v in request.cookies.items():
        merged[k] = v   # client cookies win
    return merged


async def _fetch(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    body: bytes,
) -> cffi_requests.Response:
    session = _pick()
    loop = asyncio.get_event_loop()

    kwargs: dict = dict(
        headers=headers,
        cookies=cookies,
        allow_redirects=True,
        extra_fp=EXTRA_FP,
        akamai=AKAMAI_FP,
    )
    if body:
        kwargs["content"] = body

    return await loop.run_in_executor(
        None,
        lambda: session.request(method, url, **kwargs),
    )


def _respond(upstream: cffi_requests.Response) -> Response:
    resp_headers: dict[str, str] = {}
    for k, v in upstream.headers.items():
        if k.lower() not in HOP_BY_HOP_RESP:
            resp_headers[k] = v

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=None,
    )


# ──────────────────────────────────────────────────────────────
# ▌ ROUTES
# ──────────────────────────────────────────────────────────────

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


@app.api_route("/proxy/{path:path}", methods=METHODS)
async def proxy_endpoint(request: Request, path: str):
    qs   = request.url.query
    url  = f"{PROXY_TARGET}/{path}" + (f"?{qs}" if qs else "")
    hdrs = _build_headers(request)
    cook = _merge_cookies(request)   # no extra injection
    body = await request.body()

    log.info("PROXY  %s  %s", request.method, url)
    try:
        up = await _fetch(request.method, url, hdrs, cook, body)
        log.info("       → %d  (%d bytes)", up.status_code, len(up.content))
        return _respond(up)
    except Exception as exc:
        log.exception("PROXY error: %s", exc)
        return Response(content=f"Proxy error: {exc}", status_code=502)


@app.api_route("/api/{path:path}", methods=METHODS)
async def api_endpoint(request: Request, path: str):
    qs   = request.url.query
    url  = f"{API_TARGET}/api/{path}" + (f"?{qs}" if qs else "")
    hdrs = _build_headers(request)
    cook = _merge_cookies(request, extra=INJECTED_COOKIES)
    body = await request.body()

    log.info("API    %s  %s", request.method, url)
    try:
        up = await _fetch(request.method, url, hdrs, cook, body)
        log.info("       → %d  (%d bytes)", up.status_code, len(up.content))
        return _respond(up)
    except Exception as exc:
        log.exception("API error: %s", exc)
        return Response(content=f"API error: {exc}", status_code=502)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "pool":   len(_sessions),
        "impersonate": IMPERSONATE,
        "grease": True,
        "permute_extensions": True,
    }
