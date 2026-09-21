"""
CF-Proxy  —  Cloudflare-bypass reverse proxy  (v3)
  /proxy/<path>  →  https://proxy.streamvideo.co.in/<path>
  /api/<path>    →  https://pwthor.live/api/<path>  (+ injected cookies)

Bypass strategy (layered):
  1. curl_cffi chrome146 — latest available TLS/JA3/HTTP2 fingerprint
  2. GREASE tokens + TLS extension permutation
  3. Brotli cert compression
  4. Exact Chrome 146 Akamai HTTP/2 fingerprint
  5. Full Chrome 146 browser header stack (correct order & values)
  6. Session warmup: visit pwthor.live homepage before first real request
     → earns a cf_clearance cookie from each session
  7. Per-session persistent cookie jar (clearance survives across requests)
  8. Hardcoded Referer + Origin from pwthor.live study page
  9. Retry-with-backoff on 403/503/challenge pages
 10. PROXY_URL env var: drop in a residential proxy URL to bypass IP-level block
"""

import asyncio
import logging
import os
import time
import random
import httpx

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response

import curl_cffi.requests as cffi_requests
from curl_cffi.requests.session import ExtraFingerprints
from curl_cffi import CurlHttpVersion, CurlSslVersion

# ──────────────────────────────────────────────────────────────
# ▌ CONFIG — edit here
# ──────────────────────────────────────────────────────────────

PROXY_TARGET = "https://proxy.streamvideo.co.in"
API_TARGET   = "https://pwthor.live"

# Injected cookies for /api/ only
INJECTED_COOKIES: dict[str, str] = {
    "auth_token": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJtb2JpbGUiOiI2NDI2MzQwOTQzNDciLCJuYW1lIjoiUFdUaG9yIFVzZXIgZDQyOTM3"
        "NTgiLCJyYW5kb21JZCI6ImQ0MjkzNzU4LTIwNzktNDdhMy04ODhiLWVmYWJiMGY2NDY0Ni"
        "IsImF1dGhUeXBlIjoiZGlyZWN0X2xvZ2luIiwiZGlyZWN0TG9naW4iOnRydWUsImlhdCI6"
        "MTc4OTk4NjcwMSwiZXhwIjoxNzk3NzYyNzAxfQ"
        ".GduD_SjI6qReGj5cPFaxJHss-kr1-VwiIaJXl510Gps"
    ),
    # Add more cookies here:
    # "cookie2": "value2",
}

# Optional residential proxy — set this env var on Render to bypass IP-level CF blocks
# Format: http://user:pass@host:port   or   socks5://user:pass@host:port
PROXY_URL = os.getenv("PROXY_URL", "")   # empty = direct (no proxy)

SESSION_POOL_SIZE = int(os.getenv("SESSION_POOL_SIZE", "4"))

# Use latest available Chrome profile — covers Chrome 146 TLS/JA3/H2
IMPERSONATE = "chrome146"

# These headers are injected on EVERY request (both /proxy and /api)
FORCED_REFERER = "https://pwthor.live/study/batches"
FORCED_ORIGIN  = "https://pwthor.live"

# ──────────────────────────────────────────────────────────────
# ▌ CHROME 146 FINGERPRINT CONSTANTS
# ──────────────────────────────────────────────────────────────

# Akamai H2 fingerprint for Chrome 146 (macOS Tahoe)
# SETTINGS frame values | WINDOW_UPDATE | PRIORITY | pseudo-header order
AKAMAI_FP = "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"

# TLS signature algorithms for Chrome 146
TLS_SIG_ALGS = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
]

EXTRA_FP = ExtraFingerprints(
    tls_min_version=CurlSslVersion.TLSv1_2,
    tls_grease=True,
    tls_permute_extensions=True,
    tls_cert_compression="brotli",
    tls_signature_algorithms=TLS_SIG_ALGS,
    http2_stream_weight=256,
    http2_stream_exclusive=1,
)

# Chrome 146 browser header stack — EXACT order matters for H2 pseudo-header fingerprint
BASE_HEADERS: dict[str, str] = {
    "sec-ch-ua":          '"Google Chrome";v="146", "Chromium";v="146", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile":   "?0",
    "sec-ch-ua-platform": '"macOS"',
    "upgrade-insecure-requests": "1",
    "user-agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site":     "same-origin",
    "sec-fetch-mode":     "navigate",
    "sec-fetch-user":     "?1",
    "sec-fetch-dest":     "document",
    "referer":            FORCED_REFERER,
    "accept-encoding":    "gzip, deflate, br, zstd",
    "accept-language":    "en-US,en;q=0.9",
    "priority":           "u=0, i",
}

# ──────────────────────────────────────────────────────────────
# ▌ HOP-BY-HOP HEADER SETS
# ──────────────────────────────────────────────────────────────

HOP_REQ = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
})

HOP_RESP = frozenset({
    "transfer-encoding", "connection", "keep-alive", "content-encoding",
})

# sec-* headers — always use our spoofed values, never the client's
SEC_HEADERS = frozenset({
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
})

log = logging.getLogger("cf-proxy")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-7s  %(message)s")

# ──────────────────────────────────────────────────────────────
# ▌ SESSION POOL
# ──────────────────────────────────────────────────────────────

_sessions: list[cffi_requests.Session] = []
_warmup_done: list[bool] = []
_rr = 0
_lock = asyncio.Lock()


def _proxy_kwargs() -> dict:
    if PROXY_URL:
        return {"proxy": PROXY_URL}
    return {}


def _new_session() -> cffi_requests.Session:
    return cffi_requests.Session(
        impersonate=IMPERSONATE,
        http_version=CurlHttpVersion.V2_0,
        verify=True,
        timeout=30,
        max_redirects=10,
        **_proxy_kwargs(),
    )


async def _warmup_session(idx: int) -> None:
    """
    Visit pwthor.live homepage first so CF issues a cf_clearance cookie.
    Also visit proxy.streamvideo.co.in homepage for the /proxy sessions.
    This builds behavioral trust before we hit the real endpoints.
    """
    s = _sessions[idx]
    loop = asyncio.get_event_loop()

    warmup_urls = [
        "https://pwthor.live/",
        "https://pwthor.live/study/batches",
    ]

    headers = dict(BASE_HEADERS)
    # For warmup, use none sec-fetch-site (fresh navigation)
    headers["sec-fetch-site"] = "none"
    headers.pop("referer", None)

    for url in warmup_urls:
        try:
            resp = await loop.run_in_executor(
                None,
                lambda u=url: s.get(
                    u,
                    headers=headers,
                    allow_redirects=True,
                    extra_fp=EXTRA_FP,
                    akamai=AKAMAI_FP,
                ),
            )
            log.info("WARMUP [%d] %s → %d", idx, url, resp.status_code)
            await asyncio.sleep(random.uniform(0.3, 0.8))   # human-like pause
        except Exception as e:
            log.warning("WARMUP [%d] %s failed: %s", idx, url, e)

    _warmup_done[idx] = True


@asynccontextmanager
async def lifespan(_app):
    global _sessions, _warmup_done
    _sessions    = [_new_session() for _ in range(SESSION_POOL_SIZE)]
    _warmup_done = [False] * SESSION_POOL_SIZE

    log.info("Pool: %d sessions, impersonate=%s, proxy=%s",
             SESSION_POOL_SIZE, IMPERSONATE, PROXY_URL or "direct")

    # Warm up sessions concurrently
    await asyncio.gather(*[_warmup_session(i) for i in range(SESSION_POOL_SIZE)])
    log.info("All sessions warmed up")
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
    Start from Chrome 146 browser stack, then overlay client headers.
    Rules:
      - Hop-by-hop → dropped
      - sec-* → always our spoofed values (never client's)
      - referer / origin → FORCED values (pwthor.live study page)
      - Everything else → client value wins (preserves auth, content-type, etc.)
    """
    merged = dict(BASE_HEADERS)

    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_REQ:
            continue
        if kl in SEC_HEADERS:
            # keep our spoofed sec- values
            continue
        if kl in ("referer", "origin"):
            # always use forced pwthor values — don't let caller override
            continue
        merged[k] = v

    # Always force these regardless of what client sent
    merged["referer"] = FORCED_REFERER
    merged["origin"]  = FORCED_ORIGIN

    return merged


def _merge_cookies(
    request: Request,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    merged: dict[str, str] = {}
    if extra:
        merged.update(extra)
    for k, v in request.cookies.items():
        merged[k] = v   # client cookies win over injected
    return merged


def _is_cf_block(status: int, body: bytes) -> bool:
    """Detect Cloudflare challenge / block pages."""
    if status in (403, 503):
        return True
    if status == 200:
        b = body[:2000].lower()
        if b"cf-mitigated" in b or b"cloudflare ray id" in b or b"just a moment" in b:
            return True
    return False


async def _fetch_with_retry(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    body: bytes,
    max_retries: int = 3,
) -> cffi_requests.Response:
    loop = asyncio.get_event_loop()
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        session = _pick()
        kwargs: dict = dict(
            headers=headers,
            cookies=cookies,
            allow_redirects=True,
            extra_fp=EXTRA_FP,
            akamai=AKAMAI_FP,
        )
        if body:
            kwargs["content"] = body

        try:
            resp = await loop.run_in_executor(
                None,
                lambda s=session: s.request(method, url, **kwargs),
            )

            if _is_cf_block(resp.status_code, resp.content):
                log.warning(
                    "CF block detected (attempt %d/%d) status=%d url=%s",
                    attempt + 1, max_retries, resp.status_code, url,
                )
                if attempt < max_retries - 1:
                    # Re-warm this session before retrying
                    idx = _sessions.index(session)
                    await _warmup_session(idx)
                    await asyncio.sleep(random.uniform(1.0, 2.5))
                    continue
            return resp

        except Exception as exc:
            last_exc = exc
            log.warning("Request error attempt %d: %s", attempt + 1, exc)
            if attempt < max_retries - 1:
                await asyncio.sleep(random.uniform(0.5, 1.5))

    if last_exc:
        raise last_exc
    raise RuntimeError("All retries exhausted")


def _respond(upstream: cffi_requests.Response) -> Response:
    resp_headers: dict[str, str] = {}
    for k, v in upstream.headers.items():
        if k.lower() not in HOP_RESP:
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
    cook = _merge_cookies(request)
    body = await request.body()

    log.info("PROXY  %s  %s", request.method, url)
    try:
        up = await _fetch_with_retry(request.method, url, hdrs, cook, body)
        log.info("       → %d  (%d B)", up.status_code, len(up.content))
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
        up = await _fetch_with_retry(request.method, url, hdrs, cook, body)
        log.info("       → %d  (%d B)", up.status_code, len(up.content))
        return _respond(up)
    except Exception as exc:
        log.exception("API error: %s", exc)
        return Response(content=f"API error: {exc}", status_code=502)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "pool": len(_sessions),
        "warmed": sum(_warmup_done),
        "impersonate": IMPERSONATE,
        "proxy": PROXY_URL or "direct",
        "grease": True,
        "permute_extensions": True,
        "akamai": AKAMAI_FP,
        "forced_referer": FORCED_REFERER,
        "forced_origin": FORCED_ORIGIN,
    }
