"""
CF-Proxy v4  —  Cloudflare-bypass reverse proxy
  /proxy/<path>  →  https://proxy.streamvideo.co.in/<path>
  /api/<path>    →  https://pwthor.live/api/<path>  (+ injected cookies)
  /health        →  status + proxy connectivity check
  /diag          →  full diagnostic dump (headers sent, proxy status, etc.)
"""

import asyncio
import logging
import os
import random

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
import curl_cffi.requests as cffi_requests
from curl_cffi.requests.session import ExtraFingerprints
from curl_cffi import CurlHttpVersion, CurlSslVersion

# ──────────────────────────────────────────────────────────────
# ▌ CONFIG
# ──────────────────────────────────────────────────────────────

PROXY_TARGET = "https://proxy.streamvideo.co.in"
API_TARGET   = "https://pwthor.live"

INJECTED_COOKIES: dict[str, str] = {
    "auth_token": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJtb2JpbGUiOiI2NDI2MzQwOTQzNDciLCJuYW1lIjoiUFdUaG9yIFVzZXIgZDQyOTM3"
        "NTgiLCJyYW5kb21JZCI6ImQ0MjkzNzU4LTIwNzktNDdhMy04ODhiLWVmYWJiMGY2NDY0Ni"
        "IsImF1dGhUeXBlIjoiZGlyZWN0X2xvZ2luIiwiZGlyZWN0TG9naW4iOnRydWUsImlhdCI6"
        "MTc4OTk4NjcwMSwiZXhwIjoxNzk3NzYyNzAxfQ"
        ".GduD_SjI6qReGj5cPFaxJHss-kr1-VwiIaJXl510Gps"
    ),
    # "cookie2": "value2",
}

# Residential proxy URL — set on Render env vars
# Supported formats:
#   http://user:pass@host:port
#   https://user:pass@host:port
#   socks5://user:pass@host:port
#   socks5h://user:pass@host:port   ← use this for DNS-through-proxy
PROXY_URL = os.getenv("PROXY_URL", "").strip()

SESSION_POOL_SIZE = int(os.getenv("SESSION_POOL_SIZE", "2"))
IMPERSONATE       = "chrome146"

FORCED_REFERER = "https://pwthor.live/study/batches"
FORCED_ORIGIN  = "https://pwthor.live"

# ──────────────────────────────────────────────────────────────
# ▌ FINGERPRINT
# ──────────────────────────────────────────────────────────────

# Chrome 146 Akamai HTTP/2 fingerprint
AKAMAI_FP = "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"

EXTRA_FP = ExtraFingerprints(
    tls_min_version=CurlSslVersion.TLSv1_2,
    tls_grease=True,
    tls_permute_extensions=True,
    tls_cert_compression="brotli",
    tls_signature_algorithms=[
        "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512",
    ],
    http2_stream_weight=256,
    http2_stream_exclusive=1,
)

# Chrome 146 macOS — exact header stack
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
    "origin":             FORCED_ORIGIN,
    "accept-encoding":    "gzip, deflate, br, zstd",
    "accept-language":    "en-US,en;q=0.9",
    "priority":           "u=0, i",
}

HOP_REQ = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
})
HOP_RESP = frozenset({
    "transfer-encoding", "connection", "keep-alive", "content-encoding",
})
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
_rr = 0
_proxy_ok: bool | None = None   # None = untested, True/False after diag


def _make_session() -> cffi_requests.Session:
    kw: dict = dict(
        impersonate=IMPERSONATE,
        http_version=CurlHttpVersion.V2_0,
        verify=True,
        timeout=30,
        max_redirects=10,
    )
    if PROXY_URL:
        kw["proxy"] = PROXY_URL
    return cffi_requests.Session(**kw)


async def _check_proxy() -> dict:
    """Test proxy connectivity and return a diagnostic dict."""
    global _proxy_ok
    loop = asyncio.get_event_loop()
    result = {"proxy_url": PROXY_URL or "none (direct)"}

    if not PROXY_URL:
        result["proxy_status"] = "no proxy configured"
        _proxy_ok = False
        return result

    s = _make_session()
    try:
        resp = await loop.run_in_executor(
            None,
            lambda: s.get(
                "https://api.ipify.org?format=json",
                headers={"user-agent": BASE_HEADERS["user-agent"]},
                timeout=10,
            ),
        )
        result["proxy_status"]  = "ok"
        result["proxy_http"]    = resp.status_code
        result["egress_ip"]     = resp.json().get("ip", resp.text[:50])
        _proxy_ok = True
    except Exception as e:
        result["proxy_status"] = f"FAILED: {e}"
        _proxy_ok = False
    finally:
        s.close()

    return result


@asynccontextmanager
async def lifespan(_app):
    global _sessions
    _sessions = [_make_session() for _ in range(SESSION_POOL_SIZE)]
    log.info("Pool: %d sessions, impersonate=%s", SESSION_POOL_SIZE, IMPERSONATE)
    if PROXY_URL:
        log.info("Proxy configured: %s", PROXY_URL)
        diag = await _check_proxy()
        log.info("Proxy check: %s", diag)
    else:
        log.warning("No PROXY_URL set — using direct (Render datacenter IP will likely be blocked by CF)")
    yield
    for s in _sessions:
        try: s.close()
        except Exception: pass


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


def _pick() -> cffi_requests.Session:
    global _rr
    s = _sessions[_rr % len(_sessions)]
    _rr += 1
    return s


# ──────────────────────────────────────────────────────────────
# ▌ HELPERS
# ──────────────────────────────────────────────────────────────

def _build_headers(request: Request) -> dict[str, str]:
    merged = dict(BASE_HEADERS)
    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_REQ:
            continue
        if kl in SEC_HEADERS:
            continue    # always keep our spoofed sec- values
        if kl in ("referer", "origin"):
            continue    # always force pwthor values
        merged[k] = v
    # Always force these
    merged["referer"] = FORCED_REFERER
    merged["origin"]  = FORCED_ORIGIN
    return merged


def _merge_cookies(request: Request, extra: dict[str, str] | None = None) -> dict[str, str]:
    merged: dict[str, str] = {}
    if extra:
        merged.update(extra)
    for k, v in request.cookies.items():
        merged[k] = v
    return merged


def _is_cf_block(status: int, body: bytes) -> bool:
    if status in (403, 503):
        b = body[:4096].lower()
        if b"cloudflare" in b or b"cf-mitigated" in b or b"ray id" in b or b"just a moment" in b:
            return True
    return False


async def _fetch(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    body: bytes,
    max_retries: int = 2,
) -> cffi_requests.Response:
    loop   = asyncio.get_event_loop()
    kwargs = dict(
        headers=headers,
        cookies=cookies,
        allow_redirects=True,
        extra_fp=EXTRA_FP,
        akamai=AKAMAI_FP,
    )
    if body:
        kwargs["content"] = body

    last_exc: Exception | None = None

    for attempt in range(max_retries):
        session = _pick()
        try:
            resp = await loop.run_in_executor(
                None,
                lambda s=session: s.request(method, url, **kwargs),
            )
            if _is_cf_block(resp.status_code, resp.content):
                log.warning("CF block status=%d attempt=%d/%d url=%s",
                            resp.status_code, attempt + 1, max_retries, url)
                if attempt < max_retries - 1:
                    await asyncio.sleep(random.uniform(1.0, 2.0))
                    continue
            return resp
        except Exception as exc:
            last_exc = exc
            log.warning("Fetch error attempt %d: %s", attempt + 1, exc)
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

METHODS = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]


@app.api_route("/proxy/{path:path}", methods=METHODS)
async def proxy_endpoint(request: Request, path: str):
    qs   = request.url.query
    url  = f"{PROXY_TARGET}/{path}" + (f"?{qs}" if qs else "")
    hdrs = _build_headers(request)
    cook = _merge_cookies(request)
    body = await request.body()
    log.info("PROXY %s %s", request.method, url)
    try:
        up = await _fetch(request.method, url, hdrs, cook, body)
        log.info("  → %d (%d B)", up.status_code, len(up.content))
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
    log.info("API %s %s", request.method, url)
    try:
        up = await _fetch(request.method, url, hdrs, cook, body)
        log.info("  → %d (%d B)", up.status_code, len(up.content))
        return _respond(up)
    except Exception as exc:
        log.exception("API error: %s", exc)
        return Response(content=f"API error: {exc}", status_code=502)


@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "pool":        len(_sessions),
        "impersonate": IMPERSONATE,
        "proxy":       PROXY_URL or "none (direct)",
        "proxy_ok":    _proxy_ok,
    }


@app.get("/diag")
async def diag():
    """
    Full diagnostic: checks proxy connectivity, returns egress IP.
    Hit this first after deploy to see what's happening.
    """
    proxy_info = await _check_proxy()

    # Also try to reach the actual targets (will show exact error)
    loop = asyncio.get_event_loop()
    target_results = {}

    for name, url in [
        ("pwthor_root", "https://pwthor.live/"),
        ("pwthor_api",  "https://pwthor.live/api/"),
        ("streamvideo", "https://proxy.streamvideo.co.in/"),
    ]:
        s = _make_session()
        try:
            resp = await loop.run_in_executor(
                None,
                lambda u=url, sess=s: sess.get(
                    u,
                    headers=BASE_HEADERS,
                    extra_fp=EXTRA_FP,
                    akamai=AKAMAI_FP,
                    allow_redirects=True,
                    timeout=10,
                ),
            )
            body_preview = resp.content[:300].decode("utf-8", errors="replace")
            target_results[name] = {
                "status":  resp.status_code,
                "headers": dict(resp.headers),
                "body":    body_preview,
            }
        except Exception as e:
            target_results[name] = {"error": str(e)}
        finally:
            s.close()

    return {
        "proxy":   proxy_info,
        "targets": target_results,
        "headers_sent": BASE_HEADERS,
    }
