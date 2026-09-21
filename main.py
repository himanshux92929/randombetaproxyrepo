"""
Two-layer Cloudflare bypass proxy:
  Layer 1 — Camoufox (patched Firefox): solves CF JS challenge, gets cf_clearance cookie
  Layer 2 — curl_cffi (Chrome TLS fingerprint): reuses cookie for fast subsequent requests

On first request to a domain, Camoufox spins up, solves the challenge (~10-30s),
stores the cf_clearance cookie. All later requests use curl_cffi with that cookie
until it expires, then Camoufox re-solves automatically.
"""

import os
import time
import logging
import threading
from flask import Flask, request, Response
from curl_cffi import requests as cffi_requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

TARGET_BASE = "https://proxy.streamvideo.co.in"

# ── Cookie store ──────────────────────────────────────────────────────────────
# { domain: {"cookies": {name: value}, "ua": str, "expires_at": float} }
_cookie_store: dict = {}
_store_lock = threading.Lock()
CF_COOKIE_TTL = 60 * 60 * 4  # re-solve every 4 hours (cf_clearance lasts ~24h)

# The exact UA the original site uses — must match between Camoufox solve + curl_cffi replay
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36"
)


# ── Camoufox solver ──────────────────────────────────────────────────────────

def _solve_with_camoufox(url: str) -> dict:
    """
    Spin up a headless Camoufox (patched Firefox) browser, navigate to the URL,
    wait for Cloudflare to issue cf_clearance, then return all cookies as a dict.
    This is slow (~10-30s) but only runs once per domain / cookie expiry.
    """
    from camoufox.sync_api import Camoufox

    logger.info(f"[Camoufox] Solving CF challenge for {url} ...")
    cookies = {}

    with Camoufox(headless=True, geoip=True) as fox:
        page = fox.new_page()

        # Set the same UA the app will use for curl_cffi replays
        page.set_extra_http_headers({"User-Agent": BROWSER_UA})
        page.goto(url, wait_until="networkidle", timeout=60000)

        # Wait up to 30s for cf_clearance to appear
        deadline = time.time() + 30
        while time.time() < deadline:
            raw = page.context.cookies()
            cf = {c["name"]: c["value"] for c in raw if c["name"] == "cf_clearance"}
            if cf:
                cookies = {c["name"]: c["value"] for c in raw}
                logger.info(f"[Camoufox] Got cf_clearance ✓")
                break
            time.sleep(1)
        else:
            # No clearance cookie — grab whatever cookies exist and try anyway
            cookies = {c["name"]: c["value"] for c in page.context.cookies()}
            logger.warning("[Camoufox] cf_clearance not seen; using available cookies")

        page.close()

    return cookies


def get_clearance_cookies(domain: str, sample_url: str) -> dict:
    """Return cached cookies or re-solve if expired."""
    with _store_lock:
        entry = _cookie_store.get(domain)
        now = time.time()
        if entry and now < entry["expires_at"]:
            return entry["cookies"]

    # Need to solve — do it outside the lock so other threads don't pile up
    logger.info(f"[Store] Cookie cache miss for {domain}, solving ...")
    new_cookies = _solve_with_camoufox(sample_url)

    with _store_lock:
        _cookie_store[domain] = {
            "cookies": new_cookies,
            "expires_at": time.time() + CF_COOKIE_TTL,
        }
    return new_cookies


# ── Request builder ──────────────────────────────────────────────────────────

PASSTHROUGH_REQUEST_HEADERS = [
    "client-id", "client-type", "client-version", "randomid",
    "accept", "accept-language", "priority",
]

BLOCKED_RESPONSE_HEADERS = {
    "content-encoding", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade",
}


def build_headers(incoming: dict) -> dict:
    h = {
        "User-Agent":      BROWSER_UA,
        "Accept":          incoming.get("accept", "application/json"),
        "Accept-Language": incoming.get("accept-language", "en-US"),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Origin":          "https://pwthor.live",
        "Referer":         "https://pwthor.live/",
        "Sec-Fetch-Dest":  "empty",
        "Sec-Fetch-Mode":  "cors",
        "Sec-Fetch-Site":  "cross-site",
        "Sec-GPC":         "1",
        "priority":        "u=1, i",
    }
    for key in PASSTHROUGH_REQUEST_HEADERS:
        val = incoming.get(key) or incoming.get(key.lower())
        if val:
            h[key] = val
    return h


# ── Proxy route ───────────────────────────────────────────────────────────────

@app.route("/proxy/<path:subpath>", methods=["GET", "POST", "OPTIONS", "PUT", "DELETE", "PATCH"])
def proxy(subpath):
    upstream_url = f"{TARGET_BASE}/{subpath}"
    if request.query_string:
        upstream_url += f"?{request.query_string.decode('utf-8')}"

    logger.info(f"→ {request.method} {upstream_url}")

    incoming = {k.lower(): v for k, v in request.headers.items()}
    headers  = build_headers(incoming)
    body     = request.get_data() or None

    # Get (or solve for) cf_clearance cookies
    from urllib.parse import urlparse
    domain = urlparse(upstream_url).netloc
    cf_cookies = get_clearance_cookies(domain, upstream_url)

    try:
        resp = cffi_requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            cookies=cf_cookies,           # ← the solved cf_clearance goes here
            data=body,
            impersonate="chrome124",      # match Chrome TLS fingerprint to UA above
            timeout=30,
            allow_redirects=True,
            verify=True,
        )
    except Exception as exc:
        logger.error(f"Upstream error: {exc}")
        return Response(f"Proxy error: {exc}", status=502, mimetype="text/plain")

    logger.info(f"← {resp.status_code}")

    # If CF blocked us again, invalidate cache and retry once with a fresh solve
    if resp.status_code in (403, 503) and b"cloudflare" in resp.content.lower():
        logger.warning("CF block detected — invalidating cache and re-solving ...")
        with _store_lock:
            _cookie_store.pop(domain, None)
        cf_cookies = get_clearance_cookies(domain, upstream_url)
        try:
            resp = cffi_requests.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                cookies=cf_cookies,
                data=body,
                impersonate="chrome124",
                timeout=30,
                allow_redirects=True,
                verify=True,
            )
        except Exception as exc:
            return Response(f"Retry error: {exc}", status=502, mimetype="text/plain")

    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in BLOCKED_RESPONSE_HEADERS
    }
    resp_headers["Access-Control-Allow-Origin"]  = "*"
    resp_headers["Access-Control-Allow-Headers"] = "*"
    resp_headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE, PATCH"

    return Response(
        response=resp.content,
        status=resp.status_code,
        headers=resp_headers,
        direct_passthrough=True,
    )


@app.route("/", methods=["GET"])
def health():
    return {"status": "ok", "message": "Proxy running. Use /proxy/<path>"}, 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
