from flask import Flask, request, Response
from curl_cffi import requests as cffi_requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

TARGET_BASE = "https://proxy.streamvideo.co.in"

# These are the EXACT headers captured from the working cross-site fetch
# from pwthor.live → proxy.streamvideo.co.in
# Order matters for HTTP/2 fingerprinting — keep it as-is
FIXED_HEADERS = [
    ("Host",              "proxy.streamvideo.co.in"),
    ("User-Agent",        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"),
    ("Accept",            "application/json"),
    ("Accept-Language",   "en-US"),
    ("Accept-Encoding",   "gzip, deflate, br, zstd"),
    # These three are the key Cloudflare bypass triggers:
    ("Sec-Fetch-Dest",    "empty"),          # ← NOT "document", so CF skips challenge
    ("Sec-Fetch-Mode",    "cors"),
    ("Sec-Fetch-Site",    "cross-site"),     # ← tells CF this is a cross-origin fetch
    ("Sec-GPC",           "1"),
    # Origin + Referer make it look like the request came from pwthor.live
    ("Origin",            "https://pwthor.live"),
    ("Referer",           "https://pwthor.live/"),
    ("Connection",        "keep-alive"),
    ("priority",          "u=1, i"),
]

# Per-request headers forwarded from the caller (they change each request)
DYNAMIC_HEADERS = [
    "client-id",
    "client-type",
    "client-version",
    "randomid",
]


def build_upstream_headers(incoming: dict) -> list:
    """
    Returns an ordered list of (name, value) tuples.
    curl_cffi preserves insertion order for HTTP/2 HPACK — important for
    passing Cloudflare's header-order fingerprint check.
    Dynamic per-request headers are injected right before the Sec-Fetch block,
    matching the position they appear in captured browser traffic.
    """
    headers = []
    dynamic_inserted = False

    for name, value in FIXED_HEADERS:
        # Inject dynamic headers just before Sec-Fetch-Dest (matching real browser order)
        if name == "Sec-Fetch-Dest" and not dynamic_inserted:
            for dh in DYNAMIC_HEADERS:
                v = incoming.get(dh) or incoming.get(dh.lower())
                if v:
                    headers.append((dh, v))
            dynamic_inserted = True
        headers.append((name, value))

    return headers


@app.route("/proxy/<path:subpath>", methods=["GET", "POST", "OPTIONS", "PUT", "DELETE", "PATCH"])
def proxy(subpath):
    upstream_url = f"{TARGET_BASE}/{subpath}"
    if request.query_string:
        upstream_url += f"?{request.query_string.decode('utf-8')}"

    logger.info(f"Proxying {request.method} → {upstream_url}")

    upstream_headers = build_upstream_headers(
        {k.lower(): v for k, v in request.headers.items()}
    )

    body = request.get_data() or None

    try:
        resp = cffi_requests.request(
            method=request.method,
            url=upstream_url,
            headers=upstream_headers,
            data=body,
            # chrome124 = real Chrome 124 JA3/JA4 TLS fingerprint + HTTP/2 ALPN
            impersonate="chrome124",
            timeout=30,
            allow_redirects=True,
            verify=True,
            # Do NOT send any cookies from our server — clean slate, just like
            # a cross-site fetch where third-party cookies are blocked
            cookies={},
        )
    except Exception as exc:
        logger.error(f"Upstream request failed: {exc}")
        return Response(f"Proxy error: {exc}", status=502, mimetype="text/plain")

    logger.info(f"Upstream responded {resp.status_code}")

    # Strip hop-by-hop + encoding headers (Flask handles encoding itself)
    excluded = {
        "content-encoding", "transfer-encoding", "connection",
        "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "upgrade",
    }
    response_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in excluded
    }

    # Open CORS so your frontend JS can read the response
    response_headers["Access-Control-Allow-Origin"] = "*"
    response_headers["Access-Control-Allow-Headers"] = "*"
    response_headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE, PATCH"

    return Response(
        response=resp.content,
        status=resp.status_code,
        headers=response_headers,
        direct_passthrough=True,
    )


@app.route("/", methods=["GET"])
def health():
    return {"status": "ok", "message": "Proxy running. Use /proxy/<path>"}, 200


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
