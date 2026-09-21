from flask import Flask, request, Response
from curl_cffi import requests as cffi_requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

TARGET_BASE = "https://proxy.streamvideo.co.in"

# Headers to forward as-is from the original request (if present),
# or inject realistic defaults matching the observed traffic
PASSTHROUGH_HEADERS = [
    "client-id",
    "client-type",
    "client-version",
    "randomid",
    "accept",
    "accept-language",
    "priority",
]

# Headers we always block from being forwarded upstream
BLOCKED_UPSTREAM_HEADERS = {
    "host", "content-length", "transfer-encoding",
    "connection", "x-forwarded-for", "x-real-ip",
}


def build_upstream_headers(incoming_headers: dict) -> dict:
    """Build headers that make the request look like it's coming from
    the original browser (pwthor.live origin)."""

    headers = {
        # Mimic the exact User-Agent observed
        "User-Agent": (
            incoming_headers.get("user-agent")
            or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/149.0.0.0 Safari/537.36"
        ),
        "Accept": incoming_headers.get("accept", "application/json"),
        "Accept-Language": incoming_headers.get("accept-language", "en-US"),
        # The target server checks Origin — spoof it
        "Origin": "https://pwthor.live",
        "Referer": "https://pwthor.live/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Sec-GPC": "1",
    }

    # Forward passthrough headers if the caller supplied them
    for h in PASSTHROUGH_HEADERS:
        val = incoming_headers.get(h)
        if val:
            headers[h] = val

    return headers


@app.route("/proxy/<path:subpath>", methods=["GET", "POST", "OPTIONS", "PUT", "DELETE", "PATCH"])
def proxy(subpath):
    upstream_url = f"{TARGET_BASE}/{subpath}"
    if request.query_string:
        upstream_url += f"?{request.query_string.decode('utf-8')}"

    logger.info(f"Proxying {request.method} → {upstream_url}")

    upstream_headers = build_upstream_headers(dict(request.headers))

    # Body for non-GET requests
    body = request.get_data() or None

    try:
        resp = cffi_requests.request(
            method=request.method,
            url=upstream_url,
            headers=upstream_headers,
            data=body,
            # chrome124 gives a real Chrome TLS/JA3/JA4 fingerprint + HTTP/2
            impersonate="chrome124",
            timeout=30,
            allow_redirects=True,
            verify=True,
        )
    except Exception as exc:
        logger.error(f"Upstream request failed: {exc}")
        return Response(f"Proxy error: {exc}", status=502, mimetype="text/plain")

    # Build response — strip hop-by-hop headers, force CORS open
    excluded_response_headers = {
        "content-encoding", "transfer-encoding", "connection",
        "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "upgrade",
    }

    response_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in excluded_response_headers
    }

    # Always allow any origin so browser callers don't get CORS-blocked
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
    return {"status": "ok", "message": "Proxy is running. Use /proxy/<path>"}, 200


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
