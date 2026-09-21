# CF-Proxy — Cloudflare-bypass reverse proxy

FastAPI + **curl_cffi** (Chrome 124 TLS/JA3 fingerprint) proxy server.  
Deploys to Render in ~2 minutes.

## Endpoints

| Path | Forwards to |
|------|-------------|
| `/proxy/<path>` | `https://proxy.streamvideo.co.in/<path>` |
| `/api/<path>` | `https://pwthor.live/api/<path>` + injected cookies |
| `/health` | Status check |

### What gets forwarded
- ✅ All HTTP methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
- ✅ All request headers verbatim (including `Referer`, `Origin`, `Authorization`)
- ✅ Query string
- ✅ Request body
- ✅ Incoming cookies (merged with injected cookies for `/api/`)
- ✅ All response headers (`Set-Cookie`, `Content-Type`, `Cache-Control`, …)
- ✅ Exact response body + status code

---

## Adding / editing injected cookies

Open `main.py` and find this block near the top:

```python
INJECTED_COOKIES: dict[str, str] = {
    # "cookie1": "value1",
    # "cookie2": "value2",
}
```

Add as many as you need:

```python
INJECTED_COOKIES: dict[str, str] = {
    "session": "abc123",
    "auth_token": "xyz987",
    "user_id": "42",
}
```

Incoming request cookies always **override** injected ones if the key clashes,  
so the real browser's cookies are never discarded.

---

## Deploy to Render

1. Push this folder to a GitHub repo (public or private).
2. Go to https://dashboard.render.com → **New → Web Service**.
3. Connect the repo.
4. Render auto-detects `render.yaml` — just click **Deploy**.
5. Done. Your service URL is `https://<name>.onrender.com`.

### Manual settings (if not using render.yaml)
| Field | Value |
|-------|-------|
| Environment | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 2 --loop uvloop --http httptools` |

### Optional env vars
| Var | Default | Purpose |
|-----|---------|---------|
| `SESSION_POOL_SIZE` | `4` | curl_cffi session pool size |

---

## How Cloudflare bypass works

`curl_cffi` wraps **libcurl** built against **BoringSSL** and lets you specify
an exact browser impersonation target (`chrome124` here).  This means:

- **TLS ClientHello / JA3 fingerprint** — identical to Chrome 124
- **HTTP/2 SETTINGS frames** — exact Chrome ordering & values  
- **ALPN, cipher suites, extensions** — all match the real browser
- **No Puppeteer / Playwright overhead** — pure C, microsecond latency

Cloudflare's bot detection inspects all of the above at the TCP/TLS layer,
before your application code even runs.  Because the fingerprint is
indistinguishable from real Chrome, it scores as a human visitor.
