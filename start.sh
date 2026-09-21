#!/bin/bash
set -e

echo "==> Installing system deps for headless Firefox..."
apt-get install -y --no-install-recommends \
    xvfb libgtk-3-0 libdbus-glib-1-2 libxt6 \
    libasound2 libx11-xcb1 libxcb-util1 \
    libxrender1 libxi6 libxtst6 \
    fonts-liberation fonts-noto-color-emoji 2>/dev/null || true

echo "==> Fetching Camoufox browser binary..."
# GITHUB_TOKEN must be set as an env var on Render to avoid 60 req/hr rate limit
# Set it in: Render Dashboard → Your Service → Environment → Add GITHUB_TOKEN
if [ -z "$GITHUB_TOKEN" ]; then
    echo "WARNING: GITHUB_TOKEN not set. GitHub rate limits may cause fetch to fail."
    echo "Fix: Go to Render Dashboard → Environment → add GITHUB_TOKEN=<your_pat>"
fi

python -m camoufox fetch --channel coryking/stable

echo "==> Starting proxy..."
exec gunicorn main:app \
    --bind "0.0.0.0:${PORT:-5000}" \
    --workers 1 \
    --timeout 120 \
    --log-level info
