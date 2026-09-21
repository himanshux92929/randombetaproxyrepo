#!/bin/bash
set -e

echo "==> Fetching Camoufox browser binary..."
if [ -z "$GITHUB_TOKEN" ]; then
    echo "WARNING: GITHUB_TOKEN not set - may hit GitHub rate limits"
fi

python -m camoufox fetch

echo "==> Starting proxy..."
exec gunicorn main:app \
    --bind "0.0.0.0:${PORT:-5000}" \
    --workers 1 \
    --timeout 120 \
    --log-level info
