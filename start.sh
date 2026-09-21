#!/bin/bash
set -e

echo "==> Installing Camoufox browser binary..."
python -m camoufox fetch

echo "==> Starting proxy server..."
exec gunicorn main:app --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120
