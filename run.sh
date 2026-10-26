#!/usr/bin/env bash
# Starts the LinCold™ Web Vulnerability Scanner on http://127.0.0.1:5055
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
exec .venv/bin/python app.py
