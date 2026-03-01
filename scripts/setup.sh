#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Error: $PYTHON_BIN is not installed. Install Python 3.10+ and retry."
  exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit("Error: Python 3.10+ is required.")
PY

if [ ! -d ".venv" ]; then
  "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
else
  echo ".env already exists; leaving it unchanged"
fi

mkdir -p data/reports

cat <<'EOF'
Setup complete.

Next steps:
1) Update required values in .env (at minimum TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID if you want alerts).
2) Start the app: source .venv/bin/activate && python run.py
3) Open: http://127.0.0.1:3001/app
EOF
