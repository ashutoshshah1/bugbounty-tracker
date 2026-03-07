#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-3001}"
HEALTH_URL="http://127.0.0.1:${PORT}/api/health"

payload="$(curl --silent --show-error --fail --max-time 10 "$HEALTH_URL")"

PAYLOAD="$payload" python3 - <<'PY'
import json
import os
import sys

payload = json.loads(os.environ["PAYLOAD"])
overall_status = str(payload.get("overall_status") or "").strip().lower()
startup_status = str((payload.get("startup_recovery") or {}).get("status") or "").strip().lower()

if overall_status and overall_status != "ok":
    raise SystemExit(f"overall_status is {overall_status}")

if startup_status == "error":
    raise SystemExit("startup_recovery reported error")
PY
