#!/usr/bin/env bash
set -euo pipefail

APP_FILE="app.py"

if rg -n '^(<<<<<<<|=======|>>>>>>>)' "$APP_FILE" >/tmp/conflict_markers.log 2>/dev/null; then
  echo "[FATAL] Merge conflict markers found in $APP_FILE"
  cat /tmp/conflict_markers.log
  echo "Please resolve conflicts and redeploy."
  exit 1
fi

python3 -m py_compile "$APP_FILE"
exec python3 "$APP_FILE"
