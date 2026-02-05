#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/update-kali-rpi.sh [branch]"
  exit 1
fi

APP_DIR="/opt/vi-scanner"
BRANCH="${1:-main}"

if [[ ! -d "$APP_DIR/.git" ]]; then
  echo "$APP_DIR is not a git repository. Install first."
  exit 1
fi

git -C "$APP_DIR" fetch --all
git -C "$APP_DIR" checkout "$BRANCH"
git -C "$APP_DIR" pull --ff-only origin "$BRANCH"

"$APP_DIR/.venv/bin/pip" install --upgrade pip
if [[ -f "$APP_DIR/requirements.txt" ]]; then
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
fi

systemctl restart vi-scanner.service
systemctl --no-pager status vi-scanner.service
