#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install-kali-rpi.sh <github_repo_url>"
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: sudo bash scripts/install-kali-rpi.sh <github_repo_url> [branch]"
  echo "Example: sudo bash scripts/install-kali-rpi.sh https://github.com/your-org/vi-scanner.git main"
  exit 1
fi

REPO_URL="$1"
BRANCH="${2:-main}"
APP_DIR="/opt/vi-scanner"
SERVICE_NAME="vi-scanner.service"

echo "[1/8] Installing packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git curl ca-certificates python3 python3-venv python3-pip sqlite3 nmap \
  python3-reportlab fonts-thai-tlwg

echo "[2/8] Preparing app directory..."
mkdir -p /opt
if [[ -d "$APP_DIR/.git" ]]; then
  echo "Repository exists, pulling latest branch: $BRANCH"
  git -C "$APP_DIR" fetch --all
  git -C "$APP_DIR" checkout "$BRANCH"
  git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
else
  rm -rf "$APP_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

echo "[3/8] Creating runtime user/group ownership..."
id -u www-data >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin www-data
chown -R www-data:www-data "$APP_DIR"

echo "[4/8] Creating Python virtualenv..."
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
if [[ -f "$APP_DIR/requirements.txt" ]]; then
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
fi

echo "[5/8] Creating environment file..."
if [[ ! -f "$APP_DIR/.env" ]]; then
  cat > "$APP_DIR/.env" <<ENV
SCANNER_HOST=0.0.0.0
SCANNER_PORT=5000
SCANNER_DB_PATH=$APP_DIR/scanner.db
SCANNER_REPORTS_DIR=$APP_DIR/reports
ENV
fi
mkdir -p "$APP_DIR/reports"
chown -R www-data:www-data "$APP_DIR/reports"

echo "[6/8] Installing systemd service..."
install -m 0644 "$APP_DIR/deploy/$SERVICE_NAME" "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "[7/8] Starting service..."
systemctl restart "$SERVICE_NAME"

echo "[8/8] Done"
echo "Service status:"
systemctl --no-pager --full status "$SERVICE_NAME"
echo "Open in browser: http://$(hostname -I | awk '{print $1}'):5000"
