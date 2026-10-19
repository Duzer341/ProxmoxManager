#!/usr/bin/env bash
# Proxmox Manager - bare-metal / LXC / VM installer for Debian 12+/Ubuntu 22.04+.
#
#   sudo ./install.sh            # install or upgrade in place
#
# Installs to /opt/proxmox-manager, data in /var/lib/proxmox-manager, runs as a
# dedicated system user under systemd. Safe to re-run to upgrade: it keeps .env
# and the database.

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/proxmox-manager}"
DATA_DIR="${DATA_DIR:-/var/lib/proxmox-manager}"
SVC_USER="${SVC_USER:-proxmox-manager}"
SERVICE="proxmox-manager"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

echo "==> Installing OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip rsync >/dev/null

echo "==> Creating service user and directories"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SVC_USER"
fi
mkdir -p "$APP_DIR" "$DATA_DIR"

echo "==> Copying application to $APP_DIR"
rsync -a --delete \
  --exclude '.env' --exclude '.env.bak-*' --exclude 'venv/' --exclude 'data/' --exclude '__pycache__/' --exclude '*.pyc' --exclude '.git/' \
  "$SRC_DIR/" "$APP_DIR/"

echo "==> Creating Python virtualenv and installing dependencies"
if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

if [[ ! -f "$APP_DIR/.env" ]]; then
  echo "==> Generating .env with a fresh secret key"
  SECRET="$("$APP_DIR/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
  sed -e "s|^PM_SECRET_KEY=.*|PM_SECRET_KEY=$SECRET|" \
      -e "s|^PM_DATA_DIR=.*|PM_DATA_DIR=$DATA_DIR|" \
      "$APP_DIR/.env.example" > "$APP_DIR/.env"
  NEW_INSTALL=1
else
  echo "==> Keeping existing .env"
  NEW_INSTALL=0
fi

chown -R "$SVC_USER:$SVC_USER" "$APP_DIR" "$DATA_DIR"
chmod 600 "$APP_DIR/.env"
chmod 750 "$DATA_DIR"

echo "==> Installing systemd service"
install -m 644 "$APP_DIR/deploy/$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null

if [[ "$NEW_INSTALL" == "1" ]]; then
  echo
  echo "==> Create the first admin user"
  read -r -p "Admin username [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"
  cd "$APP_DIR"
  runuser -u "$SVC_USER" -- "$APP_DIR/venv/bin/python" manage.py create-admin "$ADMIN_USER" || \
    echo "   (skipped - run later:  cd $APP_DIR && runuser -u $SVC_USER -- venv/bin/python manage.py create-admin $ADMIN_USER)"
fi

echo "==> Starting service"
systemctl restart "$SERVICE"
sleep 2
systemctl --no-pager --lines=5 status "$SERVICE" || true

PORT="$(grep -E '^PM_PORT=' "$APP_DIR/.env" | cut -d= -f2 || echo 8080)"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "Proxmox Manager is running:  http://${IP:-<this-host>}:${PORT:-8080}/"
echo "  Logs:            journalctl -u $SERVICE -f"
echo "  Config:          $APP_DIR/.env"
echo "  Manage users:    cd $APP_DIR && runuser -u $SVC_USER -- venv/bin/python manage.py list-users"
echo "  Upgrade:         copy the new files over this folder and re-run install.sh"
