#!/usr/bin/env bash
# enable-https.sh - put Proxmox Manager behind nginx with HTTPS.
#
#   sudo ./deploy/enable-https.sh --self-signed          (until the real certificate arrives)
#   sudo ./deploy/enable-https.sh --pfx /path/to/certificate.pfx --name proxmox.example.com
#   sudo ./deploy/enable-https.sh --cert /path/to/fullchain.pem --key /path/to/privkey.pem --name proxmox.example.com
#
# Options:
#   --self-signed    make a self-signed certificate for this machine's IP address (and --name)
#                    and serve it on https://<ip>/. Browsers warn once; accept it. Re-runs keep
#                    the same certificate. No HSTS in this mode, so the warning stays clickable.
#   --ip ADDRESS     IP for --self-signed (default: this machine's first address, hostname -I)
#   --name NAME      DNS name the dashboard is reached by. Required with --pfx / --cert (the
#                    certificate must cover it); optional with --self-signed (added to it)
#   --pfx FILE       certificate + key as a PFX / PKCS#12 file (asks for its password)
#   --cert FILE      certificate as PEM (with the intermediates after it, if you have them)
#   --chain FILE     extra intermediate certificate(s) as PEM, appended after --cert
#   --key FILE       private key as PEM (not passphrase-protected)
#   --app-dir DIR    install directory (default /opt/proxmox-manager)
#   --no-lockdown    set up nginx only; leave the app listening on all addresses
#
# What it does (safe to re-run):
#   1. Installs nginx if it is missing.
#   2. Checks the key matches the certificate, the certificate covers --name and has not
#      expired (or makes the self-signed one), then stores it as
#      /etc/ssl/proxmox-manager/{fullchain,privkey}.pem (key 600).
#   3. Writes /etc/nginx/sites-available/proxmox-manager: port 80 redirects to https://NAME
#      (self-signed: to https:// on whatever address was used), port 443 proxies to the app on
#      127.0.0.1. Disables nginx's default site.
#   4. Checks https://.../healthz through nginx on this machine.
#   5. Sets PM_HOST=127.0.0.1 and PM_SESSION_COOKIE_SECURE=true in .env (backup kept next to
#      it), restarts the service and checks again. After this the old http://<ip>:8080
#      address stops answering from the network.
#
# Undo:
#   sudo sed -i -e 's/^PM_HOST=.*/PM_HOST=0.0.0.0/' -e 's/^PM_SESSION_COOKIE_SECURE=.*/PM_SESSION_COOKIE_SECURE=false/' /opt/proxmox-manager/.env
#   sudo systemctl restart proxmox-manager
#   sudo rm /etc/nginx/sites-enabled/proxmox-manager && sudo systemctl reload nginx

set -euo pipefail

NAME=""
PFX="" CERT="" CHAIN="" KEY=""
SELF_SIGNED=0 IP=""
APP_DIR="/opt/proxmox-manager"
LOCKDOWN=1
SERVICE="proxmox-manager"
SSL_DIR="/etc/ssl/proxmox-manager"
SITE="/etc/nginx/sites-available/proxmox-manager"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }
die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-signed) SELF_SIGNED=1; shift ;;
    --ip) IP="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --pfx) PFX="$2"; shift 2 ;;
    --cert) CERT="$2"; shift 2 ;;
    --chain) CHAIN="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --no-lockdown) LOCKDOWN=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0 ..."
ENV_FILE="$APP_DIR/.env"
[[ -f "$ENV_FILE" ]] || die "$ENV_FILE not found. Install Proxmox Manager first (install.sh)."
[[ -z "$NAME" || "$NAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "--name must be a plain DNS name, e.g. proxmox.example.com"
if [[ "$SELF_SIGNED" == "1" ]]; then
  [[ -z "$PFX$CERT$KEY$CHAIN" ]] || die "--self-signed makes its own certificate; leave out --pfx/--cert/--key/--chain."
  [[ -n "$IP" ]] || IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Could not work out this machine's IPv4 address; give it with --ip."
elif [[ -z "$NAME" ]]; then
  die "Give the DNS name the dashboard will be reached by, e.g. --name proxmox.example.com (the certificate must cover it)."
elif [[ -n "$PFX" ]]; then
  [[ -f "$PFX" ]] || die "PFX file not found: $PFX"
  [[ -z "$CERT$KEY" ]] || die "Use either --pfx or --cert/--key, not both."
else
  [[ -n "$CERT" && -n "$KEY" ]] || die "Give the certificate: --pfx FILE, or --cert FILE --key FILE."
  [[ -f "$CERT" ]] || die "Certificate file not found: $CERT"
  [[ -f "$KEY" ]] || die "Key file not found: $KEY"
  [[ -z "$CHAIN" || -f "$CHAIN" ]] || die "Chain file not found: $CHAIN"
fi
PORT="$(grep -E '^PM_PORT=' "$ENV_FILE" | tail -1 | cut -d= -f2 | tr -d '[:space:]"' || true)"
PORT="${PORT:-8080}"

step "Installing nginx"
if ! command -v nginx >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx >/dev/null
fi
nginx -v

step "Preparing the certificate"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
only_certs() { sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'; }
is_self_signed() { [[ "$(openssl x509 -noout -subject -in "$1" | sed 's/^subject=//')" == "$(openssl x509 -noout -issuer -in "$1" | sed 's/^issuer=//')" ]]; }
if [[ "$SELF_SIGNED" == "1" ]]; then
  # Keep the existing self-signed certificate if it still fits, so browsers don't have to
  # accept a new one after every run.
  if [[ -f "$SSL_DIR/fullchain.pem" && -f "$SSL_DIR/privkey.pem" ]] && is_self_signed "$SSL_DIR/fullchain.pem" \
     && openssl x509 -noout -checkip "$IP" -in "$SSL_DIR/fullchain.pem" | grep -q "does match" \
     && openssl x509 -noout -checkend 2592000 -in "$SSL_DIR/fullchain.pem" >/dev/null; then
    echo "Keeping the existing self-signed certificate for $IP."
    cp "$SSL_DIR/fullchain.pem" "$WORK/leaf.pem"
    (umask 077; cp "$SSL_DIR/privkey.pem" "$WORK/key.pem")
  else
    SAN="IP:$IP"; [[ -z "$NAME" ]] || SAN="$SAN,DNS:$NAME"
    echo "Making a self-signed certificate for $IP${NAME:+ and $NAME} (valid 825 days)."
    (umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 825 -sha256 \
      -keyout "$WORK/key.pem" -out "$WORK/leaf.pem" \
      -subj "/CN=$IP/O=Proxmox Manager (self-signed)" \
      -addext "subjectAltName=$SAN" \
      -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
      -addext "extendedKeyUsage=serverAuth" 2>/dev/null) || die "openssl could not make the certificate."
  fi
  : > "$WORK/chain.pem"
elif [[ -n "$PFX" ]]; then
  read -rsp "Password for $(basename "$PFX") (Enter if none): " PM_PFX_PASS; echo
  export PM_PFX_PASS
  LEGACY=""
  if ! openssl pkcs12 -in "$PFX" -nokeys -passin env:PM_PFX_PASS -out /dev/null 2>/dev/null; then
    if openssl pkcs12 -legacy -in "$PFX" -nokeys -passin env:PM_PFX_PASS -out /dev/null 2>/dev/null; then
      LEGACY="-legacy"   # older PFX exports (RC2 / 3DES)
    else
      die "Could not open $PFX (wrong password, or not a PFX file)."
    fi
  fi
  # shellcheck disable=SC2086
  openssl pkcs12 $LEGACY -in "$PFX" -clcerts -nokeys -passin env:PM_PFX_PASS 2>/dev/null | only_certs > "$WORK/leaf.pem"
  # shellcheck disable=SC2086
  openssl pkcs12 $LEGACY -in "$PFX" -cacerts -nokeys -passin env:PM_PFX_PASS 2>/dev/null | only_certs > "$WORK/chain.pem" || true
  # shellcheck disable=SC2086
  (umask 077; openssl pkcs12 $LEGACY -in "$PFX" -nocerts -nodes -passin env:PM_PFX_PASS 2>/dev/null | openssl pkey -out "$WORK/key.pem")
  unset PM_PFX_PASS
else
  only_certs < "$CERT" > "$WORK/leaf.pem"
  if [[ -n "$CHAIN" ]]; then only_certs < "$CHAIN" > "$WORK/chain.pem"; else : > "$WORK/chain.pem"; fi
  (umask 077; openssl pkey -in "$KEY" -passin pass: -out "$WORK/key.pem" 2>/dev/null) \
    || die "Could not read the key $KEY (passphrase-protected keys are not supported; remove the passphrase first)."
fi
[[ -s "$WORK/leaf.pem" ]] || die "No certificate found in the input."
[[ -s "$WORK/key.pem" ]] || die "No private key found in the input."
cat "$WORK/leaf.pem" "$WORK/chain.pem" > "$WORK/fullchain.pem"

CERT_PUB="$(openssl x509 -noout -pubkey -in "$WORK/fullchain.pem" | sha256sum)"
KEY_PUB="$(openssl pkey -pubout -in "$WORK/key.pem" | sha256sum)"
[[ "$CERT_PUB" == "$KEY_PUB" ]] || die "The private key does not belong to the certificate."
if [[ "$SELF_SIGNED" == "1" ]]; then
  openssl x509 -noout -checkip "$IP" -in "$WORK/fullchain.pem" | grep -q "does match" || die "The certificate does not cover $IP."
else
  openssl x509 -noout -checkhost "$NAME" -in "$WORK/fullchain.pem" | grep -q "does match" \
  || die "The certificate does not cover $NAME. It is for: $(openssl x509 -noout -ext subjectAltName -in "$WORK/fullchain.pem" 2>/dev/null | tail -n +2 | tr -d ' ')"
fi
openssl x509 -noout -checkend 0 -in "$WORK/fullchain.pem" >/dev/null || die "The certificate has expired."
echo "Subject: $(openssl x509 -noout -subject -in "$WORK/fullchain.pem" | sed 's/^subject=//')"
echo "Issuer:  $(openssl x509 -noout -issuer -in "$WORK/fullchain.pem" | sed 's/^issuer=//')"
echo "Expires: $(openssl x509 -noout -enddate -in "$WORK/fullchain.pem" | cut -d= -f2)"
NCHAIN="$(grep -c 'BEGIN CERTIFICATE' "$WORK/chain.pem" || true)"
if [[ "$SELF_SIGNED" == "1" ]]; then
  echo "SHA-256 fingerprint (to compare with what the browser shows):"
  openssl x509 -noout -fingerprint -sha256 -in "$WORK/fullchain.pem" | cut -d= -f2
elif [[ "$NCHAIN" == "0" ]]; then
  if [[ "$(grep -c 'BEGIN CERTIFICATE' "$WORK/fullchain.pem")" == "1" ]]; then
    echo "WARNING: no intermediate certificate found. Browsers may reject the site; add your CA's intermediate with --chain."
  fi
else
  echo "Intermediates: $NCHAIN"
fi
install -d -m 700 -o root -g root "$SSL_DIR"
install -m 644 -o root -g root "$WORK/fullchain.pem" "$SSL_DIR/fullchain.pem"
install -m 600 -o root -g root "$WORK/key.pem" "$SSL_DIR/privkey.pem"
echo "Stored in $SSL_DIR"

if [[ "$SELF_SIGNED" == "1" ]]; then
  SITE_NAME="_"; LISTEN443="listen 443 ssl http2 default_server;"; REDIRECT="https://\$host\$request_uri"
  HSTS="# no HSTS with a self-signed certificate (it would make the browser warning unclickable)"
  URL="https://$IP"
else
  SITE_NAME="$NAME"; LISTEN443="listen 443 ssl http2;"; REDIRECT="https://$NAME\$request_uri"
  HSTS='add_header Strict-Transport-Security "max-age=31536000" always;'
  URL="https://$NAME"
fi

step "Writing the nginx site ($URL)"
cat > "$SITE" <<EOF
# Proxmox Manager - written by enable-https.sh. Re-run the script to change it.
server {
    listen 80 default_server;
    server_name _;
    return 301 $REDIRECT;
}

server {
    $LISTEN443
    server_name $SITE_NAME;

    ssl_certificate     $SSL_DIR/fullchain.pem;
    ssl_certificate_key $SSL_DIR/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:pmssl:10m;

    $HSTS
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "same-origin" always;
    client_max_body_size 1m;

    location / {
        proxy_pass         http://127.0.0.1:$PORT;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;   # SMART reads on a node with many disks can take a while
    }
}
EOF
ln -sf "$SITE" /etc/nginx/sites-enabled/proxmox-manager
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi

check_https() {
  local out=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [[ "$SELF_SIGNED" == "1" ]]; then
      out="$(curl -sk --noproxy "*" --max-time 5 "https://127.0.0.1/healthz" || true)"
    else
      out="$(curl -sk --noproxy "*" --max-time 5 --resolve "$NAME:443:127.0.0.1" "https://$NAME/healthz" || true)"
    fi
    [[ "$out" == *'"ok":true'* ]] && { echo "$URL/healthz -> $out"; return 0; }
    sleep 1
  done
  echo "$URL/healthz did not answer through nginx (got: ${out:-nothing})." >&2
  return 1
}

step "Checking the dashboard through nginx"
check_https || die "nginx is set up but can't reach the app on 127.0.0.1:$PORT. Is the service running? (systemctl status $SERVICE)"

if [[ "$LOCKDOWN" == "1" ]]; then
  step "Locking the app to nginx (PM_HOST=127.0.0.1, Secure session cookie)"
  BACKUP="$ENV_FILE.bak-$(date +%Y%m%d-%H%M%S)"
  cp -p "$ENV_FILE" "$BACKUP"
  set_env() {
    if grep -qE "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
  }
  set_env PM_HOST 127.0.0.1
  set_env PM_SESSION_COOKIE_SECURE true
  echo ".env updated (backup: $BACKUP)"
  systemctl restart "$SERVICE"
  check_https || die "The app did not come back behind nginx. Restore with: cp -p $BACKUP $ENV_FILE && systemctl restart $SERVICE"
  if ss -ltn 2>/dev/null | grep -qE "(0\.0\.0\.0|\*|\[::\]):$PORT\b"; then
    echo "WARNING: something is still listening on port $PORT on all addresses."
  else
    echo "Port $PORT now only listens on 127.0.0.1."
  fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  step "Firewall (ufw)"
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  echo "Allowed 80 and 443. Remove any old rule for $PORT with: ufw status numbered, then ufw delete <n>"
fi

echo
if [[ "$SELF_SIGNED" == "1" ]]; then
  echo "Done. Open $URL/ and accept the certificate warning once per browser"
  echo "(Firefox: Advanced > Accept the Risk and Continue; Chrome/Edge: Advanced > Proceed)."
  echo "Plain http:// requests are redirected to https://. When the real certificate arrives, run:"
  echo "  sudo $0 --pfx /path/to/certificate.pfx --name <dns name>      (switches to https://<dns name>)"
else
  echo "Done. Open $URL/ (the internal DNS record for $NAME must point at this machine)."
  echo "Everyone is asked to log in again once; plain http:// requests are redirected to $URL/."
fi
