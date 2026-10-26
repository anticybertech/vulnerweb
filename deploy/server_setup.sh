#!/usr/bin/env bash
# Runs ON the EC2 instance as root. Installs/updates LinCold from /tmp/lincold-release.tar.gz.
# Idempotent: safe to re-run for every deployment.
#   Env: DOMAIN (default vulnerweb.com), CERT_EMAIL (Let's Encrypt contact), SKIP_TLS=1 to skip certbot (HTTP only).
set -euo pipefail
DOMAIN="${DOMAIN:-vulnerweb.com}"
CERT_EMAIL="${CERT_EMAIL:-wayne@antibodynet.net}"
BUNDLE=/tmp/lincold-release.tar.gz
APP_DIR=/opt/lincold
STATE_DIR=/var/lib/lincold

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -f "$BUNDLE" ] || { echo "Missing $BUNDLE"; exit 1; }

echo "==> Installing system packages"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip nginx certbot python3-certbot-nginx unzip curl ca-certificates >/dev/null
  NGINX_SITE=/etc/nginx/sites-available/lincold
  NGINX_LINK=/etc/nginx/sites-enabled/lincold
elif command -v dnf >/dev/null; then
  dnf install -y -q python3 python3-pip nginx certbot python3-certbot-nginx unzip curl ca-certificates
  NGINX_SITE=/etc/nginx/conf.d/lincold.conf
  NGINX_LINK=""
else
  echo "Unsupported OS (need apt or dnf)"; exit 1
fi

echo "==> Installing Nuclei"
if ! /usr/local/bin/nuclei -version >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported arch"; exit 1 ;;
  esac
  VER=$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/projectdiscovery/nuclei/releases/latest)
  VER="${VER##*/}"
  [[ $VER == v* ]] || { echo "Could not determine latest Nuclei version"; exit 1; }
  TMP=$(mktemp -d)
  curl -fsSL -o "$TMP/nuclei.zip" "https://github.com/projectdiscovery/nuclei/releases/download/${VER}/nuclei_${VER#v}_linux_${ARCH}.zip"
  unzip -q -o "$TMP/nuclei.zip" nuclei -d "$TMP"
  install -m 0755 "$TMP/nuclei" /usr/local/bin/nuclei
  rm -rf "$TMP"
fi
/usr/local/bin/nuclei -version 2>&1 | head -1

echo "==> Creating service user and directories"
id lincold >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin lincold
install -d -o lincold -g lincold -m 0750 "$STATE_DIR" "$STATE_DIR/data"
install -d -o root -g lincold -m 0750 /etc/lincold
[ -f /etc/lincold/lincold.env ] || install -o root -g lincold -m 0640 /dev/null /etc/lincold/lincold.env

echo "==> Unpacking application"
install -d -m 0755 "$APP_DIR"
tar -xzf "$BUNDLE" -C "$APP_DIR" --no-same-owner
chown -R root:root "$APP_DIR"
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Updating Nuclei templates"
sudo -u lincold HOME="$STATE_DIR" /usr/local/bin/nuclei -update-templates -silent || echo "WARN: template update failed; will retry on next deploy"

echo "==> Installing systemd service"
install -m 0644 "$APP_DIR/deploy/lincold.service" /etc/systemd/system/lincold.service
systemctl daemon-reload
systemctl enable lincold >/dev/null
systemctl restart lincold

echo "==> Configuring nginx"
mkdir -p /var/www/html/.well-known/acme-challenge
if [ -n "$NGINX_LINK" ]; then ln -sf "$NGINX_SITE" "$NGINX_LINK"; fi
write_http_only() {
  # Bootstrap config (before a certificate exists): ACME webroot + proxy over HTTP
  cat > "$NGINX_SITE" <<NGX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/html; default_type "text/plain"; }
    location / {
        proxy_pass http://127.0.0.1:5055;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGX
}
apply_nginx() { nginx -t && { systemctl reload nginx 2>/dev/null || systemctl restart nginx; }; }
systemctl enable nginx >/dev/null

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
if [ "${SKIP_TLS:-0}" != "1" ] && [ ! -f "$CERT_DIR/fullchain.pem" ]; then
  write_http_only; apply_nginx
  echo "==> Requesting Let's Encrypt certificate (webroot)"
  certbot certonly --webroot -w /var/www/html -n --agree-tos -m "$CERT_EMAIL" -d "$DOMAIN" -d "www.$DOMAIN"
fi
if [ -f "$CERT_DIR/fullchain.pem" ]; then
  [ -f /etc/letsencrypt/options-ssl-nginx.conf ] || curl -fsSL -o /etc/letsencrypt/options-ssl-nginx.conf https://raw.githubusercontent.com/certbot/certbot/main/certbot-nginx/src/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf
  [ -f /etc/letsencrypt/ssl-dhparams.pem ] || openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
  sed "s/__DOMAIN__/$DOMAIN/g" "$APP_DIR/deploy/nginx-vulnerweb.conf" > "$NGINX_SITE"
  if grep -Rqs "ngx_http_modsecurity_module" /etc/nginx/modules-enabled/; then
    mkdir -p /etc/nginx/modsecurity
    install -m 0644 "$APP_DIR/deploy/modsecurity-lincold.conf" /etc/nginx/modsecurity/lincold.conf
  else
    echo "WARN: ModSecurity module not found; serving without WAF"
    sed -i -e '/modsecurity on;/d' -e '/modsecurity_rules_file/d' "$NGINX_SITE"
  fi
  grep -Rqs "headers_more" /etc/nginx/modules-enabled/ || sed -i '/more_clear_headers/d' "$NGINX_SITE"
  # Renew via webroot and reload nginx (certbot's nginx installer is not required)
  RENEW_CONF="/etc/letsencrypt/renewal/$DOMAIN.conf"
  if [ -f "$RENEW_CONF" ]; then
    sed -i -e 's/^authenticator = .*/authenticator = webroot/' -e '/^installer = /d' "$RENEW_CONF"
    grep -q '^webroot_path' "$RENEW_CONF" || sed -i '/^\[renewalparams\]/a webroot_path = /var/www/html,' "$RENEW_CONF"
    grep -q '^\[\[webroot_map\]\]' "$RENEW_CONF" || printf '[[webroot_map]]\n%s = /var/www/html\nwww.%s = /var/www/html\n' "$DOMAIN" "$DOMAIN" >> "$RENEW_CONF"
  fi
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/lincold-reload-nginx.sh
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/lincold-reload-nginx.sh
else
  write_http_only
fi
apply_nginx

echo "==> Waiting for app"
for _ in $(seq 1 20); do
  curl -fs -o /dev/null http://127.0.0.1:5055/ && break
  sleep 1
done
systemctl --no-pager --lines=5 status lincold
curl -fsS -o /dev/null -w "Local app HTTP %{http_code}\n" http://127.0.0.1:5055/
echo "==> Done: https://$DOMAIN"
