#!/usr/bin/env bash
# Deploys LinCold to AWS EC2 through a configured SSH jump host.
#
# Usage:
#   ./deploy/deploy_ec2.sh                 # deploy/update the app
#   ./deploy/deploy_ec2.sh --create-admin  # also create/reset the admin account (prompts for a temporary password)
#
# Settings (environment variables):
#   JUMP_HOST     SSH target for your jump host                     (required)
#   JUMP_USER     user on the jump host                             (default: ubuntu)
#   KEY_ON_JUMP   1 = jump host holds the EC2 key/alias (default), 0 = EC2 key is on this machine (uses ProxyJump)
#   EC2_TARGET    EC2 SSH alias as seen from the jump host           (default: ec2)
#   EC2_HOST      EC2 hostname or public IP (KEY_ON_JUMP=0)           (required in this mode)
#   EC2_USER      EC2 login user (KEY_ON_JUMP=0)                    (default: ubuntu)
#   EC2_KEY       EC2 private key path (required if KEY_ON_JUMP=0; optional on jump host)
#   DOMAIN        site domain                                       (required)
#   CERT_EMAIL    Let's Encrypt contact email                       (required)
#   ADMIN_EMAIL   admin account for --create-admin                   (required in this mode)
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"

JUMP_HOST="${JUMP_HOST:?Set JUMP_HOST to your SSH jump host}"
JUMP_USER="${JUMP_USER:-ubuntu}"
KEY_ON_JUMP="${KEY_ON_JUMP:-1}"
EC2_HOST="${EC2_HOST:-}"
EC2_USER="${EC2_USER:-ubuntu}"
EC2_KEY="${EC2_KEY:-}"
EC2_TARGET="${EC2_TARGET:-ec2}"
[[ $KEY_ON_JUMP == 1 || -n $EC2_KEY ]] || { echo "Set EC2_KEY when KEY_ON_JUMP=0"; exit 1; }
[[ $KEY_ON_JUMP == 1 || -n $EC2_HOST ]] || { echo "Set EC2_HOST when KEY_ON_JUMP=0"; exit 1; }
DOMAIN="${DOMAIN:?Set DOMAIN to your site hostname}"
CERT_EMAIL="${CERT_EMAIL:?Set CERT_EMAIL for certificate registration}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
CREATE_ADMIN=0
[[ "${1:-}" == "--create-admin" ]] && CREATE_ADMIN=1
[[ $CREATE_ADMIN == 0 || -n $ADMIN_EMAIL ]] || { echo "Set ADMIN_EMAIL for --create-admin"; exit 1; }

for v in "$DOMAIN" "$CERT_EMAIL" "$ADMIN_EMAIL" "$EC2_HOST" "$EC2_USER" "$EC2_TARGET" "$EC2_KEY"; do
  [[ $v =~ ^[A-Za-z0-9._@/~+-]*$ ]] || { echo "Unsafe characters in setting: $v"; exit 1; }
done

ADMIN_PW=""
if [[ $CREATE_ADMIN == 1 ]]; then
  read -rsp "Temporary password for $ADMIN_EMAIL (min 8 chars): " ADMIN_PW; echo
  [[ ${#ADMIN_PW} -ge 8 ]] || { echo "Password too short"; exit 1; }
fi

SOCK="/tmp/lincold-ec2-$$.sock"
BUNDLE=""
COMMON=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=30)
JUMP=("${COMMON[@]}" -o ControlMaster=auto -o "ControlPath=$SOCK" -o ControlPersist=120)
trap 'ssh -O exit -o "ControlPath=$SOCK" "$JUMP_USER@$JUMP_HOST" 2>/dev/null || true; rm -f "$BUNDLE"' EXIT

echo "==> Building release bundle"
BUNDLE="$(mktemp /tmp/lincold-release.XXXXXX.tar.gz)"
tar -czf "$BUNDLE" -C "$HERE" \
  --exclude=.venv --exclude=data --exclude=__pycache__ --exclude='*.pyc' \
  app.py config.py db.py manage.py report.py scanner.py requirements.txt run.sh README.md static templates samples deploy
echo "    $(du -h "$BUNDLE" | cut -f1) bundle"

REMOTE_SETUP="sudo DOMAIN=$DOMAIN CERT_EMAIL=$CERT_EMAIL bash /tmp/lincold-server_setup.sh"
REMOTE_ADMIN="cd /tmp && sudo -u lincold env HOME=/var/lib/lincold LINCOLD_DATA_DIR=/var/lib/lincold/data /opt/lincold/.venv/bin/python /opt/lincold/manage.py create-admin $ADMIN_EMAIL --name Administrator --password-stdin"

if [[ $KEY_ON_JUMP == 1 ]]; then
  echo "==> Copying to $JUMP_USER@$JUMP_HOST"
  scp -q "${JUMP[@]}" "$BUNDLE" "$JUMP_USER@$JUMP_HOST:/tmp/lincold-release.tar.gz"
  scp -q "${JUMP[@]}" "$HERE/deploy/server_setup.sh" "$JUMP_USER@$JUMP_HOST:/tmp/lincold-server_setup.sh"
  E="${EC2_KEY:+-i $EC2_KEY} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15"
  echo "==> Jump host to $EC2_TARGET: upload + install"
  ssh "${JUMP[@]}" "$JUMP_USER@$JUMP_HOST" \
    "set -e; scp -q $E /tmp/lincold-release.tar.gz /tmp/lincold-server_setup.sh $EC2_TARGET:/tmp/ \
     && ssh $E $EC2_TARGET \"$REMOTE_SETUP\"; rm -f /tmp/lincold-release.tar.gz /tmp/lincold-server_setup.sh"
  if [[ $CREATE_ADMIN == 1 ]]; then
    printf '%s' "$ADMIN_PW" | ssh "${JUMP[@]}" "$JUMP_USER@$JUMP_HOST" "ssh $E $EC2_TARGET \"$REMOTE_ADMIN\""
  fi
else
  EC2=("${COMMON[@]}" -i "$EC2_KEY" -J "$JUMP_USER@$JUMP_HOST")
  echo "==> Uploading to $EC2_USER@$EC2_HOST via $JUMP_HOST"
  scp -q "${EC2[@]}" "$BUNDLE" "$EC2_USER@$EC2_HOST:/tmp/lincold-release.tar.gz"
  scp -q "${EC2[@]}" "$HERE/deploy/server_setup.sh" "$EC2_USER@$EC2_HOST:/tmp/lincold-server_setup.sh"
  echo "==> Installing"
  ssh "${EC2[@]}" "$EC2_USER@$EC2_HOST" "$REMOTE_SETUP"
  if [[ $CREATE_ADMIN == 1 ]]; then
    printf '%s' "$ADMIN_PW" | ssh "${EC2[@]}" "$EC2_USER@$EC2_HOST" "$REMOTE_ADMIN"
  fi
fi

echo "==> Verifying https://$DOMAIN"
curl -fsS -o /dev/null -w "    HTTPS %{http_code}\n" "https://$DOMAIN/" || echo "    HTTPS check failed (DNS/TLS may still be propagating)"
