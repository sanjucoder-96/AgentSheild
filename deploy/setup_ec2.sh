#!/usr/bin/env bash
# One-time setup for a fresh Ubuntu 24.04 EC2 instance.
#   scp -r deploy ubuntu@<EC2-IP>:/tmp/aegis-deploy
#   ssh ubuntu@<EC2-IP> 'sudo bash /tmp/aegis-deploy/setup_ec2.sh'
# Installs Docker, adds swap on small instances, creates /opt/aegis, downloads
# the Amazon RDS CA bundle and generates .env with random secrets.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/aegis
OWNER_USER="${SUDO_USER:-ubuntu}"

echo "==> Installing Docker and Compose"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q docker.io docker-compose-v2 curl openssl ca-certificates
systemctl enable --now docker
usermod -aG docker "$OWNER_USER"

mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
if (( mem_kb < 3000000 )) && ! swapon --show | grep -q /swapfile; then
  echo "==> Small instance ($((mem_kb/1024)) MB RAM): adding 2 GB swap"
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "==> Installing deploy files into $APP"
mkdir -p "$APP/certs"
for f in docker-compose.prod.yml docker-compose.build.yml Caddyfile deploy.sh check_rds.sh demo_rugpull.sh setup_ec2.sh .env.example; do
  [[ "$SRC" == "$APP" ]] || cp "$SRC/$f" "$APP/"
done
chmod +x "$APP"/*.sh

echo "==> Downloading the Amazon RDS certificate bundle"
curl -fsSL -o "$APP/certs/global-bundle.pem" https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
chmod 644 "$APP/certs/global-bundle.pem"

if [[ ! -f "$APP/.env" ]]; then
  echo "==> Generating $APP/.env with random secrets"
  cp "$APP/.env.example" "$APP/.env"
  for key in ADMIN_TOKEN GATEWAY_JWT_SECRET SESSION_SECRET TOOL_SHARED_SECRET REDIS_PASSWORD POSTGRES_PASSWORD; do
    sed -i "s|^$key=.*|$key=$(openssl rand -hex 32)|" "$APP/.env"
  done
  ADMIN_PW=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20)
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$ADMIN_PW|" "$APP/.env"
  PG_PW=$(grep '^POSTGRES_PASSWORD=' "$APP/.env" | cut -d= -f2)
  printf '\n# Plan B (no RDS): run ./deploy.sh with LOCALDB=1 and use this line instead:\n# DATABASE_URL=postgres://aegis:%s@postgres:5432/aegis?sslmode=disable\n' "$PG_PW" >> "$APP/.env"
  echo
  echo "    Dashboard login:  admin / $ADMIN_PW   (also saved in $APP/.env)"
  echo
fi
chmod 600 "$APP/.env"
chown -R "$OWNER_USER:$OWNER_USER" "$APP"

cat <<MSG
==> Setup complete. Next:
  1. Edit $APP/.env: set DOMAIN, IMAGE_OWNER, DATABASE_URL and MODEL_API_KEY
  2. Log out and back in (so your user can run docker without sudo)
  3. Test the database:   cd $APP && ./check_rds.sh
  4. Deploy:              cd $APP && ./deploy.sh          (or let GitHub Actions do it)
MSG
