#!/usr/bin/env bash
# Deploy or update AgentShield on this server.
#   ./deploy.sh [TAG]      pull images built by GitHub Actions (default tag: latest)
#   ./deploy.sh --build    Plan B: build images here from a full repo checkout
#   LOCALDB=1 ./deploy.sh  Plan B: also run a local Postgres instead of RDS
set -euo pipefail
cd "$(dirname "$0")"
[[ -f .env ]] || { echo ".env missing: run setup_ec2.sh first"; exit 1; }
[[ -f certs/global-bundle.pem ]] || echo "warning: certs/global-bundle.pem missing (needed for RDS TLS)"

files=(-f docker-compose.prod.yml)
if [[ "${1:-}" == "--build" ]]; then
  files+=(-f docker-compose.build.yml)
  printf 'GATEWAY_IMAGE=aegis-gateway:local\nTOOLS_IMAGE=aegis-tools:local\n' > release.env
else
  owner=$(grep '^IMAGE_OWNER=' .env | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
  [[ -n "$owner" && "$owner" != "your-github-username" ]] || { echo "set IMAGE_OWNER in .env"; exit 1; }
  tag="${1:-latest}"
  printf 'GATEWAY_IMAGE=ghcr.io/%s/aegis-gateway:%s\nTOOLS_IMAGE=ghcr.io/%s/aegis-tools:%s\n' "$owner" "$tag" "$owner" "$tag" > release.env
fi
profiles=()
[[ "${LOCALDB:-}" == "1" ]] && profiles=(--profile localdb)
dc() { docker compose "${files[@]}" --env-file .env --env-file release.env "${profiles[@]}" "$@"; }

if [[ "${1:-}" == "--build" ]]; then dc build; else dc pull; fi
dc up -d --remove-orphans

echo "==> Waiting for the gateway to become healthy"
for _ in $(seq 1 30); do
  if dc exec -T gateway /app/bin/gatewayctl health >/dev/null 2>&1; then
    dc ps
    echo "==> Live at https://$(grep '^DOMAIN=' .env | cut -d= -f2)"
    docker image prune -f >/dev/null
    exit 0
  fi
  sleep 3
done
echo "gateway did not become healthy; recent logs:"
dc logs --tail 60 gateway
exit 1
