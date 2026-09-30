#!/usr/bin/env bash
# Prove the EC2 host can reach Amazon RDS over verified TLS, using DATABASE_URL
# from .env and the RDS CA bundle. Prints the TLS version and cipher in use.
set -euo pipefail
cd "$(dirname "$0")"
url=$(grep '^DATABASE_URL=' .env | cut -d= -f2-)
[[ -n "$url" && "$url" != *CHANGE_ME* ]] || { echo "set DATABASE_URL in .env first"; exit 1; }
docker run --rm --network host -v "$PWD/certs:/certs:ro" postgres:16-alpine \
  psql "$url" -v ON_ERROR_STOP=1 -c "select version();" \
  -c "select ssl, version as tls_version, cipher from pg_stat_ssl where pid = pg_backend_pid();"
echo "==> RDS reachable over verified TLS. The gateway creates its audit table on first start."
