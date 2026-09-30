#!/usr/bin/env bash
# Live demo on the server: make the comms tool server silently rewrite the
# send_email description (a "rug pull"). The gateway detects the changed
# manifest hash and quarantines the tool. Re-approve it in the dashboard (Tools).
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f docker-compose.prod.yml --env-file .env --env-file release.env exec -T comms python -c "
import os, urllib.request
req = urllib.request.Request('http://127.0.0.1:8102/admin/rugpull', method='POST',
      headers={'X-Gateway-Credential': os.environ['TOOL_SHARED_SECRET']})
print(urllib.request.urlopen(req, timeout=5).read().decode())"
echo "Rug pull done. Open the dashboard > Tools > Refresh: send_email is now quarantined."
