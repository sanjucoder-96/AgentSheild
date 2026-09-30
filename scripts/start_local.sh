#!/usr/bin/env bash
# Starts the attacker sink, three tool servers and the gateway in the background.
# Logs go to logs/, stop everything with scripts/stop_local.sh
# Usage: scripts/start_local.sh [--direct]   (--direct = tool servers accept calls without the gateway; baseline demo only)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs
DIRECT=""
[[ "${1:-}" == "--direct" ]] && DIRECT="--allow-direct"
PY=${PYTHON:-python3}

launch() { # name, command...
  local name=$1; shift
  if command -v setsid >/dev/null 2>&1; then
    setsid nohup "$@" >"logs/$name.log" 2>&1 </dev/null &
  else
    nohup "$@" >"logs/$name.log" 2>&1 </dev/null &
  fi
  echo $! >"logs/$name.pid"
  echo "started $name (pid $!) -> logs/$name.log"
}

[[ -x bin/gateway ]] || { echo "bin/gateway missing: run 'make build' first"; exit 1; }
launch attacker  "$PY" attacker/attacker_server.py
launch workspace "$PY" tools/workspace_server.py $DIRECT
launch comms     "$PY" tools/comms_server.py $DIRECT
launch crm       "$PY" tools/crm_server.py $DIRECT

printf "waiting for tool servers"
for port in 8101 8102 8103; do
  for _ in $(seq 1 40); do
    if curl -s -o /dev/null "http://127.0.0.1:$port/mcp" 2>/dev/null; then break; fi
    printf "."; sleep 0.5
  done
done
echo
launch gateway ./bin/gateway -config "${GATEWAY_CONFIG:-config/gateway.yaml}"
for _ in $(seq 1 40); do
  if curl -s -o /dev/null http://127.0.0.1:8080/healthz; then
    echo "gateway ready: dashboard http://localhost:8080  (admin token: \${ADMIN_TOKEN:-dev-admin-token})"
    exit 0
  fi
  sleep 0.5
done
echo "gateway did not start; see logs/gateway.log"; exit 1
