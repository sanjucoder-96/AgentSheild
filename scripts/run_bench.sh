#!/usr/bin/env bash
# Runs the benchmark against all three baselines by restarting the gateway in
# each profile. Tool servers and attacker keep running. Writes results/summary.json.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs results
rm -f results/summary.json
ADMIN=${ADMIN_TOKEN:-dev-admin-token}

start_gateway() { # profile
  [[ -f logs/gateway.pid ]] && kill "$(cat logs/gateway.pid)" 2>/dev/null || true
  sleep 1
  if command -v setsid >/dev/null 2>&1; then
    GATEWAY_PROFILE="$1" setsid nohup ./bin/gateway >"logs/gateway-$1.log" 2>&1 </dev/null &
  else
    GATEWAY_PROFILE="$1" nohup ./bin/gateway >"logs/gateway-$1.log" 2>&1 </dev/null &
  fi
  echo $! >logs/gateway.pid
  for _ in $(seq 1 40); do curl -s -o /dev/null http://127.0.0.1:8080/healthz && return 0; sleep 0.5; done
  echo "gateway ($1) failed to start"; exit 1
}

for profile in off allowlist_only full; do
  echo "=== profile: $profile ==="
  start_gateway "$profile"
  ./bin/bench -profiles "$profile" "$@"
done
echo
echo "Combined results in results/summary.json"
