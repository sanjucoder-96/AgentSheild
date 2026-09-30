#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for f in logs/*.pid; do
  [[ -f "$f" ]] || continue
  pid=$(cat "$f"); kill "$pid" 2>/dev/null && echo "stopped $(basename "$f" .pid) ($pid)"
  rm -f "$f"
done
