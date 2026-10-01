#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-wprhvso/free-vpc}"
COUNT="${2:-20}"

echo "Spawning ${COUNT} nodes in parallel for ${REPO}..."
for i in $(seq 1 "$COUNT"); do
  gh workflow run node.yml --repo "$REPO" -f node_id="$i"
  sleep 0.3
done
echo "All ${COUNT} nodes successfully dispatched."
