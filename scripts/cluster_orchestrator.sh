#!/usr/bin/env bash
set -u

SLOT_ID="${1:-1}"
REPO="${2:-wprhvso/free-vpc}"
TOKEN="${3:-}"
TOTAL_SLOTS="${4:-20}"

while true; do
  STATUS_JSON=$(curl -s "http://127.0.0.1:4001/status" 2>/dev/null || true)
  RAFT_STATE=$(echo "$STATUS_JSON" | jq -r '.store.raft.state // empty' 2>/dev/null || true)

  NOW=$(date +%s)

  curl -s -X POST "http://127.0.0.1:4001/db/execute" \
    -H "Content-Type: application/json" \
    -d "[[\"UPDATE runners SET last_heartbeat = ?, status = 'online' WHERE slot_id = ?\", $NOW, $SLOT_ID]]" >/dev/null 2>&1 || true

  if [ "$RAFT_STATE" = "Leader" ] && [ -n "$TOKEN" ]; then
    QUERY_RES=$(curl -s -X POST "http://127.0.0.1:4001/db/query" \
      -H "Content-Type: application/json" \
      -d "[[\"SELECT slot_id, last_heartbeat, expires_at FROM runners WHERE status = 'online'\"]]" 2>/dev/null || true)

    ACTIVE_SLOTS=$(echo "$QUERY_RES" | jq -r '.results[0].values[]? | select(('$NOW' - .[1]) <= 90) | .[0]' 2>/dev/null || true)
    ACTIVE_SET=" $ACTIVE_SLOTS "

    for s in $(seq 1 "$TOTAL_SLOTS"); do
      if ! echo "$ACTIVE_SET" | grep -q " $s "; then
        curl -s -X POST "https://api.github.com/repos/${REPO}/actions/workflows/node.yml/dispatches" \
          -H "Authorization: Bearer ${TOKEN}" \
          -H "Accept: application/vnd.github.v3+json" \
          -H "Content-Type: application/json" \
          -d "{\"ref\":\"init-free-vpc\",\"inputs\":{\"node_id\":\"$s\"}}" >/dev/null 2>&1 || true
        sleep 1
      fi
    done
  fi

  sleep 15
done
