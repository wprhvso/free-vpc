#!/usr/bin/env bash
set -u

SLOT_ID="${1:-1}"
REPO="${2:-wprhvso/free-vpc}"
TOKEN="${3:-}"
TOTAL_SLOTS="${4:-20}"
BRANCH="${5:-main}"

if [ -z "$TOKEN" ]; then
  exit 0
fi

while true; do
  sleep 20

  if ! command -v kubectl >/dev/null 2>&1; then
    continue
  fi

  NODES_JSON=$(kubectl get nodes -o json 2>/dev/null || true)
  if [ -z "$NODES_JSON" ]; then
    continue
  fi

  NOW=$(date +%s)

  for s in $(seq 1 "$TOTAL_SLOTS"); do
    NODE_NAME="free-vpc-${s}"
    NODE_STATUS=$(echo "$NODES_JSON" | jq -r ".items[] | select(.metadata.name == \"$NODE_NAME\") | .status.conditions[]? | select(.type == \"Ready\") | .status" 2>/dev/null || true)

    if [ "$NODE_STATUS" != "True" ]; then
      curl -s -X POST "https://api.github.com/repos/${REPO}/actions/workflows/node.yml/dispatches" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        -d "{\"ref\":\"${BRANCH}\",\"inputs\":{\"node_id\":\"$s\"}}" >/dev/null 2>&1 || true
      sleep 1
    fi
  done
done
