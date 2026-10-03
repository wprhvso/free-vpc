#!/usr/bin/env bash
set -u

SLOT_ID="${1:-${NODE_ID:-1}}"
REPO="${2:-${GITHUB_REPOSITORY:-wprhvso/free-vpc}}"
TOKEN="${3:-${GH_PAT:-}}"
TOTAL_SLOTS="${4:-${TOTAL_SLOTS:-20}}"
BRANCH="${5:-${GITHUB_REF_NAME:-main}}"

if [ -z "$TOKEN" ]; then
  exit 0
fi

sleep 180

while true; do
  KUBECONFIG_ARG=""
  if [ -f /etc/rancher/k3s/k3s.yaml ]; then
    KUBECONFIG_ARG="--kubeconfig /etc/rancher/k3s/k3s.yaml"
  fi

  if ! command -v kubectl >/dev/null 2>&1; then
    sleep 30
    continue
  fi

  NODES_JSON=$(kubectl $KUBECONFIG_ARG get nodes -o json 2>/dev/null || true)
  if [ -z "$NODES_JSON" ]; then
    sleep 30
    continue
  fi

  ACTIVE_RUNS=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${REPO}/actions/workflows/node.yml/runs?status=queued&per_page=100" 2>/dev/null || true)
  QUEUED_COUNT=$(echo "$ACTIVE_RUNS" | jq -r '.total_count // 0' 2>/dev/null || echo 0)

  IN_PROG_RUNS=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${REPO}/actions/workflows/node.yml/runs?status=in_progress&per_page=100" 2>/dev/null || true)
  IN_PROG_COUNT=$(echo "$IN_PROG_RUNS" | jq -r '.total_count // 0' 2>/dev/null || echo 0)

  TOTAL_ACTIVE=$(( QUEUED_COUNT + IN_PROG_COUNT ))

  if [ "$QUEUED_COUNT" -ge 20 ]; then
    sleep 120
    continue
  fi

  for s in $(seq 1 "$TOTAL_SLOTS"); do
    NODE_NAME="free-vpc-${s}"
    NODE_STATUS=$(echo "$NODES_JSON" | jq -r ".items[] | select(.metadata.name == \"$NODE_NAME\") | .status.conditions[]? | select(.type == \"Ready\") | .status" 2>/dev/null || true)

    if [ "$NODE_STATUS" != "True" ]; then
      if [ "$TOTAL_ACTIVE" -ge 20 ]; then
        break
      fi

      DISPATCH_RES=$(curl -s -w "%{http_code}" -o /dev/null -X POST \
        "https://api.github.com/repos/${REPO}/actions/workflows/node.yml/dispatches" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        -d "{\"ref\":\"${BRANCH}\",\"inputs\":{\"node_id\":\"$s\"}}" 2>/dev/null || true)

      if [ "$DISPATCH_RES" = "204" ]; then
        TOTAL_ACTIVE=$(( TOTAL_ACTIVE + 1 ))
      fi
      sleep 3
    fi
  done
  sleep 300
done
