#!/usr/bin/env bash
set -x

sudo apt-get update -qq && sudo apt-get install -y -qq curl jq

NODE_NAME="diag-node-${GITHUB_RUN_ID}"
CREATE_RESP=$(curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/warp_connector" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${NODE_NAME}\"}")
NODE_ID_CF=$(echo "$CREATE_RESP" | jq -r '.result.id // empty')
echo "NODE_ID_CF: $NODE_ID_CF"

TOKEN_RESP=$(curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/warp_connector/${NODE_ID_CF}/token" \
  -H "Authorization: Bearer ${CF_API_TOKEN}")
CONNECTOR_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.result // empty')

cleanup() {
  sudo warp-cli --accept-tos disconnect || true
  curl -sS -X DELETE "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/warp_connector/${NODE_ID_CF}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" || true
}
trap cleanup EXIT INT TERM

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(. /etc/os-release && echo $VERSION_CODENAME) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
sudo apt-get update -qq && sudo apt-get install -y -qq cloudflare-warp

sudo warp-cli --accept-tos connector new "$CONNECTOR_TOKEN"
sudo warp-cli --accept-tos connect

sleep 5

echo "=== IP ADDR ==="
ip addr show

echo "=== IP ROUTE ==="
ip route show

echo "=== WARP STATUS ==="
warp-cli status

echo "=== WARP SETTINGS ==="
warp-cli settings

echo "=== WARP REGISTRATION SHOW ==="
warp-cli registration show

echo "=== WARP CONNECTOR SHOW ==="
warp-cli connector show || true

echo "=== WARP TUNNEL STATS ==="
warp-cli tunnel stats || true
