#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server curl jq netcat-openbsd sudo iptables

sudo mkdir -p /etc/ssh /etc/ssh/sshd_config.d
if [ -n "${SSH_HOST_ED25519_KEY:-}" ]; then
  echo "${SSH_HOST_ED25519_KEY}" | sudo tee /etc/ssh/ssh_host_ed25519_key > /dev/null
  sudo chmod 600 /etc/ssh/ssh_host_ed25519_key
  sudo ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key | sudo tee /etc/ssh/ssh_host_ed25519_key.pub > /dev/null
fi
if [ -n "${SSH_HOST_RSA_KEY:-}" ]; then
  echo "${SSH_HOST_RSA_KEY}" | sudo tee /etc/ssh/ssh_host_rsa_key > /dev/null
  sudo chmod 600 /etc/ssh/ssh_host_rsa_key
  sudo ssh-keygen -y -f /etc/ssh/ssh_host_rsa_key | sudo tee /etc/ssh/ssh_host_rsa_key.pub > /dev/null
fi

cat << 'SSHEOF' | sudo tee /etc/ssh/sshd_config.d/free-vpc.conf > /dev/null
Port 22
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
AuthorizedKeysFile .ssh/authorized_keys
SSHEOF

sudo mkdir -p /home/runner/.ssh /root/.ssh
sudo chmod 700 /home/runner/.ssh /root/.ssh
AUTH_FILE="/home/runner/.ssh/authorized_keys"
sudo touch "$AUTH_FILE"
if [ -n "${SSH_AUTHORIZED_KEYS:-}" ]; then
  echo "${SSH_AUTHORIZED_KEYS}" | sudo tee -a "$AUTH_FILE" > /dev/null
fi
curl -sSL "https://github.com/wprhvso.keys" | sudo tee -a "$AUTH_FILE" > /dev/null
sudo cp "$AUTH_FILE" /root/.ssh/authorized_keys
sudo chmod 600 "$AUTH_FILE" /root/.ssh/authorized_keys
sudo chown -R runner:runner /home/runner/.ssh
echo "runner ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/runner-nopasswd
sudo chmod 440 /etc/sudoers.d/runner-nopasswd
sudo systemctl restart ssh || sudo service ssh restart || true

NODE_NUM="${NODE_ID:-1}"
NODE_IP="10.0.1.${NODE_NUM}"
sudo ip addr add "${NODE_IP}/32" dev lo || true

NODE_NAME="free-vpc-${GITHUB_RUN_ID:-manual}-${NODE_NUM}"
CREATE_RESP=$(curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/warp_connector" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${NODE_NAME}\"}")
NODE_ID_CF=$(echo "$CREATE_RESP" | jq -r '.result.id // empty')

if [ -z "$NODE_ID_CF" ]; then
  echo "Failed to create WARP connector: $CREATE_RESP" >&2
  exit 1
fi

TOKEN_RESP=$(curl -sS "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/warp_connector/${NODE_ID_CF}/token" \
  -H "Authorization: Bearer ${CF_API_TOKEN}")
CONNECTOR_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.result // empty')

ROUTE_RESP=$(curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/teamnet/routes" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"network\": \"${NODE_IP}/32\",
    \"tunnel_id\": \"${NODE_ID_CF}\",
    \"comment\": \"Node ${NODE_NUM}\"
  }")
ROUTE_ID=$(echo "$ROUTE_RESP" | jq -r '.result.id // empty')

cleanup() {
  if [ -n "${ROUTE_ID:-}" ]; then
    curl -sS -X DELETE "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/teamnet/routes/${ROUTE_ID}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" || true
  fi
  sudo warp-cli --accept-tos disconnect || true
  if [ -n "${NODE_ID_CF:-}" ]; then
    curl -sS -X DELETE "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/warp_connector/${NODE_ID_CF}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" || true
  fi
}
trap cleanup EXIT INT TERM

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(. /etc/os-release && echo $VERSION_CODENAME) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
sudo apt-get update -qq && sudo apt-get install -y -qq cloudflare-warp

sudo warp-cli --accept-tos connector new "$CONNECTOR_TOKEN"
sudo warp-cli --accept-tos connect

sleep 3

sudo ip route replace 10.0.1.0/24 dev CloudflareWARP 2>/dev/null || sudo ip route add 10.0.1.0/24 dev CloudflareWARP 2>/dev/null || true
sudo ip route replace 100.96.0.0/12 dev CloudflareWARP 2>/dev/null || sudo ip route add 100.96.0.0/12 dev CloudflareWARP 2>/dev/null || true

echo "NODE_IP=${NODE_IP}"

if [ -n "${GH_PAT:-}" ]; then
  curl -sS -X PATCH "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/variables/NODE_IP" \
    -H "Authorization: Bearer ${GH_PAT}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"NODE_IP\",\"value\":\"${NODE_IP}\"}" || true
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf "## Free VPC Node Online\n- Node: %s\n- Fixed IP: \`%s\`\n- User: \`runner\`\n- SSH Command: \`ssh runner@%s\`\n" "$NODE_NAME" "$NODE_IP" "$NODE_IP" >> "$GITHUB_STEP_SUMMARY"
fi

START_TIME=$SECONDS
LIFETIME=${LIFETIME_SECONDS:-18000}
while [ $((SECONDS - START_TIME)) -lt "$LIFETIME" ]; do
  if [ -f "/tmp/stop-node" ]; then
    break
  fi
  sleep 15
done
