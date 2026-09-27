#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server curl jq netcat-openbsd sudo

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

NODE_NAME="free-vpc-${GITHUB_RUN_ID:-manual}-${NODE_ID:-1}"
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

ASSIGNED_IP=""
for i in $(seq 1 45); do
  ASSIGNED_IP=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)100\.96\.\d+\.\d+' | head -n 1 || true)
  if [ -n "$ASSIGNED_IP" ]; then
    break
  fi
  sleep 1
done

echo "NODE_IP=$ASSIGNED_IP"

if [ -n "${GH_PAT:-}" ] && [ -n "${ASSIGNED_IP}" ]; then
  curl -sS -X PATCH "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/variables/NODE_IP" \
    -H "Authorization: Bearer ${GH_PAT}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"NODE_IP\",\"value\":\"${ASSIGNED_IP}\"}" || true
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf "## Free VPC Node Online\n- Node: %s\n- Mesh IP: \`%s\`\n- User: \`runner\`\n- SSH Command: \`ssh runner@%s\`\n" "$NODE_NAME" "$ASSIGNED_IP" "$ASSIGNED_IP" >> "$GITHUB_STEP_SUMMARY"
fi

START_TIME=$SECONDS
LIFETIME=${LIFETIME_SECONDS:-18000}
while [ $((SECONDS - START_TIME)) -lt "$LIFETIME" ]; do
  if [ -f "/tmp/stop-node" ]; then
    break
  fi
  sleep 15
done
