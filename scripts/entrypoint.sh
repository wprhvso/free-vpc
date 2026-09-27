#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/firecracker_manager.sh"

WORKER_URL="${WORKER_URL:-https://free-vpc-orchestrator.wprhvso.workers.dev}"

sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server curl jq netcat-openbsd sudo iptables e2fsprogs

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
if [ -f "authorized_keys" ]; then
  cat authorized_keys | sudo tee -a "$AUTH_FILE" > /dev/null
fi
if [ -n "${SSH_AUTHORIZED_KEYS:-}" ]; then
  echo "${SSH_AUTHORIZED_KEYS}" | sudo tee -a "$AUTH_FILE" > /dev/null
fi
curl -sSL "https://github.com/wprhvso.keys" | sudo tee -a "$AUTH_FILE" > /dev/null
sudo cp "$AUTH_FILE" /root/.ssh/authorized_keys
sudo cp "$AUTH_FILE" /tmp/free-vpc-auth-keys
sudo chmod 600 "$AUTH_FILE" /root/.ssh/authorized_keys /tmp/free-vpc-auth-keys
sudo chown -R runner:runner /home/runner/.ssh
echo "runner ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/runner-nopasswd
sudo chmod 440 /etc/sudoers.d/runner-nopasswd
sudo systemctl restart ssh || sudo service ssh restart || true

setup_kvm
setup_zswap
setup_ksm

NODE_NUM="${NODE_ID:-1}"
X1=$(( 2 + (NODE_NUM - 1) / 256 ))
X2=$(( (NODE_NUM - 1) % 256 ))
SUBNET="10.${X1}.${X2}.0/24"
GATEWAY_IP="10.${X1}.${X2}.1"

setup_bridge "$GATEWAY_IP" "$SUBNET"

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
    \"network\": \"${SUBNET}\",
    \"tunnel_id\": \"${NODE_ID_CF}\",
    \"comment\": \"Runner ${NODE_NUM}\"
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
  if command -v tailscale >/dev/null 2>&1; then
    sudo tailscale logout || true
  fi
}
trap cleanup EXIT INT TERM

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(. /etc/os-release && echo $VERSION_CODENAME) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
sudo apt-get update -qq && sudo apt-get install -y -qq cloudflare-warp

sudo warp-cli --accept-tos connector new "$CONNECTOR_TOKEN"
sudo warp-cli --accept-tos connect

sleep 3

sudo ip route replace 10.0.0.0/8 dev CloudflareWARP 2>/dev/null || sudo ip route add 10.0.0.0/8 dev CloudflareWARP 2>/dev/null || true
sudo ip route replace 100.96.0.0/12 dev CloudflareWARP 2>/dev/null || sudo ip route add 100.96.0.0/12 dev CloudflareWARP 2>/dev/null || true

TS_IP=""
if [ -n "${TAILSCALE_AUTH_KEY:-}" ]; then
  curl -fsSL https://tailscale.com/install.sh | sudo sh
  sudo systemctl enable --now tailscaled || true
  sleep 2
  sudo tailscale up --auth-key="${TAILSCALE_AUTH_KEY}" --hostname="${NODE_NAME}" --accept-routes --ssh || \
  sudo tailscale up --auth-key="${TAILSCALE_AUTH_KEY}" --hostname="${NODE_NAME}" --accept-routes || true
  TS_IP=$(tailscale ip -4 2>/dev/null || true)
  echo "Tailscale online: ${NODE_NAME} (${TS_IP})"
fi

BOOT_DATA=$(curl -sS -X POST "${WORKER_URL}/api/runner/boot" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\": ${GITHUB_RUN_ID:-0}, \"slot_id\": ${NODE_NUM}}")

install_firecracker
download_assets

VMS_COUNT=$(echo "$BOOT_DATA" | jq '.vms | length')
if [ "$VMS_COUNT" -gt 0 ]; then
  for row in $(echo "$BOOT_DATA" | jq -r '.vms[] | @base64'); do
    _jq() {
      echo "${row}" | base64 --decode | jq -r "${1}"
    }
    VM_ID=$(_jq '.id')
    VM_IP=$(_jq '.ip')
    VM_VCPUS=$(_jq '.vcpus')
    VM_RAM=$(_jq '.memory_mb')
    spawn_microvm "$VM_ID" "$VM_IP" "$GATEWAY_IP" "$VM_VCPUS" "$VM_RAM"
  done
else
  DEFAULT_VM_IP="10.${X1}.${X2}.2"
  spawn_microvm "vm-${NODE_NUM}-default" "$DEFAULT_VM_IP" "$GATEWAY_IP" 2 2048 || true
fi

if [ -n "${GH_PAT:-}" ]; then
  curl -sS -X PATCH "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/variables/NODE_IP" \
    -H "Authorization: Bearer ${GH_PAT}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"NODE_IP\",\"value\":\"${GATEWAY_IP}\"}" || true
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf "## Free VPC Node Online\n- Node: %s\n- Host Gateway IP: \`%s\`\n- MicroVM Subnet: \`%s\`\n- Default VM IP: \`10.%s.%s.2\`\n- Tailscale IP: \`%s\`\n" "$NODE_NAME" "$GATEWAY_IP" "$SUBNET" "$X1" "$X2" "${TS_IP:-none}" >> "$GITHUB_STEP_SUMMARY"
fi

START_TIME=$SECONDS
HANDOVER_TRIGGERED=0

while [ $((SECONDS - START_TIME)) -lt 21120 ]; do
  if [ -f "/tmp/stop-node" ]; then
    break
  fi

  curl -sS -X POST "${WORKER_URL}/api/runner/heartbeat" \
    -H "Content-Type: application/json" \
    -d "{\"slot_id\": ${NODE_NUM}, \"runner_id\": \"${NODE_NAME}\"}" >/dev/null 2>&1 || true

  if [ $((SECONDS - START_TIME)) -ge 20700 ] && [ "$HANDOVER_TRIGGERED" -eq 0 ]; then
    HANDOVER_TRIGGERED=1
    curl -sS -X POST "${WORKER_URL}/api/runner/handover" \
      -H "Content-Type: application/json" \
      -d "{\"slot_id\": ${NODE_NUM}, \"runner_id\": \"${NODE_NAME}\"}" >/dev/null 2>&1 || true
  fi

  sleep 30
done
