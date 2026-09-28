#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/firecracker_manager.sh"

WORKER_URL="${WORKER_URL:-https://vm.unsafie.com}"

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
INTERNAL_GATEWAY="10.200.${NODE_NUM}.1"
INTERNAL_SUBNET="10.200.${NODE_NUM}.0/24"

setup_bridge "$INTERNAL_GATEWAY" "$INTERNAL_SUBNET"
start_metadata_server "$INTERNAL_GATEWAY" 18080

curl -fsSL https://tailscale.com/install.sh | sh
sudo systemctl start tailscaled || sudo tailscaled --state=/var/lib/tailscale/tailscaled.state &
sleep 2

TS_AUTH="${TAILSCALE_AUTH_KEY:-${TAILSCALE_AUTHKEY:-}}"
sudo tailscale up --authkey="${TS_AUTH}" --hostname="free-vpc-${NODE_NUM}" --accept-routes --ssh

TAILSCALE_IP=""
for i in $(seq 1 30); do
  TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || true)
  if [ -n "$TAILSCALE_IP" ]; then
    break
  fi
  sleep 1
done

install_firecracker
download_assets

BOOT_DATA=$(curl -sS -X POST "${WORKER_URL}/api/runner/boot" \
  -H "Content-Type: application/json" \
  -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-5a06f20e534be12f4e259e932af57b57.access}" \
  -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a}" \
  -d "{\"run_id\": ${GITHUB_RUN_ID:-0}, \"slot_id\": ${NODE_NUM}, \"tailscale_ip\": \"${TAILSCALE_IP}\"}")

CURRENT_KEYS_HASH=""

sync_keys() {
  local json_keys="$1"
  local new_hash
  new_hash=$(echo "$json_keys" | md5sum | awk '{print $1}')
  if [ "$new_hash" != "$CURRENT_KEYS_HASH" ]; then
    CURRENT_KEYS_HASH="$new_hash"
    local tmp_k="/tmp/ts_keys.txt"
    echo "$json_keys" | jq -r '.[]' 2>/dev/null > "$tmp_k" || true
    if [ -s "$tmp_k" ]; then
      sudo cp "$tmp_k" "$AUTH_FILE"
      sudo cp "$tmp_k" /root/.ssh/authorized_keys
      sudo cp "$tmp_k" /tmp/free-vpc-auth-keys
      sudo chmod 600 "$AUTH_FILE" /root/.ssh/authorized_keys /tmp/free-vpc-auth-keys
    fi
    rm -f "$tmp_k"
  fi
}

INIT_KEYS=$(echo "$BOOT_DATA" | jq '.ssh_keys // []')
sync_keys "$INIT_KEYS"

VMS_COUNT=$(echo "$BOOT_DATA" | jq '.vms | length')
if [ "$VMS_COUNT" -gt 0 ]; then
  for row in $(echo "$BOOT_DATA" | jq -r '.vms[] | @base64'); do
    _jq() {
      echo "${row}" | base64 --decode | jq -r "${1}"
    }
    VM_ID=$(_jq '.id')
    VM_VCPUS=$(_jq '.vcpus // 1')
    VM_RAM=$(_jq '.memory_mb // 1024')
    VM_KEYS=$(_jq '.ssh_keys // empty')
    if [ -n "$VM_KEYS" ] && [ "$VM_KEYS" != "null" ]; then
      echo "$VM_KEYS" | jq -r '.[]' 2>/dev/null > "/tmp/keys_${VM_ID}" || true
    fi
    spawn_microvm "$VM_ID" "10.200.${NODE_NUM}.2" "$INTERNAL_GATEWAY" "$VM_VCPUS" "$VM_RAM"
  done
else
  spawn_microvm "vm-${NODE_NUM}-standby" "10.200.${NODE_NUM}.2" "$INTERNAL_GATEWAY" 1 1024 || true
fi

if [ -n "${GH_PAT:-}" ] && [ -n "${TAILSCALE_IP}" ]; then
  curl -sS -X PATCH "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/variables/NODE_IP" \
    -H "Authorization: Bearer ${GH_PAT}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"NODE_IP\",\"value\":\"${TAILSCALE_IP}\"}" || true
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf "## Free VPC Online\n- Tailscale Host IP: \`%s\`\n- Slot: \`#%s\`\n" "$TAILSCALE_IP" "$NODE_NUM" >> "$GITHUB_STEP_SUMMARY"
fi

cleanup() {
  sudo tailscale logout || true
  pkill -f "metadata_server.py" || true
}
trap cleanup EXIT INT TERM

START_TIME=$SECONDS
HANDOVER_TRIGGERED=0

while [ $((SECONDS - START_TIME)) -lt 21120 ]; do
  if [ -f "/tmp/stop-node" ]; then
    break
  fi

  REPORTED_JSON="[]"
  for f in /tmp/vm_ip_*; do
    if [ -f "$f" ]; then
      F_VM_ID="${f#/tmp/vm_ip_}"
      F_VM_IP=$(cat "$f" 2>/dev/null || true)
      if [ -n "$F_VM_IP" ]; then
        REPORTED_JSON=$(echo "$REPORTED_JSON" | jq --arg vid "$F_VM_ID" --arg vip "$F_VM_IP" '. + [{"vm_id": $vid, "vm_ip": $vip}]')
      fi
    fi
  done

  HB_DATA=$(curl -sS -X POST "${WORKER_URL}/api/runner/heartbeat" \
    -H "Content-Type: application/json" \
    -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-5a06f20e534be12f4e259e932af57b57.access}" \
    -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a}" \
    -d "{\"slot_id\": ${NODE_NUM}, \"tailscale_ip\": \"${TAILSCALE_IP}\", \"reported_vms\": ${REPORTED_JSON}}" 2>/dev/null || true)

  LATEST_KEYS=$(echo "$HB_DATA" | jq '.ssh_keys // []' 2>/dev/null || true)
  if [ -n "$LATEST_KEYS" ] && [ "$LATEST_KEYS" != "null" ]; then
    sync_keys "$LATEST_KEYS"
  fi

  TASKS_COUNT=$(echo "$HB_DATA" | jq -r '.tasks | length // 0' 2>/dev/null || echo 0)
  if [ "$TASKS_COUNT" -gt 0 ]; then
    for row in $(echo "$HB_DATA" | jq -r '.tasks[] | @base64'); do
      _tjq() {
        echo "${row}" | base64 --decode | jq -r "${1}"
      }
      TASK_ID=$(_tjq '.id')
      TASK_TYPE=$(_tjq '.type')
      TASK_PAYLOAD=$(_tjq '.payload')

      if [ "$TASK_TYPE" = "claim" ] || [ "$TASK_TYPE" = "activate_vm" ]; then
        TASK_VM_ID=$(echo "$TASK_PAYLOAD" | jq -r '.vm_id // empty')
        TASK_IP=$(echo "$TASK_PAYLOAD" | jq -r '.ip // empty')
        echo "$TASK_PAYLOAD" | jq -r '.ssh_keys[]?' 2>/dev/null > "/tmp/keys_${TASK_IP}" || true
        echo "$TASK_PAYLOAD" | jq -r '.ssh_keys[]?' 2>/dev/null > "/tmp/keys_${TASK_VM_ID}" || true
        curl -sS -X POST "${WORKER_URL}/api/runner/ack" \
          -H "Content-Type: application/json" \
          -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-5a06f20e534be12f4e259e932af57b57.access}" \
          -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a}" \
          -d "{\"task_id\": \"${TASK_ID}\", \"slot_id\": ${NODE_NUM}}" >/dev/null 2>&1 || true
      elif [ "$TASK_TYPE" = "spawn_standby" ]; then
        SVM_ID=$(echo "$TASK_PAYLOAD" | jq -r '.vm_id')
        SVM_VCPUS=$(echo "$TASK_PAYLOAD" | jq -r '.vcpus // 1')
        SVM_RAM=$(echo "$TASK_PAYLOAD" | jq -r '.memory_mb // 1024')
        spawn_microvm "$SVM_ID" "10.200.${NODE_NUM}.2" "$INTERNAL_GATEWAY" "$SVM_VCPUS" "$SVM_RAM" || true
        curl -sS -X POST "${WORKER_URL}/api/runner/ack" \
          -H "Content-Type: application/json" \
          -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-5a06f20e534be12f4e259e932af57b57.access}" \
          -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a}" \
          -d "{\"task_id\": \"${TASK_ID}\", \"slot_id\": ${NODE_NUM}}" >/dev/null 2>&1 || true
      elif [ "$TASK_TYPE" = "stop_vm" ]; then
        SVM_ID=$(echo "$TASK_PAYLOAD" | jq -r '.vm_id')
        stop_microvm "$SVM_ID" || true
        curl -sS -X POST "${WORKER_URL}/api/runner/ack" \
          -H "Content-Type: application/json" \
          -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-5a06f20e534be12f4e259e932af57b57.access}" \
          -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a}" \
          -d "{\"task_id\": \"${TASK_ID}\", \"slot_id\": ${NODE_NUM}}" >/dev/null 2>&1 || true
      fi
    done
  fi

  if [ $((SECONDS - START_TIME)) -ge 20700 ] && [ "$HANDOVER_TRIGGERED" -eq 0 ]; then
    HANDOVER_TRIGGERED=1
    curl -sS -X POST "${WORKER_URL}/api/runner/handover" \
      -H "Content-Type: application/json" \
      -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-5a06f20e534be12f4e259e932af57b57.access}" \
      -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a}" \
      -d "{\"slot_id\": ${NODE_NUM}}" >/dev/null 2>&1 || true
  fi

  sleep 5
done
