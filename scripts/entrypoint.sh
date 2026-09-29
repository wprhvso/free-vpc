#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/firecracker_manager.sh"

CF_TUNNEL_TOKEN="${CF_TUNNEL_TOKEN:-eyJhIjoiMzlmNjg1OGY5YjU4NjU2NTJhYzY5YzUwNmVjNDczNmMiLCJ0IjoiYTcxZDM2OTctMGI3Ny00YjQzLWE4MWEtMDYyNmQ2NWMwNjliIiwicyI6Ik16ZzRaak13TWprdE1qSmhZaTAwWWpaaExXRXdPVGt0TlRsbE9URTBNMk13WTJWbCJ9}"

sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server curl jq netcat-openbsd sudo iptables e2fsprogs

sudo mkdir -p /etc/ssh /etc/ssh/sshd_config.d
if [ -n "${SSH_HOST_ED25519_KEY:-}" ]; then
    echo "${SSH_HOST_ED25519_KEY}" | sudo tee /etc/ssh/ssh_host_ed25519_key >/dev/null
    sudo chmod 600 /etc/ssh/ssh_host_ed25519_key
    sudo ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key | sudo tee /etc/ssh/ssh_host_ed25519_key.pub >/dev/null
fi
if [ -n "${SSH_HOST_RSA_KEY:-}" ]; then
    echo "${SSH_HOST_RSA_KEY}" | sudo tee /etc/ssh/ssh_host_rsa_key >/dev/null
    sudo chmod 600 /etc/ssh/ssh_host_rsa_key
    sudo ssh-keygen -y -f /etc/ssh/ssh_host_rsa_key | sudo tee /etc/ssh/ssh_host_rsa_key.pub >/dev/null
fi

cat <<'SSHEOF' | sudo tee /etc/ssh/sshd_config.d/free-vpc.conf >/dev/null
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
    cat authorized_keys | sudo tee -a "$AUTH_FILE" >/dev/null
fi
if [ -n "${SSH_AUTHORIZED_KEYS:-}" ]; then
    echo "${SSH_AUTHORIZED_KEYS}" | sudo tee -a "$AUTH_FILE" >/dev/null
fi
curl -sSL "https://github.com/wprhvso.keys" | sudo tee -a "$AUTH_FILE" >/dev/null
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
NODE_NAME="free-vpc-${GITHUB_RUN_ID:-manual}-${NODE_NUM}"

download_assets

echo "Installing latest Zig nightly..."
ZIG_TARBALL_URL=$(curl -sS https://ziglang.org/download/index.json | jq -r '.master."x86_64-linux".tarball')
curl -sSL "$ZIG_TARBALL_URL" | sudo tar -xJ -C /usr/local
sudo ln -sf /usr/local/zig-x86_64-linux-*/zig /usr/local/bin/zig
echo "Zig installed: $(zig version)"

echo "Building cf-proxy-server using Zig nightly..."
cd "${SCRIPT_DIR}/../proxy"
zig build -Donly-server=true --prefix /tmp/zig-proxy-dist
sudo cp /tmp/zig-proxy-dist/bin/cf-proxy-server /usr/local/bin/cf-proxy-server
sudo chmod +x /usr/local/bin/cf-proxy-server
cd "${SCRIPT_DIR}"

/usr/local/bin/cf-proxy-server >/tmp/cf-proxy-server.log 2>&1 &
SERVER_PID=$!

sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: cf-proxy-server failed to start! Crash log:" >&2
    cat /tmp/cf-proxy-server.log >&2
    exit 1
fi

echo "cf-proxy-server started successfully (PID $SERVER_PID)"

if ! nc -z 127.0.0.1 8023; then
    echo "ERROR: cf-proxy-server port 8023 is not reachable!" >&2
    exit 1
fi

if [ -n "${CF_TUNNEL_TOKEN:-}" ]; then
    echo "Starting cloudflared named tunnel..."
    /usr/local/bin/cloudflared tunnel run --token "${CF_TUNNEL_TOKEN}" >/tmp/cf_named_tunnel.log 2>&1 &
    sleep 3
fi

cleanup() {
    if [ -x /usr/local/bin/rqlited ]; then
        curl -s -X POST "http://127.0.0.1:4001/db/execute" \
            -H "Content-Type: application/json" \
            -d "[[\"UPDATE runners SET status = 'offline' WHERE slot_id = ?\", $NODE_NUM]]" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

MESH_IP="127.0.0.1"

mkdir -p /tmp/rqlite-data

if [ "$NODE_NUM" = "1" ]; then
    /usr/local/bin/rqlited -node-id "node-${NODE_NUM}" -http-addr "0.0.0.0:4001" -raft-addr "0.0.0.0:4002" /tmp/rqlite-data >/tmp/rqlited.log 2>&1 &
    sleep 3

    curl -s -X POST "http://127.0.0.1:4001/db/execute" \
        -H "Content-Type: application/json" \
        -d '[["CREATE TABLE IF NOT EXISTS runners (slot_id INTEGER PRIMARY KEY, node_name TEXT, mesh_ip TEXT, web_url TEXT, ssh_url TEXT, status TEXT, started_at INTEGER, last_heartbeat INTEGER, expires_at INTEGER)"], ["CREATE TABLE IF NOT EXISTS vms (id TEXT PRIMARY KEY, slot_id INTEGER, name TEXT, status TEXT, created_at INTEGER)"]]' >/dev/null 2>&1 || true

    if [ -n "${GH_PAT:-}" ] && [ -n "${MESH_IP}" ]; then
        curl -sS -X PATCH "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/variables/SEED_MESH_IP" \
            -H "Authorization: Bearer ${GH_PAT}" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Content-Type: application/json" \
            -d "{\"name\":\"SEED_MESH_IP\",\"value\":\"${MESH_IP}\"}" 2>/dev/null || true
    fi

    python3 "${SCRIPT_DIR}/dashboard_server.py" 8080 >/tmp/dashboard.log 2>&1 &
    /usr/local/bin/ttyd -p 7681 -b /ssh -W -t fontSize=14 -t theme='{"background": "#0b0f19"}' bash >/tmp/ttyd.log 2>&1 &

# cloudflared tunnel already started above
else
    SEED_IP=""
    if [ -n "${GH_PAT:-}" ]; then
        SEED_IP=$(curl -s -H "Authorization: Bearer ${GH_PAT}" "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/variables/SEED_MESH_IP" | jq -r '.value // empty' 2>/dev/null || true)
    fi

    if [ -n "$SEED_IP" ] && ping -c 1 -W 2 "$SEED_IP" >/dev/null 2>&1; then
        /usr/local/bin/rqlited -node-id "node-${NODE_NUM}" -http-addr "0.0.0.0:4001" -raft-addr "0.0.0.0:4002" -join "http://${SEED_IP}:4001" /tmp/rqlite-data >/tmp/rqlited.log 2>&1 &
    else
        /usr/local/bin/rqlited -node-id "node-${NODE_NUM}" -http-addr "0.0.0.0:4001" -raft-addr "0.0.0.0:4002" /tmp/rqlite-data >/tmp/rqlited.log 2>&1 &
    fi
    sleep 3

    /usr/local/bin/ttyd -p 7681 -b /ssh -W -t fontSize=14 -t theme='{"background": "#0b0f19"}' bash >/tmp/ttyd.log 2>&1 &
fi

NOW=$(date +%s)
EXPIRES=$((NOW + 21600))

curl -s -X POST "http://127.0.0.1:4001/db/execute" \
    -H "Content-Type: application/json" \
    -d '[["INSERT OR REPLACE INTO runners (slot_id, node_name, mesh_ip, web_url, ssh_url, status, started_at, last_heartbeat, expires_at) VALUES (?, ?, ?, ?, ?, '\''online'\'', ?, ?, ?)", '$NODE_NUM', "'$NODE_NAME'", "'$MESH_IP'", "https://vm.unsafie.com", "ssh.unsafie.com:443", '$NOW', '$NOW', '$EXPIRES']]' >/dev/null 2>&1 || true

bash "${SCRIPT_DIR}/cluster_orchestrator.sh" "$NODE_NUM" "${GITHUB_REPOSITORY:-wprhvso/free-vpc}" "${GH_PAT:-}" 20 >/tmp/orchestrator.log 2>&1 &

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf "## Free VPC Node Online\n- Slot: \`#%s\`\n- Mesh IP: \`%s\`\n- Web Portal: https://vm.unsafie.com\n- Web SSH Terminal: https://vm.unsafie.com/ssh\n- CLI SSH via gRPC: \`ssh.unsafie.com:443\`\n" "$NODE_NUM" "${MESH_IP:-none}" >>"$GITHUB_STEP_SUMMARY"
fi

START_TIME=$SECONDS

while [ $((SECONDS - START_TIME)) -lt 21120 ]; do
    if [ -f "/tmp/stop-node" ]; then
        break
    fi
    sleep 10
done

if [ -x /usr/local/bin/rqlited ]; then
    curl -s -X POST "http://127.0.0.1:4001/db/execute" \
        -H "Content-Type: application/json" \
        -d "[[\"UPDATE runners SET status = 'draining' WHERE slot_id = ?\", $NODE_NUM]]" >/dev/null 2>&1 || true
fi
