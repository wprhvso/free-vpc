#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/share/boost 2>/dev/null || true

if [ -e /dev/kvm ]; then
    sudo chmod 666 /dev/kvm
fi

sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server curl jq netcat-openbsd socat python3-cryptography rclone e2fsprogs iptables xz-utils 2>/dev/null || true

if ! command -v yggdrasil >/dev/null 2>&1; then
    curl -fsSL https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v0.5.14/yggdrasil-0.5.14-amd64.deb -o /tmp/ygg.deb
    sudo dpkg -i /tmp/ygg.deb 2>/dev/null || true
    rm -f /tmp/ygg.deb
fi

if ! command -v cloudflared >/dev/null 2>&1; then
    sudo curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
    sudo chmod +x /usr/local/bin/cloudflared
fi

if ! command -v k3s >/dev/null 2>&1; then
    curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_START=true sh -
fi

RAW_ID="${NODE_ID:-1}"
NODE_NUM=$(echo "$RAW_ID" | tr -cd "0-9")
NODE_NUM="${NODE_NUM:-1}"
TOTAL_SLOTS="${TOTAL_SLOTS:-20}"
CLUSTER_SALT="${CLUSTER_SALT:-unsafie-cluster-v1}"
YGG_PASS="${YGG_PASSWORD:?YGG_PASSWORD is required}"
K3S_SECRET="${K3S_TOKEN:?K3S_TOKEN is required}"
S3_PASS="${S3_SECRET_KEY:-}"

YGG_DATA=$(python3 "${SCRIPT_DIR}/ygg_gen.py" "$NODE_NUM" "$TOTAL_SLOTS" "$CLUSTER_SALT" "/usr/bin/yggdrasil")
PRIV_KEY=$(echo "$YGG_DATA" | jq -r .private_key)
MY_IPV6=$(echo "$YGG_DATA" | jq -r .my_address)

echo "$YGG_DATA" | jq -r ".hosts[]" | sudo tee -a /etc/hosts >/dev/null

sudo mkdir -p /etc/yggdrasil
if [ "$NODE_NUM" -le 3 ]; then
    LISTEN_CONF="[\"ws://127.0.0.1:9001?password=${YGG_PASS}\"]"
else
    LISTEN_CONF="[]"
fi

cat <<YGGEOF | sudo tee /etc/yggdrasil/yggdrasil.conf >/dev/null
{
  "PrivateKey": "${PRIV_KEY}",
  "Peers": [
    "wss://mesh1.unsafie.com:443?password=${YGG_PASS}",
    "wss://mesh2.unsafie.com:443?password=${YGG_PASS}",
    "wss://mesh3.unsafie.com:443?password=${YGG_PASS}"
  ],
  "Listen": ${LISTEN_CONF},
  "IfName": "ygg0",
  "IfMTU": 1280
}
YGGEOF

sudo yggdrasil -useconffile /etc/yggdrasil/yggdrasil.conf >/tmp/yggdrasil.log 2>&1 &
sleep 1

if [ "$NODE_NUM" -le 3 ]; then
    TOKEN_VAR="CF_TUNNEL_TOKEN_${NODE_NUM}"
    CURRENT_TUNNEL_TOKEN="${!TOKEN_VAR:-${CF_TUNNEL_TOKEN:-}}"
    if [ -n "$CURRENT_TUNNEL_TOKEN" ]; then
        TOKEN_JSON=$(echo "$CURRENT_TUNNEL_TOKEN" | base64 -d 2>/dev/null || true)
        CF_ACC=$(echo "$TOKEN_JSON" | jq -r '.a // empty' 2>/dev/null || true)
        CF_TUN_ID=$(echo "$TOKEN_JSON" | jq -r '.t // empty' 2>/dev/null || true)
        CF_SECRET=$(echo "$TOKEN_JSON" | jq -r '.s // empty' 2>/dev/null || true)

        if [ -n "$CF_ACC" ] && [ -n "$CF_TUN_ID" ] && [ -n "$CF_SECRET" ]; then
            sudo mkdir -p /etc/cloudflared
            cat <<CREDEOF | sudo tee /etc/cloudflared/credentials.json >/dev/null
{
  "AccountTag": "${CF_ACC}",
  "TunnelID": "${CF_TUN_ID}",
  "TunnelSecret": "${CF_SECRET}"
}
CREDEOF
            cat <<CFEOF | sudo tee /etc/cloudflared/config.yml >/dev/null
tunnel: ${CF_TUN_ID}
credentials-file: /etc/cloudflared/credentials.json
ingress:
  - hostname: mesh${NODE_NUM}.unsafie.com
    service: http://127.0.0.1:9001
  - hostname: gitops.unsafie.com
    service: http://127.0.0.1:80
  - hostname: headlamp.unsafie.com
    service: http://127.0.0.1:80
  - hostname: ui.unsafie.com
    service: http://127.0.0.1:80
  - hostname: "*.unsafie.com"
    service: http://127.0.0.1:80
  - service: http_status:404
CFEOF
            /usr/local/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run >/tmp/cf_tunnel.log 2>&1 &
        else
            /usr/local/bin/cloudflared tunnel run --token "$CURRENT_TUNNEL_TOKEN" >/tmp/cf_tunnel.log 2>&1 &
        fi
        sleep 2
    fi
fi

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

cat <<SSHEOF | sudo tee /etc/ssh/sshd_config.d/free-vpc.conf >/dev/null
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
sudo chmod 600 "$AUTH_FILE" /root/.ssh/authorized_keys
sudo chown -R runner:runner /home/runner/.ssh
echo "runner ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/runner-nopasswd
sudo chmod 440 /etc/sudoers.d/runner-nopasswd
sudo systemctl restart ssh || sudo service ssh restart || true

if ! command -v containerd-shim-kata-v2 >/dev/null 2>&1; then
    (
        KATA_VER="3.10.0"
        KATA_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VER}/kata-static-${KATA_VER}-amd64.tar.xz"
        curl -fsSL "$KATA_URL" -o /tmp/kata.tar.xz 2>/dev/null && sudo tar -xJf /tmp/kata.tar.xz -C / 2>/dev/null && rm -f /tmp/kata.tar.xz && sudo ln -sf /opt/kata/bin/* /usr/local/bin/ || true
    ) &
fi

sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd
cat <<KATAEOF | sudo tee /var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl >/dev/null
{{ template "base" . }}

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-clh]
  runtime_type = "io.containerd.kata-clh.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-qemu]
  runtime_type = "io.containerd.kata-qemu.v2"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-clh]
  runtime_type = "io.containerd.kata-clh.v2"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-qemu]
  runtime_type = "io.containerd.kata-qemu.v2"
KATAEOF

sudo mkdir -p /etc/rancher/k3s
cat <<PSAEOF | sudo tee /etc/rancher/k3s/psa.yaml >/dev/null
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "restricted"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces:
        - kube-system
        - flux-system
        - envoy-gateway-system
        - spegel
        - headlamp
PSAEOF

sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 30080 2>/dev/null || true
sudo iptables -t nat -A OUTPUT -p tcp -o lo --dport 80 -j REDIRECT --to-ports 30080 2>/dev/null || true
sudo socat TCP-LISTEN:80,fork,reuseaddr TCP:127.0.0.1:30080 >/dev/null 2>&1 &

if [ -n "${HF_TOKEN:-}" ]; then
    mkdir -p ~/.config/rclone
    cat <<RCEOF > ~/.config/rclone/rclone.conf
[hf-raw]
type = s3
provider = Other
endpoint = https://s3.hf.co/${HF_NAMESPACE:-wprhvso}
access_key_id = ${HF_ACCESS_KEY:-$HF_TOKEN}
secret_access_key = ${HF_SECRET_KEY:-$HF_TOKEN}
region = us-east-1
force_path_style = true
list_version = 2
upload_cutoff = 2G
chunk_size = 2G

[hf-crypt]
type = crypt
remote = hf-raw:${HF_BUCKET:-cluster-backups}
filename_encryption = standard
directory_name_encryption = true
password = ${RCLONE_CRYPT_PASSWORD:-}
RCEOF
    rclone serve s3 hf-crypt: --addr 127.0.0.1:9000 --auth-key "admin,${S3_PASS}" --vfs-cache-mode minimal >/tmp/rclone.log 2>&1 &
    sleep 2
fi

cleanup() {
    if command -v kubectl >/dev/null 2>&1; then
        kubectl drain "free-vpc-${NODE_NUM}" --ignore-daemonsets --delete-emptydir-data --force --grace-period=15 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

COMMON_K3S_FLAGS="--node-name free-vpc-${NODE_NUM} --node-ip ${MY_IPV6} --flannel-iface ygg0 --cluster-cidr 10.42.0.0/16,fd00:42:1::/56 --service-cidr 10.43.0.0/16,fd00:42:2::/112 --token ${K3S_SECRET}"

if [ "$NODE_NUM" -le 3 ]; then
    ETCD_S3_FLAGS=""
    if [ -n "${HF_TOKEN:-}" ]; then
        ETCD_S3_FLAGS="--etcd-s3 --etcd-s3-endpoint 127.0.0.1:9000 --etcd-s3-bucket etcd-backups --etcd-s3-access-key admin --etcd-s3-secret-key ${S3_PASS} --etcd-s3-insecure --etcd-snapshot-schedule-cron 0 */1 * * *"
    fi

    PSA_ARG="--kube-apiserver-arg admission-control-config-file=/etc/rancher/k3s/psa.yaml"

    if [ "$NODE_NUM" = "1" ]; then
        sudo k3s server --cluster-init \
            ${COMMON_K3S_FLAGS} \
            --tls-san master-1 --tls-san master-2 --tls-san master-3 \
            --disable traefik --disable servicelb --disable local-storage --disable metrics-server \
            --kube-controller-manager-arg "node-monitor-grace-period=16s" \
            --kube-controller-manager-arg "pod-eviction-timeout=20s" \
            ${PSA_ARG} \
            ${ETCD_S3_FLAGS} >/tmp/k3s.log 2>&1 &
    else
        for i in $(seq 1 45); do
            if nc -z -w 2 master-1 6443 2>/dev/null; then
                break
            fi
            sleep 2
        done

        sudo k3s server --server "https://master-1:6443" \
            ${COMMON_K3S_FLAGS} \
            --tls-san master-1 --tls-san master-2 --tls-san master-3 \
            --disable traefik --disable servicelb --disable local-storage --disable metrics-server \
            --kube-controller-manager-arg "node-monitor-grace-period=16s" \
            --kube-controller-manager-arg "pod-eviction-timeout=20s" \
            ${PSA_ARG} \
            ${ETCD_S3_FLAGS} >/tmp/k3s.log 2>&1 &
    fi
else
    for i in $(seq 1 60); do
        if nc -z -w 2 master-1 6443 2>/dev/null || nc -z -w 2 master-2 6443 2>/dev/null || nc -z -w 2 master-3 6443 2>/dev/null; then
            break
        fi
        sleep 2
    done

    socat TCP-LISTEN:6443,fork,reuseaddr "TCP:master-1:6443" >/tmp/socat.log 2>&1 &

    sudo k3s agent --server "https://127.0.0.1:6443" \
        --node-name "free-vpc-${NODE_NUM}" \
        --node-ip "${MY_IPV6}" \
        --flannel-iface "ygg0" \
        --token "${K3S_SECRET}" >/tmp/k3s.log 2>&1 &
fi

HEADLAMP_TOKEN=""

if [ "$NODE_NUM" = "1" ]; then
    echo "Waiting for k3s cluster to initialize..."
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    for i in $(seq 1 60); do
        if sudo kubectl get nodes 2>/dev/null | grep -q "Ready"; then
            break
        fi
        sleep 2
    done

    echo "Installing Flux v2 CLI and Helm CLI..."
    if ! command -v flux >/dev/null 2>&1; then
        curl -s https://fluxcd.io/install.sh | sudo bash 2>/dev/null || true
    fi

    if ! command -v helm >/dev/null 2>&1; then
        curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash 2>/dev/null || true
    fi

    if ! command -v sops >/dev/null 2>&1; then
        sudo curl -fsSL https://github.com/getsops/sops/releases/download/v3.9.1/sops-v3.9.1.linux.amd64 -o /usr/local/bin/sops 2>/dev/null || true
        sudo chmod +x /usr/local/bin/sops 2>/dev/null || true
    fi

    if command -v flux >/dev/null 2>&1; then
        echo "Bootstrapping Flux v2 controllers..."
        sudo flux install --components=source-controller,kustomize-controller,helm-controller,notification-controller || true

        sudo kubectl create secret generic sops-age \
            --namespace=flux-system \
            --from-literal=age.agekey="${SOPS_AGE_KEY:-AGE-SECRET-KEY-106S3FMM5Q6HANQXGVJRJY9NUC943X2E6GDVJW32JPU022XWEKTJQ96XKGY}" \
            --dry-run=client -o yaml | sudo kubectl apply -f - || true

        sudo kubectl create secret generic cluster-user-auth \
            --namespace=flux-system \
            --from-literal=username="admin" \
            --from-literal=password='$2a$10$ceOhGVam1gdh2ctMHentueYObHqvRySuweffs7xKXfN2.p4joA1WK' \
            --dry-run=client -o yaml | sudo kubectl apply -f - || true

        sudo kubectl create namespace headlamp --dry-run=client -o yaml | sudo kubectl apply -f - || true
        sudo kubectl create serviceaccount headlamp-admin --namespace=headlamp --dry-run=client -o yaml | sudo kubectl apply -f - || true
        sudo kubectl create clusterrolebinding headlamp-admin --clusterrole=cluster-admin --serviceaccount=headlamp:headlamp-admin --dry-run=client -o yaml | sudo kubectl apply -f - || true

        cat <<TOKEOF | sudo kubectl apply -f - || true
apiVersion: v1
kind: Secret
metadata:
  name: headlamp-admin-token
  namespace: headlamp
  annotations:
    kubernetes.io/service-account.name: headlamp-admin
type: kubernetes.io/service-account-token
TOKEOF

        sudo flux create source git free-vpc \
            --url="https://github.com/${GITHUB_REPOSITORY:-wprhvso/free-vpc}.git" \
            --branch="${GITHUB_REF_NAME:-main}" \
            --interval=1m \
            --export | sudo kubectl apply -f - || true

        sudo flux create kustomization cluster-sync \
            --source=free-vpc \
            --path="./gitops/clusters/free-vpc" \
            --prune=true \
            --interval=1m \
            --decryption-provider=sops \
            --decryption-secret=sops-age \
            --export | sudo kubectl apply -f - || true

        sleep 5
        HEADLAMP_TOKEN=$(sudo kubectl get secret headlamp-admin-token -n headlamp -o jsonpath="{.data.token}" 2>/dev/null | base64 -d || true)
    fi

    bash "${SCRIPT_DIR}/cluster_orchestrator.sh" "$NODE_NUM" "${GITHUB_REPOSITORY:-wprhvso/free-vpc}" "${GH_PAT:-}" "$TOTAL_SLOTS" "${GITHUB_REF_NAME:-main}" >/tmp/orchestrator.log 2>&1 &
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    ROLE="Worker"
    if [ "$NODE_NUM" -le 3 ]; then
        ROLE="Master (Control Plane)"
    fi
    printf "## Free VPC Kubernetes Node Online\n- Role: \`%s\`\n- Slot: \`#%s\`\n- Yggdrasil IPv6: \`%s\`\n- Peers: \`mesh1..3.unsafie.com\`\n" "$ROLE" "$NODE_NUM" "$MY_IPV6" >>"$GITHUB_STEP_SUMMARY"

    if [ "$NODE_NUM" = "1" ]; then
        printf "\n### Cluster Management & UIs\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Weave GitOps (Flux v2 UI)**: [https://gitops.unsafie.com](https://gitops.unsafie.com)\n  - Username: \`admin\`\n  - Password: \`unsafie2026!\`\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Headlamp (Kubernetes Web UI)**: [https://headlamp.unsafie.com](https://headlamp.unsafie.com) | [https://ui.unsafie.com](https://ui.unsafie.com)\n" >>"$GITHUB_STEP_SUMMARY"
        if [ -n "$HEADLAMP_TOKEN" ]; then
            printf "  - ServiceAccount Bearer Token: \`%s\`\n" "$HEADLAMP_TOKEN" >>"$GITHUB_STEP_SUMMARY"
        fi
        printf -- "- **Envoy Gateway**: Gateway API v1 active on NodePort 30080 / Port 80\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Spegel**: P2P Registry Cache active on containerd\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Kata Containers**: RuntimeClasses \`kata\`, \`kata-clh\`, \`kata-qemu\`\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Pod Security Admission**: Restricted profile enforced cluster-wide\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **SOPS**: Age key encryption configured\n" >>"$GITHUB_STEP_SUMMARY"
    fi
fi

START_TIME=$SECONDS
while [ $((SECONDS - START_TIME)) -lt 21120 ]; do
    if [ -f "/tmp/stop-node" ]; then
        break
    fi
    sleep 10
done
