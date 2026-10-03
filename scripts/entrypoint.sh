#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RAW_ID="${NODE_ID:-1}"
NODE_NUM=$(echo "$RAW_ID" | tr -cd "0-9")
NODE_NUM="${NODE_NUM:-1}"

if ! command -v ansible-playbook >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y -qq ansible-core 2>/dev/null || true
fi

if ! python3 -c "import ansible_mitogen" >/dev/null 2>&1; then
    sudo pip install --break-system-packages mitogen 2>/dev/null || sudo pip install mitogen 2>/dev/null || pip install mitogen 2>/dev/null || true
fi

MITOGEN_STRATEGY=$(python3 -c "import os, ansible_mitogen; print(os.path.join(os.path.dirname(ansible_mitogen.__file__), 'plugins', 'strategy'))" 2>/dev/null || true)
if [ -n "$MITOGEN_STRATEGY" ] && [ -d "$MITOGEN_STRATEGY" ]; then
    export ANSIBLE_STRATEGY_PLUGINS="$MITOGEN_STRATEGY"
    export ANSIBLE_STRATEGY="mitogen_linear"
fi

ANSIBLE_BIN=$(command -v ansible-playbook || echo "/usr/bin/ansible-playbook")

export ANSIBLE_CONFIG="${REPO_DIR}/ansible/ansible.cfg"
cd "$REPO_DIR/ansible"

sudo -E "$ANSIBLE_BIN" -i "localhost," -c local playbooks/node.yml \
  -e "node_id=${NODE_NUM}" \
  -e "total_slots=${TOTAL_SLOTS:-20}" \
  -e "cluster_salt=${CLUSTER_SALT:-unsafie-cluster-v1}" \
  -e "ygg_password=${YGG_PASSWORD}" \
  -e "k3s_token=${K3S_TOKEN}" \
  -e "s3_secret_key=${S3_SECRET_KEY:-}" \
  -e "hf_token=${HF_TOKEN:-}" \
  -e "hf_namespace=${HF_NAMESPACE:-wprhvso}" \
  -e "hf_bucket=${HF_BUCKET:-cluster-backups}" \
  -e "rclone_crypt_password=${RCLONE_CRYPT_PASSWORD:-}" \
  -e "sops_age_key=${SOPS_AGE_KEY:-AGE-SECRET-KEY-106S3FMM5Q6HANQXGVJRJY9NUC943X2E6GDVJW32JPU022XWEKTJQ96XKGY}" \
  -e "gh_pat=${GH_PAT:-}" \
  -e "github_repository=${GITHUB_REPOSITORY:-wprhvso/free-vpc}" \
  -e "github_ref_name=${GITHUB_REF_NAME:-main}" \
  -e "ssh_host_ed25519_key=${SSH_HOST_ED25519_KEY:-}" \
  -e "ssh_host_rsa_key=${SSH_HOST_RSA_KEY:-}" \
  -e "ssh_authorized_keys=${SSH_AUTHORIZED_KEYS:-}" \
  -e "cf_tunnel_token_1=${CF_TUNNEL_TOKEN_1:-}" \
  -e "cf_tunnel_token_2=${CF_TUNNEL_TOKEN_2:-}" \
  -e "cf_tunnel_token_3=${CF_TUNNEL_TOKEN_3:-}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    ROLE="Worker"
    if [ "$NODE_NUM" -le 3 ]; then
        ROLE="Master (Control Plane)"
    fi
    printf "## Free VPC Kubernetes Node Online\n- Role: \`%s\`\n- Slot: \`#%s\`\n- Provisioner: Ansible (Mitogen accelerated)\n" "$ROLE" "$NODE_NUM" >>"$GITHUB_STEP_SUMMARY"
    if [ "$NODE_NUM" = "1" ]; then
        printf "\n### Cluster Management & UIs\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Weave GitOps**: [https://gitops.unsafie.com](https://gitops.unsafie.com)\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Headlamp**: [https://headlamp.unsafie.com](https://headlamp.unsafie.com) | [https://ui.unsafie.com](https://ui.unsafie.com)\n" >>"$GITHUB_STEP_SUMMARY"
        printf -- "- **Mesh Endpoints**: [https://mesh1.unsafie.com](https://mesh1.unsafie.com)\n" >>"$GITHUB_STEP_SUMMARY"
    fi
fi

START_TIME=$SECONDS
while [ $((SECONDS - START_TIME)) -lt 21120 ]; do
    if [ -f "/tmp/stop-node" ]; then
        break
    fi
    sleep 10
done
