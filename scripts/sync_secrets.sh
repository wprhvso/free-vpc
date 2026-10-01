#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"

cd "$TF_DIR"

T1=$(terraform output -raw cf_tunnel_token_1 2>/dev/null || true)
T2=$(terraform output -raw cf_tunnel_token_2 2>/dev/null || true)
T3=$(terraform output -raw cf_tunnel_token_3 2>/dev/null || true)
YGG=$(terraform output -raw ygg_password 2>/dev/null || true)
K3S=$(terraform output -raw k3s_token 2>/dev/null || true)
CRYPT=$(terraform output -raw rclone_crypt_password 2>/dev/null || true)
S3KEY=$(terraform output -raw s3_secret_key 2>/dev/null || true)

REPO="wprhvso/free-vpc"

[ -n "$T1" ] && echo -n "$T1" | gh secret set CF_TUNNEL_TOKEN_1 --repo "$REPO"
[ -n "$T2" ] && echo -n "$T2" | gh secret set CF_TUNNEL_TOKEN_2 --repo "$REPO"
[ -n "$T3" ] && echo -n "$T3" | gh secret set CF_TUNNEL_TOKEN_3 --repo "$REPO"
[ -n "$YGG" ] && echo -n "$YGG" | gh secret set YGG_PASSWORD --repo "$REPO"
[ -n "$K3S" ] && echo -n "$K3S" | gh secret set K3S_TOKEN --repo "$REPO"
[ -n "$CRYPT" ] && echo -n "$CRYPT" | gh secret set RCLONE_CRYPT_PASSWORD --repo "$REPO"
[ -n "$S3KEY" ] && echo -n "$S3KEY" | gh secret set S3_SECRET_KEY --repo "$REPO"

echo "Secrets synchronized successfully."
