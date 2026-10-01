#!/usr/bin/env bash
set -euo pipefail

echo "=== Cloudflare Health Check ==="
curl -fsSL https://mesh1.unsafie.com || true
curl -fsSL https://gitops.unsafie.com || true
curl -fsSL https://headlamp.unsafie.com || true
