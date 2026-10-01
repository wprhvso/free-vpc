# Free VPC: 20-Node Autonomous K3s Cluster over Yggdrasil & Cloudflare

Free VPC turns ephemeral GitHub Actions runners into a high-availability **20-node Kubernetes (K3s) cluster** interconnected via an encrypted **Yggdrasil IPv6 mesh** over **Cloudflare Named Tunnels (WSS)**, with client-side encrypted backup streaming to **Hugging Face S3**.

The entire 20-node cluster boots in parallel in under 2 minutes.

---

## Architecture

- **Control Plane:** 3 Master nodes (Slots #1, #2, #3) running embedded etcd with continuous S3 snapshots.
- **Workers:** 17 Worker nodes (Slots #4 through #20) providing 68 vCPU and 272 GB RAM for user workloads.
- **Networking:** Yggdrasil end-to-end encrypted IPv6 mesh operating over WebSocket Secure (WSS) through Cloudflare Named Tunnels (mesh1..3).
- **Deterministic Addressing:** Every slot derives a deterministic Ed25519 key, providing permanent static IPv6 addresses and /etc/hosts mappings across restarts.
- **Encrypted S3 Storage:** Transparent client-side encryption via rclone crypt proxying to Hugging Face Public Buckets (bypassing the 100GB private quota).
- **Auto-Healing Orchestrator:** Active leader continuously watches cluster health and automatically dispatches replacement runners when nodes expire or fail.

---

## Quick Start

### 1. Prerequisites

- just task runner
- terraform or opentofu
- gh CLI (authenticated)

### 2. Deployment

```bash
just bootstrap
```

This runs:
1. `just tf-init` & `just tf-apply`: provisions 3 Cloudflare Named Tunnels and DNS records (`mesh1..3`), generating all cryptographic secrets.
2. `just secrets-sync`: synchronizes tunnel tokens and cluster passwords into GitHub Actions Secrets.
3. `just spawn-all`: concurrently dispatches all 20 runner slots in parallel.

---

## CLI Management (just)

| Command | Description |
| :--- | :--- |
| `just bootstrap` | Full setup: Terraform apply, sync secrets, and spawn all 20 nodes |
| `just spawn-all` | Concurrently launch all 20 cluster nodes in parallel |
| `just spawn <SLOT>` | Launch or replace a specific cluster slot (1-20) |
| `just nodes` | List running / recent workflow jobs |
| `just stop <RUN_ID>` | Gracefully terminate a specific runner node |
