# Free VPC: 20-Node Autonomous K3s Cluster over Yggdrasil & Cloudflare

Free VPC turns ephemeral GitHub Actions runners into a high-availability **20-node Kubernetes (K3s) cluster** interconnected via an encrypted **Yggdrasil IPv6 mesh** over **Cloudflare Named Tunnels (WSS)**, with client-side encrypted backup streaming to **Hugging Face S3**.

---

## Cloud-Native Platform Stack

- **Envoy Gateway:** Kubernetes Gateway API v1 implementation serving all ingress traffic.
- **Flux v2 & Helm:** Continuous GitOps reconciliation managing all cluster infrastructure via Helm releases and OCI repositories.
- **Spegel:** Stateless cluster-local P2P OCI registry cache accelerating container image distribution across nodes.
- **Kata Containers:** Hardware-isolated microVM container runtime (kata, kata-clh, kata-qemu) leveraging /dev/kvm.
- **PSA Restricted:** Cluster-wide Pod Security Admission enforcing the restricted profile on all tenant namespaces.
- **SOPS + Age:** In-tree GitOps secret encryption with Mozilla SOPS and Age private key decryption.

---

## Web Interfaces & Authentication

All dashboards are securely routed through Cloudflare Named Tunnels with authentication:

- **Weave GitOps:** https://gitops.unsafie.com
  - Access: Password authenticated
  - Username: admin
  - Password: Wv9#kL2$xQ8!tZ5*GitOps2026

- **Headlamp:** https://headlamp.unsafie.com and https://ui.unsafie.com
  - Access: HTTP Basic Authentication protected gateway + Kubernetes ServiceAccount Bearer token
  - Basic Auth Username: admin
  - Basic Auth Password: Hl8*pQ3$mK9!wZ2#Headlamp2026

- **Yggdrasil Mesh Endpoints:**
  - https://mesh1.unsafie.com
  - https://mesh2.unsafie.com
  - https://mesh3.unsafie.com

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

---

## CLI Management (just)

| Command | Description |
| :--- | :--- |
| just bootstrap | Full setup: Terraform apply, sync secrets, and spawn all 20 nodes |
| just spawn-all | Concurrently launch all 20 cluster nodes in parallel |
| just spawn <SLOT> | Launch or replace a specific cluster slot (1-20) |
| just nodes | List running / recent workflow jobs |
| just stop <RUN_ID> | Gracefully terminate a specific runner node |
