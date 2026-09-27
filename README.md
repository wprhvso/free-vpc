# Free VPC: Serverless Cloud Runners over Cloudflare Mesh

Free VPC provisions on-demand, persistent virtual private servers using GitHub Actions runners, interconnected through **Cloudflare Mesh (MASQUE protocol)**.

No central ingress server, no open firewall ports, no GitHub schedule/matrix hacks. You connect directly from your personal workstation via the official Cloudflare One Client (warp-cli / GUI) to the runner private Mesh IP (100.96.x.x).

---

## Architecture

- **Private Network:** Cloudflare Zero Trust Mesh with MASQUE (HTTP/3 + QUIC over UDP 443, TLS 1.3, Post-Quantum keys).
- **Runners:** Ubuntu Latest GitHub Actions runners registered dynamically as Cloudflare Mesh Nodes via Cloudflare API.
- **SSH Host Keys:** Fixed ED25519 & RSA host keys configured across all runners so SSH clients never raise host key change warnings.
- **Access Control:** Automatic authentication using GitHub public keys (https://github.com/wprhvso.keys) and passwordless sudo for user runner.
- **Orchestration:** Cloudflare Worker on a Cron trigger (*/15 * * * *) that queries the GitHub Actions API and dispatches replacement runners to maintain node capacity.
- **Versioning:** Managed via Greewil/version-update-helper (.vuh).

---

## Quick Start

### 1. Prerequisites

- just task runner
- terraform or opentofu
- gh CLI (authenticated)
- Cloudflare One Client running on your local PC connected to your Zero Trust team (shy-resonance-71c0) with MASQUE protocol.

### 2. Deployment

```bash
just bootstrap
```

This runs:
1. `just tf-init` & `just tf-apply`: provisions the Cloudflare Zero Trust Device Profile with MASQUE protocol and routes `100.96.0.0/12`.
2. `just secrets-sync`: synchronizes all required API credentials and SSH host keys to GitHub Secrets.
3. `just spawn`: dispatches the initial runner node.

---

## CLI Management (just)

| Command | Description |
| :--- | :--- |
| `just spawn` | Launch a new Free VPC runner node on demand |
| `just nodes` | List running / recent workflow jobs |
| `just status` | Query Cloudflare API for active Mesh connectors |
| `just ssh <MESH_IP>` | Connect to a runner via SSH (`ssh runner@100.96.x.x`) |
| `just stop <RUN_ID>` | Gracefully terminate a specific runner node |
| `just worker-deploy` | Deploy the Cloudflare Worker orchestrator |

---

## Connecting via SSH

Once a runner starts:
1. It registers with Cloudflare Mesh and receives an IP in the `100.96.0.0/12` range.
2. The IP is output in the GitHub Actions step summary and job logs.
3. With Cloudflare WARP running on your computer:

```bash
ssh runner@100.96.x.y
```

User `runner` has full passwordless `sudo` privileges.

### Fixed Host Keys

To pre-populate `~/.ssh/known_hosts` so SSH never prompts on first connection, refer to `known_hosts.sample`.

---

## Versioning

Versioning is validated via `Greewil/version-update-helper` against `.vuh` and `VERSION`.
