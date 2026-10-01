set shell := ["bash", "-uc"]

default:
    @just --list

bootstrap: tf-init tf-apply secrets-sync spawn-all

tf-init:
    cd terraform && terraform init

tf-plan:
    cd terraform && terraform plan

tf-apply:
    cd terraform && terraform apply -auto-approve

secrets-sync:
    @echo "Syncing generated secrets to GitHub Actions..."
    @bash scripts/sync_secrets.sh

spawn node_id="1":
    gh workflow run node.yml --repo wprhvso/free-vpc -f node_id={{node_id}}

spawn-all:
    @echo "Spawning full 20-node Kubernetes cluster in parallel..."
    @for i in $(seq 1 20); do \
      gh workflow run node.yml --repo wprhvso/free-vpc -f node_id=$$i; \
      sleep 0.2; \
    done
    @echo "All 20 nodes dispatched. Cluster will be ready in ~1-2 minutes."

nodes:
    gh run list --repo wprhvso/free-vpc --workflow node.yml --limit 20

stop run_id:
    gh run cancel {{run_id}} --repo wprhvso/free-vpc
