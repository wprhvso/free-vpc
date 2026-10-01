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
    @cd terraform && \
      T1=$$(terraform output -raw cf_tunnel_token_1 2>/dev/null || true) && \
      T2=$$(terraform output -raw cf_tunnel_token_2 2>/dev/null || true) && \
      T3=$$(terraform output -raw cf_tunnel_token_3 2>/dev/null || true) && \
      YGG=$$(terraform output -raw ygg_password 2>/dev/null || true) && \
      K3S=$$(terraform output -raw k3s_token 2>/dev/null || true) && \
      CRYPT=$$(terraform output -raw rclone_crypt_password 2>/dev/null || true) && \
      S3KEY=$$(terraform output -raw s3_secret_key 2>/dev/null || true) && \
      [ -n "$$T1" ] && echo -n "$$T1" | gh secret set CF_TUNNEL_TOKEN_1 --repo wprhvso/free-vpc || true && \
      [ -n "$$T2" ] && echo -n "$$T2" | gh secret set CF_TUNNEL_TOKEN_2 --repo wprhvso/free-vpc || true && \
      [ -n "$$T3" ] && echo -n "$$T3" | gh secret set CF_TUNNEL_TOKEN_3 --repo wprhvso/free-vpc || true && \
      [ -n "$$YGG" ] && echo -n "$$YGG" | gh secret set YGG_PASSWORD --repo wprhvso/free-vpc || true && \
      [ -n "$$K3S" ] && echo -n "$$K3S" | gh secret set K3S_TOKEN --repo wprhvso/free-vpc || true && \
      [ -n "$$CRYPT" ] && echo -n "$$CRYPT" | gh secret set RCLONE_CRYPT_PASSWORD --repo wprhvso/free-vpc || true && \
      [ -n "$$S3KEY" ] && echo -n "$$S3KEY" | gh secret set S3_SECRET_KEY --repo wprhvso/free-vpc || true
    @echo "Secrets synchronized successfully."

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
