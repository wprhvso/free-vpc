set shell := ["bash", "-uc"]

default:
    @just --list

bootstrap: tf-init tf-apply secrets-sync spawn

tf-init:
    cd terraform && terraform init

tf-plan:
    cd terraform && terraform plan

tf-apply:
    cd terraform && terraform apply -auto-approve \
      -target=cloudflare_device_settings_policy.free_vpc_mesh \
      -target=cloudflare_split_tunnel.mesh_include \
      -target=cloudflare_zero_trust_access_policy.device_enrollment \
      -target=cloudflare_zero_trust_access_application.warp_enrollment \
      -target=cloudflare_split_tunnel.default_include

secrets-sync:
    @if [ -z "${CF_API_TOKEN:-}" ]; then echo "CF_API_TOKEN is required" && exit 1; fi
    @if [ -z "${CF_ACCOUNT_ID:-}" ]; then echo "CF_ACCOUNT_ID is required" && exit 1; fi
    @echo -n "${CF_ACCOUNT_ID}" | gh secret set CF_ACCOUNT_ID --repo wprhvso/free-vpc
    @echo -n "${CF_API_TOKEN}" | gh secret set CF_API_TOKEN --repo wprhvso/free-vpc
    @echo -n "${CF_TEAM_NAME:-shy-resonance-71c0}" | gh secret set CF_TEAM_NAME --repo wprhvso/free-vpc

spawn:
    gh workflow run node.yml --repo wprhvso/free-vpc --ref init-free-vpc

nodes:
    @echo "=== Active Mesh IP ==="
    @gh variable get NODE_IP --repo wprhvso/free-vpc || echo "No active node"
    @echo "=== Workflow Runs ==="
    @gh run list --repo wprhvso/free-vpc --workflow node.yml --limit 5

status:
    @curl -sS -H "Authorization: Bearer ${CF_API_TOKEN:-cfat_hzrn3XyC7ntmtpMyD9znlPmhBMKNbU0QBT1DiYaW57abbf4d}" \
      "https://api.cloudflare.com/client/v4/accounts/39f6858f9b5865652ac69c506ec4736c/warp_connector" | jq '.result[] | {id, name, status, created_on}'

stop run_id:
    gh run cancel {{run_id}} --repo wprhvso/free-vpc

ssh:
    @IP=$$(gh variable get NODE_IP --repo wprhvso/free-vpc); \
    echo "Connecting to $$IP..."; \
    ssh -o StrictHostKeyChecking=no runner@$$IP

worker-deploy:
    cd worker && npx wrangler deploy
