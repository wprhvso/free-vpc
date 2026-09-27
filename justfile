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
      -target=cloudflare_split_tunnel.default_include \
      -target=cloudflare_teams_rule.allow_mesh_traffic \
      -target=cloudflare_worker_script.orchestrator \
      -target=cloudflare_worker_cron_trigger.orchestrator_cron

secrets-sync:
    @if [ -z "${CF_API_TOKEN:-}" ]; then echo "CF_API_TOKEN is required" && exit 1; fi
    @if [ -z "${CF_ACCOUNT_ID:-}" ]; then echo "CF_ACCOUNT_ID is required" && exit 1; fi
    @echo -n "${CF_ACCOUNT_ID}" | gh secret set CF_ACCOUNT_ID --repo wprhvso/free-vpc
    @echo -n "${CF_API_TOKEN}" | gh secret set CF_API_TOKEN --repo wprhvso/free-vpc
    @echo -n "${CF_TEAM_NAME:-shy-resonance-71c0}" | gh secret set CF_TEAM_NAME --repo wprhvso/free-vpc

spawn node_id="1":
    gh workflow run node.yml --repo wprhvso/free-vpc --ref init-free-vpc -f node_id={{node_id}}

spawn-all:
    curl -sS -X POST "https://free-vpc-orchestrator.wprhvso.workers.dev/spawn" | jq .

worker-status:
    curl -sS "https://free-vpc-orchestrator.wprhvso.workers.dev/status" | jq .

nodes:
    gh run list --repo wprhvso/free-vpc --workflow node.yml --limit 20

status:
    @echo "=== Active WARP Connectors ==="
    @curl -sS -H "Authorization: Bearer ${CF_API_TOKEN:-cfat_hzrn3XyC7ntmtpMyD9znlPmhBMKNbU0QBT1DiYaW57abbf4d}" \
      "https://api.cloudflare.com/client/v4/accounts/39f6858f9b5865652ac69c506ec4736c/warp_connector" | jq '.result[] | {id, name, status}'
    @echo "=== Private CIDR Routes ==="
    @curl -sS -H "Authorization: Bearer ${CF_API_TOKEN:-cfat_hzrn3XyC7ntmtpMyD9znlPmhBMKNbU0QBT1DiYaW57abbf4d}" \
      "https://api.cloudflare.com/client/v4/accounts/39f6858f9b5865652ac69c506ec4736c/teamnet/routes" | jq '.result[] | {network, comment, tunnel_id}'

stop run_id:
    gh run cancel {{run_id}} --repo wprhvso/free-vpc

ssh target="1":
    @if [[ "{{target}}" =~ ^[0-9]+$ ]]; then \
      ssh -o StrictHostKeyChecking=no runner@10.0.1.{{target}}; \
    else \
      ssh -o StrictHostKeyChecking=no runner@{{target}}; \
    fi
