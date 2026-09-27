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
      -target=cloudflare_d1_database.free_vpc_db \
      -target=cloudflare_worker_script.orchestrator \
      -target=cloudflare_worker_cron_trigger.orchestrator_cron

secrets-sync:
    @if [ -z "${CF_API_TOKEN:-}" ]; then echo "CF_API_TOKEN is required" && exit 1; fi
    @if [ -z "${CF_ACCOUNT_ID:-}" ]; then echo "CF_ACCOUNT_ID is required" && exit 1; fi
    @echo -n "${CF_ACCOUNT_ID}" | gh secret set CF_ACCOUNT_ID --repo wprhvso/free-vpc
    @echo -n "${CF_API_TOKEN}" | gh secret set CF_API_TOKEN --repo wprhvso/free-vpc
    @echo -n "${CF_TEAM_NAME:-shy-resonance-71c0}" | gh secret set CF_TEAM_NAME --repo wprhvso/free-vpc

d1-migrate:
    @curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID:-39f6858f9b5865652ac69c506ec4736c}/d1/database/c4887003-15c4-4e85-8e83-bd33e7aa278b/query" \
      -H "Authorization: Bearer ${CF_API_TOKEN:-cfat_hzrn3XyC7ntmtpMyD9znlPmhBMKNbU0QBT1DiYaW57abbf4d}" \
      -H "Content-Type: application/json" \
      -d "$$(jq -n --arg sql "$$(cat terraform/schema.sql)" '{"sql": $$sql}')" | jq .

d1-tables:
    @curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID:-39f6858f9b5865652ac69c506ec4736c}/d1/database/c4887003-15c4-4e85-8e83-bd33e7aa278b/query" \
      -H "Authorization: Bearer ${CF_API_TOKEN:-cfat_hzrn3XyC7ntmtpMyD9znlPmhBMKNbU0QBT1DiYaW57abbf4d}" \
      -H "Content-Type: application/json" \
      -d '{"sql": "SELECT name FROM sqlite_master WHERE type=\"table\" ORDER BY name;"}' | jq '.result[0].results'

vm-create name slot="1" vcpus="1" ram="1024" image="debian-12-minimal":
    @curl -sS -X POST "https://free-vpc-orchestrator.wprhvso.workers.dev/v1/vms" \
      -H "Content-Type: application/json" \
      -d '{"name":"{{name}}","slot_id":{{slot}},"vcpus":{{vcpus}},"memory_mb":{{ram}},"image":"{{image}}"}' | jq .

vm-list:
    @curl -sS "https://free-vpc-orchestrator.wprhvso.workers.dev/v1/vms" | jq .

vm-delete name_or_id:
    @curl -sS -X DELETE "https://free-vpc-orchestrator.wprhvso.workers.dev/v1/vms/{{name_or_id}}" | jq .

image-add name repo path:
    @curl -sS -X POST "https://free-vpc-orchestrator.wprhvso.workers.dev/v1/images" \
      -H "Content-Type: application/json" \
      -d '{"name":"{{name}}","hf_repo":"{{repo}}","hf_path":"{{path}}"}' | jq .

image-list:
    @curl -sS "https://free-vpc-orchestrator.wprhvso.workers.dev/v1/images" | jq .

secret-set key value:
    @curl -sS -X POST "https://free-vpc-orchestrator.wprhvso.workers.dev/v1/admin/secrets" \
      -H "Content-Type: application/json" \
      -d '{"key_name":"{{key}}","value":"{{value}}"}' | jq .

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
      ssh -o StrictHostKeyChecking=no runner@10.200.0.{{target}}; \
    else \
      ssh -o StrictHostKeyChecking=no runner@{{target}}; \
    fi
