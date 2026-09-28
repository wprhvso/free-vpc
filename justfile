set shell := ["bash", "-uc"]

API_URL := "https://vm.unsafie.com"
CF_ACCESS_CLIENT_ID := "5a06f20e534be12f4e259e932af57b57.access"
CF_ACCESS_CLIENT_SECRET := "cfast_clJJ6Rx6HA0bdn2eXV31EO7UNnApjsLaOOdkWCMe71e2052a"

default:
    @just --list

bootstrap: tf-init tf-apply secrets-sync spawn

tf-init:
    cd terraform && terraform init

tf-plan:
    cd terraform && terraform plan

tf-apply:
    cd terraform && terraform apply -auto-approve \
      -target=cloudflare_zero_trust_access_policy.device_enrollment \
      -target=cloudflare_zero_trust_access_application.warp_enrollment \
      -target=cloudflare_d1_database.free_vpc_db \
      -target=cloudflare_worker_script.orchestrator \
      -target=cloudflare_worker_cron_trigger.orchestrator_cron \
      -target=cloudflare_workers_domain.vm_domain \
      -target=cloudflare_zero_trust_access_service_token.orchestrator_token \
      -target=cloudflare_zero_trust_access_policy.service_auth \
      -target=cloudflare_zero_trust_access_policy.admin_ui \
      -target=cloudflare_zero_trust_access_application.vm_app

secrets-sync:
    @if [ -z "${CF_API_TOKEN:-}" ]; then echo "CF_API_TOKEN is required" && exit 1; fi
    @if [ -z "${CF_ACCOUNT_ID:-}" ]; then echo "CF_ACCOUNT_ID is required" && exit 1; fi
    @echo -n "${CF_ACCOUNT_ID}" | gh secret set CF_ACCOUNT_ID --repo wprhvso/free-vpc
    @echo -n "${CF_API_TOKEN}" | gh secret set CF_API_TOKEN --repo wprhvso/free-vpc
    @echo -n "${CF_TEAM_NAME:-shy-resonance-71c0}" | gh secret set CF_TEAM_NAME --repo wprhvso/free-vpc
    @echo -n "{{CF_ACCESS_CLIENT_ID}}" | gh secret set CF_ACCESS_CLIENT_ID --repo wprhvso/free-vpc
    @echo -n "{{CF_ACCESS_CLIENT_SECRET}}" | gh secret set CF_ACCESS_CLIENT_SECRET --repo wprhvso/free-vpc

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

vm-create:
    @curl -sS -X POST "{{API_URL}}/api/vm" \
      -H "CF-Access-Client-Id: {{CF_ACCESS_CLIENT_ID}}" \
      -H "CF-Access-Client-Secret: {{CF_ACCESS_CLIENT_SECRET}}" \
      -H "Content-Type: application/json" | jq .

vm-list:
    @curl -sS "{{API_URL}}/api/vm" \
      -H "CF-Access-Client-Id: {{CF_ACCESS_CLIENT_ID}}" \
      -H "CF-Access-Client-Secret: {{CF_ACCESS_CLIENT_SECRET}}" | jq .

vm-delete id:
    @curl -sS -X DELETE "{{API_URL}}/api/vm/{{id}}" \
      -H "CF-Access-Client-Id: {{CF_ACCESS_CLIENT_ID}}" \
      -H "CF-Access-Client-Secret: {{CF_ACCESS_CLIENT_SECRET}}" | jq .

keys-get:
    @curl -sS "{{API_URL}}/api/ssh-keys" \
      -H "CF-Access-Client-Id: {{CF_ACCESS_CLIENT_ID}}" \
      -H "CF-Access-Client-Secret: {{CF_ACCESS_CLIENT_SECRET}}" | jq .

keys-set keys_file:
    @curl -sS -X POST "{{API_URL}}/api/ssh-keys" \
      -H "CF-Access-Client-Id: {{CF_ACCESS_CLIENT_ID}}" \
      -H "CF-Access-Client-Secret: {{CF_ACCESS_CLIENT_SECRET}}" \
      -H "Content-Type: application/json" \
      -d "$$(jq -n --arg keys "$$(cat {{keys_file}})" '{"keys": ($$keys | split("\n"))}')" | jq .

spawn node_id="1":
    gh workflow run node.yml --repo wprhvso/free-vpc --ref init-free-vpc -f node_id={{node_id}}

nodes:
    gh run list --repo wprhvso/free-vpc --workflow node.yml --limit 20

stop run_id:
    gh run cancel {{run_id}} --repo wprhvso/free-vpc

ssh ip:
    ssh -o StrictHostKeyChecking=no runner@{{ip}}

vm-acquire name="" slot="" key="":
    @curl -sS -X POST "{{API_URL}}/api/vm" \
      -H "CF-Access-Client-Id: {{CF_ACCESS_CLIENT_ID}}" \
      -H "CF-Access-Client-Secret: {{CF_ACCESS_CLIENT_SECRET}}" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"{{name}}\",\"slot_id\":\"{{slot}}\",\"ssh_key\":\"{{key}}\"}" | jq .
