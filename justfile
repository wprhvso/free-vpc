set shell := ["bash", "-uc"]

default:
    @just --list

spawn node_id="1":
    gh workflow run node.yml --repo wprhvso/free-vpc --ref init-free-vpc -f node_id={{node_id}}

spawn-all:
    @for i in $(seq 1 20); do \
      gh workflow run node.yml --repo wprhvso/free-vpc --ref init-free-vpc -f node_id=$$i; \
      sleep 0.5; \
    done

nodes:
    gh run list --repo wprhvso/free-vpc --workflow node.yml --limit 20

stop run_id:
    gh run cancel {{run_id}} --repo wprhvso/free-vpc

status:
    @curl -sS -H "Authorization: Bearer ${CF_API_TOKEN:-cfat_hzrn3XyC7ntmtpMyD9znlPmhBMKNbU0QBT1DiYaW57abbf4d}" \
      "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID:-39f6858f9b5865652ac69c506ec4736c}/warp_connector" | jq '.result[] | {id, name, status}'
