#!/usr/bin/env bash
set -x

echo "Testing token verification..."
curl -sS -H "Authorization: Bearer ${CF_API_TOKEN}" "https://api.cloudflare.com/client/v4/user/tokens/verify" | jq .

echo "Testing accounts list..."
curl -sS -H "Authorization: Bearer ${CF_API_TOKEN}" "https://api.cloudflare.com/client/v4/accounts" | jq .

echo "Testing zones list..."
curl -sS -H "Authorization: Bearer ${CF_API_TOKEN}" "https://api.cloudflare.com/client/v4/zones" | jq .

echo "Testing tunnel list..."
curl -sS -H "Authorization: Bearer ${CF_API_TOKEN}" "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" | jq .

echo "Testing Global API Key with X-Auth-Key..."
curl -sS -H "X-Auth-Email: wprhvso@gmail.com" -H "X-Auth-Key: ${CF_API_TOKEN}" "https://api.cloudflare.com/client/v4/accounts" | jq . || true
