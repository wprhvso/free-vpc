import json
import os
import sys
import urllib.request
import urllib.error

account_id = os.environ.get("CF_ACCOUNT_ID", "").strip()
api_token = os.environ.get("CF_API_TOKEN", "").strip()
domain = os.environ.get("CLUSTER_DOMAIN", "unsafie.com").strip()

if not account_id or not api_token:
    sys.exit(1)

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

def cf_api(method, path, body=None):
    url = f"https://api.cloudflare.com/client/v4{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"API Error {method} {path}: {e.code} {err_msg}", file=sys.stderr)
        return None

zones_data = cf_api("GET", f"/zones?name={domain}")
if not zones_data or not zones_data.get("result"):
    sys.exit(1)

zone_id = zones_data["result"][0]["id"]

tunnels_data = cf_api("GET", f"/accounts/{account_id}/cfd_tunnel?is_deleted=false")
if not tunnels_data or not tunnels_data.get("result"):
    sys.exit(1)

tunnels = {t["name"]: t["id"] for t in tunnels_data["result"]}

t1_id = tunnels.get("ygg-mesh-1")
t2_id = tunnels.get("ygg-mesh-2")
t3_id = tunnels.get("ygg-mesh-3")

if not t1_id:
    t1_id = next(iter(tunnels.values()))

tunnel_map = {
    1: t1_id,
    2: t2_id or t1_id,
    3: t3_id or t1_id
}

for slot, tun_id in tunnel_map.items():
    if not tun_id:
        continue
    ingress = [
        {"hostname": f"mesh{slot}.{domain}", "service": "http://127.0.0.1:9001"},
        {"hostname": f"gitops.{domain}", "service": "http://127.0.0.1:80"},
        {"hostname": f"headlamp.{domain}", "service": "http://127.0.0.1:80"},
        {"hostname": f"ui.{domain}", "service": "http://127.0.0.1:80"},
        {"hostname": f"*.{domain}", "service": "http://127.0.0.1:80"},
        {"service": "http_status:404"}
    ]
    cf_api("PUT", f"/accounts/{account_id}/cfd_tunnel/{tun_id}/configurations", {"config": {"ingress": ingress}})

dns_data = cf_api("GET", f"/zones/{zone_id}/dns_records?per_page=100")
existing_records = {}
if dns_data and dns_data.get("result"):
    for r in dns_data["result"]:
        existing_records[r["name"]] = r

target_records = {
    f"mesh1.{domain}": f"{t1_id}.cfargotunnel.com",
    f"mesh2.{domain}": f"{tunnel_map[2]}.cfargotunnel.com",
    f"mesh3.{domain}": f"{tunnel_map[3]}.cfargotunnel.com",
    f"gitops.{domain}": f"{t1_id}.cfargotunnel.com",
    f"headlamp.{domain}": f"{t1_id}.cfargotunnel.com",
    f"ui.{domain}": f"{t1_id}.cfargotunnel.com",
    f"*.{domain}": f"{t1_id}.cfargotunnel.com",
}

for name, target in target_records.items():
    if name in existing_records:
        rec = existing_records[name]
        if rec["type"] != "CNAME" or rec["content"] != target or not rec["proxied"]:
            cf_api("PUT", f"/zones/{zone_id}/dns_records/{rec['id']}", {
                "type": "CNAME",
                "name": name,
                "content": target,
                "proxied": True,
                "ttl": 1
            })
    else:
        cf_api("POST", f"/zones/{zone_id}/dns_records", {
            "type": "CNAME",
            "name": name,
            "content": target,
            "proxied": True,
            "ttl": 1
        })
