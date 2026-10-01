import sys
import hashlib
import json
import subprocess
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def derive_keys(seed_str):
    seed = hashlib.sha256(seed_str.encode()).digest()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub_key = priv.public_key()
    if hasattr(pub_key, "public_bytes_raw"):
        pub = pub_key.public_bytes_raw()
    else:
        pub = pub_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return (seed + pub).hex()

def get_ygg_address(ygg_bin, priv_hex):
    cfg = {"PrivateKey": priv_hex}
    p = subprocess.Popen([ygg_bin, "-useconf", "-address"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = p.communicate(input=json.dumps(cfg).encode())
    return out.decode().strip()

def main():
    if len(sys.argv) < 3:
        print("Usage: ygg_gen.py <slot_id> <total_slots> [salt] [ygg_bin]")
        sys.exit(1)
    
    raw_slot = "".join(c for c in sys.argv[1] if c.isdigit())
    slot_id = int(raw_slot) if raw_slot else 1
    total_slots = int(sys.argv[2])
    salt = sys.argv[3] if len(sys.argv) > 3 else "unsafie-mesh-v1"
    ygg_bin = sys.argv[4] if len(sys.argv) > 4 else "yggdrasil"

    my_priv = derive_keys(f"{salt}-slot-{slot_id}")
    
    hosts = []
    my_addr = ""
    for s in range(1, total_slots + 1):
        priv_hex = derive_keys(f"{salt}-slot-{s}")
        addr = get_ygg_address(ygg_bin, priv_hex)
        name = f"master-{s}" if s <= 3 else f"node-{s}"
        hosts.append(f"{addr} {name} free-vpc-{s}")
        if s == slot_id:
            my_addr = addr

    result = {
        "slot_id": slot_id,
        "private_key": my_priv,
        "my_address": my_addr,
        "hosts": hosts
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
