#!/usr/bin/env bash
set -euo pipefail

FC_VERSION="v1.17.0"
FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4"

setup_kvm() {
  if [ -e /dev/kvm ]; then
    sudo chmod 666 /dev/kvm
  fi
}

setup_zswap() {
  echo 1 | sudo tee /sys/module/zswap/parameters/enabled 2>/dev/null || true
  echo zstd | sudo tee /sys/module/zswap/parameters/compressor 2>/dev/null || echo lz4 | sudo tee /sys/module/zswap/parameters/compressor 2>/dev/null || true
  echo z3fold | sudo tee /sys/module/zswap/parameters/zpool 2>/dev/null || echo zbud | sudo tee /sys/module/zswap/parameters/zpool 2>/dev/null || true
  echo 50 | sudo tee /sys/module/zswap/parameters/max_pool_percent 2>/dev/null || true

  if ! swapon --show 2>/dev/null | grep -q "/swapfile"; then
    sudo fallocate -l 8G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=8192 2>/dev/null || true
    if [ -f /swapfile ]; then
      sudo chmod 600 /swapfile
      sudo mkswap /swapfile >/dev/null 2>&1 || true
      sudo swapon /swapfile 2>/dev/null || true
    fi
  fi
  sudo sysctl -w vm.swappiness=80 >/dev/null 2>&1 || true
}

setup_ksm() {
  echo 1 | sudo tee /sys/kernel/mm/ksm/run 2>/dev/null || true
  echo 100 | sudo tee /sys/kernel/mm/ksm/pages_to_scan 2>/dev/null || true
  echo 20 | sudo tee /sys/kernel/mm/ksm/sleep_millisecs 2>/dev/null || true
}

setup_bridge() {
  local gateway_ip="$1"
  local subnet="$2"

  sudo ip link add br0 type bridge 2>/dev/null || true
  sudo ip addr replace "${gateway_ip}/24" dev br0 2>/dev/null || sudo ip addr add "${gateway_ip}/24" dev br0 2>/dev/null || true
  sudo ip link set br0 up

  sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
  local def_iface
  def_iface=$(ip route show default | awk '{print $5}' | head -n1 || true)
  if [ -n "$def_iface" ]; then
    sudo iptables -t nat -A POSTROUTING -s "${subnet}" ! -o br0 -j MASQUERADE 2>/dev/null || true
    sudo iptables -A FORWARD -i br0 -j ACCEPT 2>/dev/null || true
    sudo iptables -A FORWARD -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
}

start_metadata_server() {
  local gateway_ip="$1"
  local port="${2:-18080}"
  pkill -f "metadata_server.py" 2>/dev/null || true
  python3 "${SCRIPT_DIR}/metadata_server.py" "$gateway_ip" "$port" >/tmp/meta_server.log 2>&1 &
}

install_firecracker() {
  if ! command -v firecracker >/dev/null 2>&1; then
    mkdir -p /tmp/fc-install
    curl -fsSL "$FC_URL" | tar -zx -C /tmp/fc-install
    sudo cp /tmp/fc-install/release-*/firecracker-${FC_VERSION}-x86_64 /usr/local/bin/firecracker
    sudo chmod +x /usr/local/bin/firecracker
    rm -rf /tmp/fc-install
  fi
}

download_assets() {
  mkdir -p /tmp/fc-assets
  if [ ! -f /tmp/fc-assets/vmlinux.bin ]; then
    curl -fsSL -o /tmp/fc-assets/vmlinux.bin "$KERNEL_URL"
  fi
  if [ ! -f /tmp/fc-assets/base-rootfs.ext4 ]; then
    curl -fsSL -o /tmp/fc-assets/base-rootfs.ext4 "$ROOTFS_URL"
  fi
}

spawn_microvm() {
  local vm_id="$1"
  local vm_ip="$2"
  local gateway_ip="$3"
  local vcpus="${4:-1}"
  local mem_mb="${5:-1024}"
  local tap_name="tap-${vm_id:0:8}"
  local sock="/tmp/fc-${vm_id}.sock"
  local vm_rootfs="/tmp/rootfs-${vm_id}.ext4"

  sudo ip tuntap add dev "$tap_name" mode tap 2>/dev/null || true
  sudo ip link set "$tap_name" master br0 2>/dev/null || true
  sudo ip link set "$tap_name" up

  cp --sparse=always /tmp/fc-assets/base-rootfs.ext4 "$vm_rootfs" 2>/dev/null || cp /tmp/fc-assets/base-rootfs.ext4 "$vm_rootfs"

  mkdir -p /tmp/mnt-"$vm_id"
  sudo mount -o loop "$vm_rootfs" /tmp/mnt-"$vm_id" 2>/dev/null || true
  if [ -d /tmp/mnt-"$vm_id"/root ]; then
    sudo mkdir -p /tmp/mnt-"$vm_id"/root/.ssh
    if [ -f /tmp/free-vpc-auth-keys ]; then
      sudo cp /tmp/free-vpc-auth-keys /tmp/mnt-"$vm_id"/root/.ssh/authorized_keys
      sudo chmod 600 /tmp/mnt-"$vm_id"/root/.ssh/authorized_keys
    fi
  fi

  if [ -d /tmp/mnt-"$vm_id"/etc ]; then
    cat << AGENTEOF | sudo tee /tmp/mnt-"$vm_id"/etc/rc.local > /dev/null
#!/bin/sh -e
(
  while true; do
    GUEST_IP=\$(hostname -I 2>/dev/null | awk '{print \$1}')
    if [ -n "\$GUEST_IP" ]; then
      FETCHED_KEYS=\$(curl -sf "http://${gateway_ip}:18080/keys?ip=\${GUEST_IP}" 2>/dev/null || true)
      if [ -n "\$FETCHED_KEYS" ]; then
        mkdir -p /root/.ssh
        echo "\$FETCHED_KEYS" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        break
      fi
    fi
    sleep 1
  done
) &
exit 0
AGENTEOF
    sudo chmod +x /tmp/mnt-"$vm_id"/etc/rc.local
  fi

  sudo umount /tmp/mnt-"$vm_id" 2>/dev/null || true
  rm -rf /tmp/mnt-"$vm_id"

  rm -f "$sock"
  firecracker --api-sock "$sock" >/tmp/fc-"$vm_id".log 2>&1 &
  sleep 1

  local boot_args="console=ttyS0 reboot=k panic=1 pci=off ip=${vm_ip}::${gateway_ip}:255.255.255.0::eth0:off root=/dev/vda rw"

  curl -s -X PUT --unix-socket "$sock" http://localhost/boot-source \
    -H "Content-Type: application/json" \
    -d "{\"kernel_image_path\": \"/tmp/fc-assets/vmlinux.bin\", \"boot_args\": \"$boot_args\"}"

  curl -s -X PUT --unix-socket "$sock" http://localhost/drives/rootfs \
    -H "Content-Type: application/json" \
    -d "{\"drive_id\": \"rootfs\", \"path_on_host\": \"$vm_rootfs\", \"is_root_device\": true, \"is_read_only\": false}"

  local mac_suffix
  mac_suffix=$(printf '%02x:%02x' $((RANDOM%256)) $((RANDOM%256)))
  local guest_mac="AA:FC:00:00:${mac_suffix}"

  curl -s -X PUT --unix-socket "$sock" http://localhost/network-interfaces/eth0 \
    -H "Content-Type: application/json" \
    -d "{\"iface_id\": \"eth0\", \"guest_mac\": \"$guest_mac\", \"host_dev_name\": \"$tap_name\"}"

  curl -s -X PUT --unix-socket "$sock" http://localhost/machine-config \
    -H "Content-Type: application/json" \
    -d "{\"vcpu_count\": $vcpus, \"mem_size_mib\": $mem_mb}"

  curl -s -X PUT --unix-socket "$sock" http://localhost/actions \
    -H "Content-Type: application/json" \
    -d "{\"action_type\": \"InstanceStart\"}"
}

stop_microvm() {
  local vm_id="$1"
  local sock="/tmp/fc-${vm_id}.sock"
  local tap_name="tap-${vm_id:0:8}"
  local pid
  pid=$(pgrep -f "firecracker.*${vm_id}" || true)
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$sock" "/tmp/rootfs-${vm_id}.ext4"
  sudo ip link set "$tap_name" down 2>/dev/null || true
  sudo ip link delete "$tap_name" 2>/dev/null || true
}
