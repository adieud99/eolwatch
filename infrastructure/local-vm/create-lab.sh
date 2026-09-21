#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/cache"
RUNTIME_DIR="$SCRIPT_DIR/runtime"
VM_DIR="$RUNTIME_DIR/vms"
IMAGE_NAME="ubuntu-24.04-server-cloudimg-arm64.img"
IMAGE_URL="https://cloud-images.ubuntu.com/releases/noble/release/$IMAGE_NAME"
SUMS_URL="https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS"
BASE_IMAGE="$CACHE_DIR/$IMAGE_NAME"
SSH_KEY="$RUNTIME_DIR/id_ed25519"
LAB_NETWORK="eolwatch-lab"

command -v VBoxManage >/dev/null || { echo "VirtualBox가 필요합니다." >&2; exit 1; }
command -v hdiutil >/dev/null || { echo "macOS hdiutil이 필요합니다." >&2; exit 1; }
mkdir -p "$CACHE_DIR" "$RUNTIME_DIR/seeds" "$VM_DIR"

if [[ ! -f "$BASE_IMAGE" ]]; then
  curl --fail --location --retry 3 "$IMAGE_URL" --output "$BASE_IMAGE"
fi
curl --fail --location --retry 3 "$SUMS_URL" --output "$CACHE_DIR/SHA256SUMS"
EXPECTED="$(awk -v name="$IMAGE_NAME" '$2 == "*" name || $2 == name {print $1}' "$CACHE_DIR/SHA256SUMS")"
ACTUAL="$(shasum -a 256 "$BASE_IMAGE" | awk '{print $1}')"
[[ -n "$EXPECTED" && "$ACTUAL" == "$EXPECTED" ]] || { echo "Ubuntu 이미지 SHA-256 검증 실패" >&2; exit 1; }

if [[ ! -f "$SSH_KEY" ]]; then
  ssh-keygen -q -t ed25519 -N "" -C "eolwatch-local-lab" -f "$SSH_KEY"
fi
PUBLIC_KEY="$(cat "$SSH_KEY.pub")"

create_seed() {
  local name="$1" address="$2" mac1="$3" mac2="$4" role="$5"
  local seed_dir="$RUNTIME_DIR/seeds/$name"
  mkdir -p "$seed_dir"
  cat >"$seed_dir/meta-data" <<EOF
instance-id: $name
local-hostname: $name
EOF
  cat >"$seed_dir/network-config" <<EOF
version: 2
ethernets:
  nat0:
    match:
      macaddress: "${mac1:0:2}:${mac1:2:2}:${mac1:4:2}:${mac1:6:2}:${mac1:8:2}:${mac1:10:2}"
    set-name: enp0s3
    dhcp4: true
  lab0:
    match:
      macaddress: "${mac2:0:2}:${mac2:2:2}:${mac2:4:2}:${mac2:6:2}:${mac2:8:2}:${mac2:10:2}"
    set-name: enp0s8
    addresses: [$address/24]
EOF
  local packages="openssh-server, curl, jq"
  if [[ "$role" == "controller" ]]; then
    packages="$packages, docker.io, docker-compose-v2"
  else
    packages="$packages, nginx, postgresql-client, python3-jinja2"
  fi
  cat >"$seed_dir/user-data" <<EOF
#cloud-config
users:
  - name: eolwatch
    gecos: EOLWatch Operator
    groups: [adm, sudo, docker]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $PUBLIC_KEY
package_update: true
packages: [$packages]
ssh_pwauth: false
disable_root: true
runcmd:
  - [systemctl, enable, --now, ssh]
  - [sh, -c, "echo '$role' > /etc/eolwatch-role"]
EOF
  hdiutil makehybrid -quiet -ov -iso -joliet -iso-volume-name cidata -joliet-volume-name cidata -o "$RUNTIME_DIR/seeds/$name.iso" "$seed_dir"
}

create_vm() {
  local name="$1" address="$2" ssh_port="$3" memory="$4" cpus="$5" mac1="$6" mac2="$7" role="$8"
  if VBoxManage showvminfo "$name" >/dev/null 2>&1; then
    echo "이미 존재하는 VM이라 건너뜁니다: $name"
    return
  fi
  create_seed "$name" "$address" "$mac1" "$mac2" "$role"
  local disk="$VM_DIR/$name.vdi"
  VBoxManage clonemedium disk "$BASE_IMAGE" "$disk" --format VDI
  VBoxManage modifymedium disk "$disk" --resize 20480
  VBoxManage createvm --name "$name" --platform-architecture arm --ostype Ubuntu_arm64 --basefolder "$VM_DIR" --register
  VBoxManage modifyvm "$name" --memory "$memory" --cpus "$cpus" --firmware efi --graphicscontroller vmsvga --audio-enabled off
  VBoxManage modifyvm "$name" --nic1 nat --nictype1 virtio --mac-address1 "$mac1" --natpf1 "ssh,tcp,127.0.0.1,$ssh_port,,22"
  VBoxManage modifyvm "$name" --nic2 intnet --nictype2 virtio --intnet2 "$LAB_NETWORK" --mac-address2 "$mac2"
  if [[ "$role" == "controller" ]]; then
    VBoxManage modifyvm "$name" --natpf1 "web,tcp,127.0.0.1,18080,,8080" --natpf1 "api,tcp,127.0.0.1,18000,,8000"
  fi
  VBoxManage storagectl "$name" --name VirtioSCSI --add virtio-scsi --controller VirtIO --portcount 2 --bootable on
  VBoxManage storageattach "$name" --storagectl VirtioSCSI --port 0 --device 0 --type hdd --medium "$disk"
  VBoxManage storageattach "$name" --storagectl VirtioSCSI --port 1 --device 0 --type dvddrive --medium "$RUNTIME_DIR/seeds/$name.iso"
  VBoxManage modifyvm "$name" --boot1 disk --boot2 dvd --boot3 none --boot4 none
  VBoxManage startvm "$name" --type headless
}

create_vm eolwatch-controller 10.77.0.10 12222 4096 2 080027770010 080027770110 controller
create_vm eolwatch-target-01 10.77.0.21 12223 1536 1 080027770021 080027770121 target
create_vm eolwatch-target-02 10.77.0.22 12224 1536 1 080027770022 080027770122 target

cat <<EOF
VM 생성을 시작했습니다. cloud-init 설치에는 몇 분 걸릴 수 있습니다.
다음 단계: $SCRIPT_DIR/deploy-to-lab.sh
웹 주소: http://127.0.0.1:18080
SSH 키: $SSH_KEY
EOF
