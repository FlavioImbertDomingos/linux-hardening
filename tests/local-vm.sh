#!/usr/bin/env bash
# =============================================================================
# End-to-end test of the playbook against a throwaway local VM using Multipass
# (https://multipass.run — `brew install multipass` on macOS, snap on Linux).
#
#   tests/local-vm.sh                 # Ubuntu 24.04, full harden-image.yml
#   tests/local-vm.sh 22.04           # Ubuntu 22.04
#   tests/local-vm.sh 24.04 verify    # only run verify.yml against an existing VM
#   tests/local-vm.sh 24.04 destroy   # delete the VM
#
# The VM keeps NOPASSWD sudo for `ubuntu` until finalize seals it, exactly like
# a Packer build. Artefacts land in ./artifacts/<vm-name>/.
# On Apple Silicon the VM is aarch64 — the playbook supports it (audit rules,
# node_exporter/otelcol/syft/grype arm64 builds).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

RELEASE="${1:-24.04}"
ACTION="${2:-build}"
VM="lh-ubuntu${RELEASE//./}"
KEY="${HOME}/.ssh/linux-hardening-test"
INV="$(pwd)/artifacts/${VM}-inventory.yml"

need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
need multipass; need ansible-playbook

if [ "$ACTION" = "destroy" ]; then
  multipass delete --purge "$VM" 2>/dev/null || true
  rm -f "$INV"; echo "$VM destroyed"; exit 0
fi

[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C "linux-hardening test"

if ! multipass info "$VM" >/dev/null 2>&1; then
  echo ">> launching $VM (Ubuntu $RELEASE)"
  cat > /tmp/${VM}-cloud-init.yml <<EOF
#cloud-config
users:
  - default
  - name: ubuntu
    ssh_authorized_keys:
      - $(cat "${KEY}.pub")
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
EOF
  multipass launch "$RELEASE" --name "$VM" --cpus 2 --memory 4G --disk 20G \
    --cloud-init /tmp/${VM}-cloud-init.yml
fi

IP=$(multipass info "$VM" --format json | python3 -c 'import sys,json; d=json.load(sys.stdin)["info"]; print(list(d.values())[0]["ipv4"][0])')
mkdir -p artifacts
cat > "$INV" <<EOF
all:
  children:
    image_builders:
      hosts:
        ${VM}:
          ansible_host: ${IP}
          ansible_user: ubuntu
          ansible_ssh_private_key_file: ${KEY}
          ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
          image_name: base-ubuntu${RELEASE//./}-test
EOF
echo ">> $VM is at $IP — inventory: $INV"

export IMAGE_VERSION="${IMAGE_VERSION:-0.0.0-local}"
export GIT_SHA="${GIT_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"

# Local-test overrides: the SSH allow-list is whatever the VM sees us as
# (handled automatically by the preflight play), telemetry has nowhere to go
# (harmless: the collector queues and retries), signing is off unless you
# export COSIGN_KEY, and the build user is kept so you can still get in.
COMMON=(-i "$INV" -e finalize_remove_build_user=false)

case "$ACTION" in
  build)  ansible-playbook "${COMMON[@]}" playbooks/harden-image.yml "${@:3}" ;;
  verify) ansible-playbook "${COMMON[@]}" playbooks/verify.yml "${@:3}" ;;
  *) echo "unknown action: $ACTION (build|verify|destroy)"; exit 1 ;;
esac

echo
echo ">> done. Inspect:   multipass shell $VM"
echo ">> artefacts:       artifacts/${VM}/"
echo ">> tear down:       tests/local-vm.sh $RELEASE destroy"
