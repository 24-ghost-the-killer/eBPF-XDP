#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/deploy-xdp.sh <ssh-host> <interface> [native|generic]

Syncs this checkout to a temporary directory on a Linux server, builds there,
installs sentinelctl, sentinel-agent, and the BPF object, then atomically
replaces the XDP program on the selected interface.

The server needs ssh access, rsync, make, clang/LLVM, libbpf development files,
bpftool, Rust/Cargo, and password-capable sudo. Run from any directory.
USAGE
}

die() {
  printf 'deploy-xdp: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ $# -ge 2 && $# -le 3 ]] || { usage >&2; exit 2; }
HOST=$1
IFACE=$2
MODE=${3:-native}
[[ -n "$HOST" ]] || die 'SSH host must not be empty'
[[ "$IFACE" =~ ^[[:alnum:]_.:-]{1,15}$ ]] || die "invalid interface name: $IFACE"
[[ "$MODE" == native || "$MODE" == generic ]] || die 'mode must be native or generic'

for tool in ssh rsync; do
  command -v "$tool" >/dev/null 2>&1 || die "required local command not found: $tool"
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REMOTE_DIR=$(ssh "$HOST" 'mktemp -d /tmp/xdp-sentinel-deploy.XXXXXX') || die 'could not create remote staging directory'
[[ "$REMOTE_DIR" == /tmp/xdp-sentinel-deploy.* ]] || die 'server returned an unexpected staging path'

cleanup() {
  ssh "$HOST" rm -rf -- "$REMOTE_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rsync -az --delete \
  --exclude='.git/' \
  --exclude='.venv/' \
  --exclude='target/' \
  --exclude='build/' \
  --exclude='ebpf/build/' \
  "$ROOT/" "$HOST:$REMOTE_DIR/"

ssh -t "$HOST" bash -s -- "$REMOTE_DIR" "$IFACE" "$MODE" <<'REMOTE_SCRIPT'
set -euo pipefail
REMOTE_DIR=$1
IFACE=$2
MODE=$3

cd "$REMOTE_DIR"
make all

sudo install -D -m 0755 target/release/sentinelctl /usr/local/bin/sentinelctl
sudo install -D -m 0755 target/release/sentinel-agent /usr/local/bin/sentinel-agent
sudo install -D -m 0644 ebpf/build/xdp_main.bpf.o /usr/lib/xdp-sentinel/xdp_main.bpf.o

sudo /usr/local/bin/sentinelctl attach \
  --iface "$IFACE" \
  --obj /usr/lib/xdp-sentinel/xdp_main.bpf.o \
  --mode "$MODE" \
  --replace

if sudo systemctl is-active --quiet sentinel-agent; then
  sudo systemctl restart sentinel-agent
fi

sudo /usr/local/bin/sentinelctl status --iface "$IFACE"
REMOTE_SCRIPT