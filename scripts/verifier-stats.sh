#!/usr/bin/env bash
# Load the XDP object through the in-kernel verifier (without attaching it)
# and print per-program verifier statistics. Needs root and a mounted bpffs.
#   scripts/verifier-stats.sh [path/to/xdp_main.bpf.o]
set -euo pipefail
OBJ=${1:-ebpf/build/xdp_main.bpf.o}
PIN=/sys/fs/bpf/xs-verifier-check-$$
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
trap 'rm -rf "$PIN"' EXIT
LOG=$(bpftool -d prog loadall "$OBJ" "$PIN" 2>&1) || { echo "$LOG" | tail -60; echo "VERIFIER REJECTED $OBJ" >&2; exit 1; }
echo "$LOG" | grep -E "^(processed|verification time|stack depth)|^func#|Func#" || true
bpftool prog show pinned "$PIN/xs_xdp_main"
