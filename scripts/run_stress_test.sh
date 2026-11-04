#!/usr/bin/env bash
# =============================================================================
# run_stress_test.sh — safe, in-kernel stress/benchmark harness for xdp-sentinel
# =============================================================================
# Runs ENTIRELY in-kernel (BPF_PROG_TEST_RUN + `bpftool prog run` injection).
# It NEVER transmits on the wire, so it cannot saturate the DUT's own uplink or
# DoS the management plane. Use it on a single-NIC / generic-XDP appliance where
# a line-rate wire flood would take SSH + the dashboard down with it.
#
# For TRUE line-rate numbers you need a SEPARATE wired load host flooding the
# DUT (see benchmarks/xdp/pktgen_tx.sh — "run on another machine, never the
# DUT" — and scripts/bench-10g.sh). This harness deliberately does not do that.
#
# Vectors:
#   A  per-packet CPU cost across 64..1500 B   (bench_prog_run, no maps needed)
#   B  high-cardinality source churn (LRU)     (spoofed injection + occupancy)
#   C  rate-limiter / conntrack behaviour       (SYN/UDP injection + map reads)
#   D  telemetry ring-buffer                    (reports state; sampling is
#                                                usually OFF on a live bridge)
#
# Usage:
#   sudo scripts/run_stress_test.sh                 # full run on the pinned iface
#   XS_IFACE=vlan20 sudo -E scripts/run_stress_test.sh
#   sudo scripts/run_stress_test.sh --no-inject     # A + map envelope only (no live flood)
#
# Env:
#   XS_IFACE    target interface (default: first pinned iface under BPFFS root)
#   XS_METRICS  agent metrics    (default: http://127.0.0.1:9464/metrics)
#   XS_DASH     health URL to watchdog (default: http://127.0.0.1:9091/-/healthy)
#   XS_OBJ      deployed xdp_main.bpf.o (default: /usr/lib/xdp-sentinel/xdp_main.bpf.o)
#   XS_REPO     repo root (default: dir two levels up from this script)
# -----------------------------------------------------------------------------
set -euo pipefail

XS_METRICS="${XS_METRICS:-http://127.0.0.1:9464/metrics}"
XS_DASH="${XS_DASH:-http://127.0.0.1:9091/-/healthy}"
XS_OBJ="${XS_OBJ:-/usr/lib/xdp-sentinel/xdp_main.bpf.o}"
BPFFS_ROOT="${XS_BPFFS_ROOT:-/sys/fs/bpf/xdp-sentinel}"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XS_REPO="${XS_REPO:-$(cd "$SELF/.." && pwd)}"
INJECT=yes
[ "${1:-}" = "--no-inject" ] && INJECT=no

c(){ printf '\033[%sm' "$1"; }
hdr(){ printf '\n%s== %s ==%s\n' "$(c '1;36')" "$*" "$(c 0)"; }
ok(){ printf '   %s✓%s %s\n' "$(c '1;32')" "$(c 0)" "$*"; }
warn(){ printf '%s!! %s%s\n' "$(c '1;33')" "$*" "$(c 0)" >&2; }
die(){ printf '%sxx %s%s\n' "$(c '1;31')" "$*" "$(c 0)" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo) — BPF_PROG_TEST_RUN / bpftool prog run need it."

# Pick a pinned interface if XS_IFACE not set (external injection needs pinned maps).
if [ -z "${XS_IFACE:-}" ]; then
  for d in "$BPFFS_ROOT"/*/; do
    [ -e "$d/xs_attacker_v4" ] && { XS_IFACE="$(basename "$d")"; break; }
  done
fi
: "${XS_IFACE:?no pinned interface found under $BPFFS_ROOT; set XS_IFACE=}"
BPFFS="$BPFFS_ROOT/$XS_IFACE"
ok "target interface: $XS_IFACE   (maps: $BPFFS)"

metric(){ curl -s "$XS_METRICS" | grep -E "$1" | awk '{print $NF}' | tail -1; }

# ---------------------------------------------------------------------------
# Vector A: per-packet CPU cost (no live traffic, no maps).
# ---------------------------------------------------------------------------
hdr "Vector A — per-packet CPU cost (BPF_PROG_TEST_RUN)"
BIN=/tmp/xs_bench_prog_run
BASE=/tmp/xs_baseline.bpf.o
if [ ! -x "$BIN" ] || [ ! -e "$BASE" ]; then
  command -v clang >/dev/null || die "clang needed to build the microbench"
  clang -g -O2 -target bpf -mcpu=v3 -std=gnu11 -I "$XS_REPO/ebpf" -I "$XS_REPO/ebpf/src" \
    -c "$XS_REPO/benchmarks/xdp/baseline.bpf.c" -o "$BASE" || die "baseline build failed"
  clang -O2 -I "$XS_REPO/tests/common" -I "$XS_REPO/ebpf/src" -I "$XS_REPO/ebpf" \
    "$XS_REPO/benchmarks/xdp/bench_prog_run.c" -lbpf -lelf -lz -o "$BIN" || die "bench build failed"
  ok "built microbench -> $BIN"
fi
[ -e "$XS_OBJ" ] || die "deployed object not found: $XS_OBJ"
"$BIN" "$XS_OBJ" "$BASE" "${XS_REPEAT:-500000}"

# ---------------------------------------------------------------------------
# Map & memory envelope (capacity ceiling for vectors B/C/D).
# ---------------------------------------------------------------------------
hdr "Map & memory envelope"
printf '%-16s %-10s %10s %12s\n' map type max_entries memlock
for m in xs_ct xs_rl_v4 xs_rl_v6 xs_attacker_v4 xs_victim_v4 xs_dport_hist xs_samples xs_global_rl; do
  p="$BPFFS/$m"; [ -e "$p" ] || continue
  bpftool map show pinned "$p" 2>/dev/null | awk -v n="$m" '
    /name/{t=$2}
    {for(i=1;i<=NF;i++){if($i=="max_entries")me=$(i+1);if($i=="memlock")ml=$(i+1)}}
    END{printf "%-16s %-10s %10s %12s\n", n, t, me, ml}'
done

if [ "$INJECT" = no ]; then
  ok "done (--no-inject: skipped live vectors B/C/D)"; exit 0
fi

# ---------------------------------------------------------------------------
# Vectors B/C: live high-cardinality + SYN injection, with a mgmt-plane watchdog.
# ---------------------------------------------------------------------------
hdr "Vectors B/C — live injection on $XS_IFACE (in-kernel; LAN stays exempt)"
command -v python3 >/dev/null || die "python3 needed for the injector"
PT="$XS_REPO/pentest/xdp_pentest.py"; [ -f "$PT" ] || die "injector not found: $PT"

d0="$(metric 'xs_verdict_packets_total.*verdict="drop".*'"$XS_IFACE" || echo 0)"
SAMP=/tmp/xs_stress_watch.log; : > "$SAMP"
( for _ in $(seq 1 40); do
    printf '%s dash=%s idle=%s srcs=%s ring_drop=%s\n' \
      "$(date +%s)" \
      "$(curl -s -o /dev/null -w '%{http_code}' "$XS_DASH")" \
      "$(mpstat 1 1 2>/dev/null | awk '/Average/{print $NF}')" \
      "$(curl -s "$XS_METRICS" | awk -F'[ }]' '/xs_attacker_sources\{iface="'"$XS_IFACE"'"/{print $(NF-1)+0}')" \
      "$(curl -s "$XS_METRICS" | awk '/xs_sample_packets_total\{iface="'"$XS_IFACE"'",event="dropped"/{print $NF}')" \
      >> "$SAMP"
  done ) &
WATCH=$!

# --pcap records a sampled .pcap of the injected frames to pentest/results/ so
# every stress run leaves a capturable artifact to analyse for holes (the suite
# injects in-kernel and never hits the wire, so a live tcpdump cannot see it).
XS_IFACE="$XS_IFACE" XS_METRICS="$XS_METRICS" python3 "$PT" --run --filter evasion --pcap 2>&1 | tail -14 || true
kill "$WATCH" 2>/dev/null || true; wait "$WATCH" 2>/dev/null || true

d1="$(metric 'xs_verdict_packets_total.*verdict="drop".*'"$XS_IFACE" || echo 0)"
hdr "Results"
printf '   packets dropped by mitigation: %s\n' "$(( ${d1:-0} - ${d0:-0} ))"
printf '   dashboard non-200 samples    : %s\n' "$(awk '$2!="dash=200"&&$0~/dash=/{n++}END{print n+0}' "$SAMP")"
printf '   min CPU idle during run      : %s\n' "$(awk -F'idle=' '/idle=/{split($2,a," ");if(m==""||a[1]<m)m=a[1]}END{print m}' "$SAMP")"
printf '   max ringbuf drops            : %s (0 = sampling off / no overflow)\n' \
  "$(awk -F'ring_drop=' '/ring_drop=/{if($2>m)m=$2}END{print m+0}' "$SAMP")"

hdr "Vector D — telemetry ring-buffer"
taken="$(metric 'xs_sample_packets_total\{iface="'"$XS_IFACE"'",event="taken"' || echo 0)"
if [ "${taken:-0}" = "0" ]; then
  warn "header sampling is DISABLED on $XS_IFACE (taken=0) — ring cannot be saturated in this config."
else
  ok "sampling active: taken=$taken dropped=$(metric 'xs_sample_packets_total.*event="dropped".*'"$XS_IFACE")"
fi
ok "stress run complete."
