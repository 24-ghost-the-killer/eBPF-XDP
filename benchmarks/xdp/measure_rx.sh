#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# DUT side: record what the XDP program saw, what the NIC dropped before XDP
# and how busy the RX cores were, for one benchmark rung.
#
#   measure_rx.sh -i <iface> -l <label> [-d seconds] [-o results dir]
#
# Output: <dir>/<label>.{stats.jsonl,ethtool.before,ethtool.after,mpstat,meta}
#
# Interpretation (see docs/performance.md, "Reading results"):
#   * xdp rx pps  = sentinelctl `rx` rate: packets that reached the program
#   * NIC drops   = delta of rx_missed/rx_dropped/rx_out_of_buffer style
#                   counters in ethtool -S (names are driver specific):
#                   packets the host could not take in time
#   * CPU         = %soft (softirq) on the RX cores from mpstat
# A rung "sustains" a rate only if NIC drops stay ~0 at that offered load.
set -euo pipefail

DUR=30; OUT=benchmarks/results
while getopts "i:l:d:o:" o; do
	case $o in i) IFACE=$OPTARG ;; l) LABEL=$OPTARG ;; d) DUR=$OPTARG ;; o) OUT=$OPTARG ;;
	*) sed -n '4,20p' "$0"; exit 2 ;; esac
done
: "${IFACE:?-i required}" "${LABEL:?-l required}"
CTL=${CTL:-sentinelctl}
mkdir -p "$OUT"
P="$OUT/$LABEL"

{
	echo "date: $(date -Is)"; echo "kernel: $(uname -r)"; echo "host: $(hostname)"
	echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-)"
	ethtool -i "$IFACE"; ethtool -l "$IFACE" 2>/dev/null || true
	ethtool -g "$IFACE" 2>/dev/null || true; ethtool -k "$IFACE" | grep -E 'rx-vlan|gro|lro|ntuple'
	ip -details link show "$IFACE"
	grep -H . /proc/irq/*/smp_affinity_list 2>/dev/null | grep -f <(grep "$IFACE" /proc/interrupts | cut -d: -f1 | tr -d ' ' | sed 's|^|/proc/irq/|;s|$|/|') || true
} > "$P.meta"

ethtool -S "$IFACE" > "$P.ethtool.before"
mpstat -P ALL 1 "$DUR" > "$P.mpstat" &
MP=$!
"$CTL" stats -i "$IFACE" --interval 1 --count "$DUR" --json > "$P.stats.jsonl"
wait $MP
ethtool -S "$IFACE" > "$P.ethtool.after"

python3 - "$P" <<'PY'
import json, re, sys
p = sys.argv[1]
rows = [json.loads(l) for l in open(p + ".stats.jsonl")]
steady = rows[2:-2] or rows  # drop ramp-up/ramp-down seconds
def avg(name, field): return sum(r["counters"][name][field] for r in steady) / len(steady)
def eth(f):
    d = {}
    for line in open(f):
        m = re.match(r"\s*([\w\.\-\[\]]+):\s*(\d+)", line)
        if m: d[m.group(1)] = int(m.group(2))
    return d
b, a = eth(p + ".ethtool.before"), eth(p + ".ethtool.after")
drops = {k: a[k] - b.get(k, 0) for k in a
         if re.search(r"(miss|drop|no_buf|out_of_buffer|discard|fifo)", k) and a[k] - b.get(k, 0) > 0}
print(f"{p}: xdp rx {avg('rx','pps')/1e6:.3f} Mpps {avg('rx','bps')/1e9:.3f} Gbit/s "
      f"| xdp drop {avg('verdict_drop','pps')/1e6:.3f} Mpps | NIC drop counters: {drops or 'none'}")
PY
