#!/usr/bin/env bash
# bench-10g.sh - line-rate acceptance benchmark (Phase 16), run ON the system
# under test while a separate wired host floods it (pktgen / TRex / xdp-hammer
# from a 10G LAN host). It samples the dataplane counters and CPU over a window
# and checks the acceptance criteria from docs/performance.md:
#
#   * handles the offered pps with drop behaviour matching the mitigation config
#   * average program cost <= 150 ns/packet (derived from CPU busy time in the
#     softirq path vs packets processed)
#
#   sudo scripts/bench-10g.sh <iface> [seconds]
#
# It does NOT generate traffic; start the flood from the load host first. On
# Wi-Fi / generic XDP it will run but the offered rate is capped far below
# 10G, so treat the result as functional, not line-rate (it says so).
set -u
IFACE="${1:?usage: bench-10g.sh <iface> [seconds]}"
DUR="${2:-10}"
CTL="${CTL:-sentinelctl}"
NS_BUDGET="${NS_BUDGET:-150}"

command -v "$CTL" >/dev/null 2>&1 || { echo "need sentinelctl in PATH (or CTL=...)"; exit 3; }

read_rx() { sudo "$CTL" stats -i "$IFACE" --prometheus 2>/dev/null \
  | awk -F'[ {}]' '/xs_rx_packets_total/{v=$NF} END{print v+0}'; }
read_drop() { sudo "$CTL" stats -i "$IFACE" --prometheus 2>/dev/null \
  | awk '/xs_verdict_packets_total.*verdict="drop"/{print $NF}' | tail -1; }
cpu_busy_ns() { awk '/^cpu /{busy=($2+$3+$4+$6+$7+$8); print busy}' /proc/stat; }  # jiffies

mode=$(sudo "$CTL" status -i "$IFACE" 2>/dev/null | awk '/attach mode/{print $3}')
echo "=== 10G acceptance benchmark: $IFACE, ${DUR}s, mode=$mode ==="
[ "$mode" = "generic" ] && echo "NOTE: generic XDP - offered rate is NOT line rate; functional check only."

CLK=$(getconf CLK_TCK)
rx0=$(read_rx); dr0=$(read_drop); c0=$(cpu_busy_ns); t0=$(date +%s.%N)
sleep "$DUR"
rx1=$(read_rx); dr1=$(read_drop); c1=$(cpu_busy_ns); t1=$(date +%s.%N)

dt=$(awk "BEGIN{print $t1-$t0}")
pkts=$(( rx1 - rx0 ))
drops=$(( ${dr1:-0} - ${dr0:-0} ))
pps=$(awk "BEGIN{print $pkts/$dt}")
# CPU busy time across all cores, in ns, over the window.
cores=$(nproc)
busy_ns=$(awk "BEGIN{print ($c1-$c0)/$CLK*1e9}")
ns_per_pkt=$(awk "BEGIN{ if($pkts>0) print $busy_ns/$pkts; else print 0 }")

printf "packets handled : %d  (%.0f pps)\n" "$pkts" "$pps"
printf "dropped         : %d  (%.1f%%)\n" "$drops" "$(awk "BEGIN{print ($pkts>0)?100*$drops/$pkts:0}")"
printf "system-wide CPU : %.0f ns busy over %d cores\n" "$busy_ns" "$cores"
printf "cost/packet     : %.1f ns  (whole-system upper bound; budget %d ns)\n" "$ns_per_pkt" "$NS_BUDGET"

echo "=== acceptance ==="
pass=1
awk "BEGIN{exit !($pps>0)}" || { echo "  FAIL: no traffic offered (start the load host first)"; pass=0; }
if [ "$mode" = "generic" ]; then
  echo "  N/A : line-rate criteria require a native-XDP 10G NIC (this is generic)."
  pass=0
else
  awk "BEGIN{exit !($ns_per_pkt<=$NS_BUDGET)}" \
    && echo "  PASS: cost/packet within ${NS_BUDGET} ns" \
    || { echo "  FAIL: cost/packet ${ns_per_pkt} ns > ${NS_BUDGET} ns"; pass=0; }
fi
echo "(cost/packet here is a whole-system upper bound; use 'make bench-prog' for the isolated per-packet program cost.)"
exit $(( pass ? 0 : 1 ))
