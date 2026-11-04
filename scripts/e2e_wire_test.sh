#!/usr/bin/env bash
# =============================================================================
# e2e_wire_test.sh — full end-to-end, REAL-WIRE stress capture for xdp-sentinel.
# =============================================================================
# Isolated from the production NIC: an internal veth pair carries the attack.
#   veth-xs1 (sender) --- wire --- veth-xs0 (XDP-attached, device under test)
# Real frames are transmitted out veth-xs1; the live xdp_main.bpf.o RX-processes
# them on veth-xs0 and drops per the armed flags. tcpdump on BOTH ends:
#   input.pcap    = everything sent          (on veth-xs1)
#   survived.pcap = what XDP let through      (on veth-xs0, post-XDP)
#   dropped       = input - survived          (the mitigation, visible on the wire)
# Nothing touches enp1s0 / vlan10 / vlan20, so the management plane is untouched.
# -----------------------------------------------------------------------------
set -uo pipefail
IF0=veth-xs0; IF1=veth-xs1
OBJ=${XS_BPF_OBJ:-/usr/lib/xdp-sentinel/xdp_main.bpf.o}
CTL=${CTL:-sentinelctl}
OUT=${OUT:-/tmp/xs_e2e}; mkdir -p "$OUT"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENDER=${SENDER:-$SELF_DIR/e2e_send.py}
# repo pentest dir (script lives in <repo>/scripts); used by the sender's builders
export XS_PENTEST_DIR="${XS_PENTEST_DIR:-$(cd "$SELF_DIR/../pentest" 2>/dev/null && pwd)}"
N=${N:-40}

cleanup(){ "$CTL" detach -i "$IF0" --force >/dev/null 2>&1 || true; ip link del "$IF0" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== 1. fresh isolated veth pair =="
ip link del "$IF0" >/dev/null 2>&1 || true
ip link add "$IF0" type veth peer name "$IF1"
ip link set "$IF0" up; ip link set "$IF1" up
echo "   $IF0 <-> $IF1 up"

echo "== 2. attach live XDP program to $IF0 =="
"$CTL" attach -i "$IF0" --obj "$OBJ" --mode native 2>/dev/null && MODE=native || {
  "$CTL" attach -i "$IF0" --obj "$OBJ" --mode generic && MODE=generic; }
echo "   attach mode: ${MODE:-FAILED}"
"$CTL" status -i "$IF0" | grep -E "attach mode|program id" | sed 's/^/   /'
[ -n "${MODE:-}" ] || { echo "attach failed"; exit 1; }

echo "== 3. arm mitigation flags via CLI =="
"$CTL" config -i "$IF0" --drop-udp on --drop-bad-tcp-flags on --drop-fragments on \
       --drop-spoofed on --drop-malformed on >/dev/null
"$CTL" status -i "$IF0" | grep config: | sed 's/^/   /'

vstat(){ "$CTL" stats -i "$IF0" --prometheus 2>/dev/null | awk -v v="$1" '$0 ~ ("iface=\"'"$IF0"'\".*verdict=\""v"\""){print $NF; exit}'; }
drops_before=$(vstat drop); pass_before=$(vstat pass)

echo "== 4. start captures on both ends =="
tcpdump -i "$IF1" -w "$OUT/input.pcap"    -n >/dev/null 2>&1 & TD1=$!
tcpdump -i "$IF0" -w "$OUT/survived.pcap" -n >/dev/null 2>&1 & TD0=$!
sleep 1

echo "== 5. transmit real attack frames =="
python3 "$SENDER" "$IF1" "$N"

sleep 1
kill "$TD0" "$TD1" 2>/dev/null || true; wait "$TD0" "$TD1" 2>/dev/null || true

echo "== 6. results =="
drops_after=$(vstat drop); pass_after=$(vstat pass)
in_n=$(tcpdump -r "$OUT/input.pcap" -n 2>/dev/null | wc -l)
sv_n=$(tcpdump -r "$OUT/survived.pcap" -n 2>/dev/null | wc -l)
echo "   frames SENT (input.pcap)        : $in_n"
echo "   frames SURVIVED (survived.pcap) : $sv_n"
echo "   XDP verdict delta  drop: $(( ${drops_after:-0} - ${drops_before:-0} ))  pass: $(( ${pass_after:-0} - ${pass_before:-0} ))"
echo "   --- protocol on INPUT vs SURVIVED (shows what the dataplane removed) ---"
for p in "udp" "tcp" "ip[6:2]&0x3fff!=0"; do
  i=$(tcpdump -r "$OUT/input.pcap"    -n "$p" 2>/dev/null | wc -l)
  s=$(tcpdump -r "$OUT/survived.pcap" -n "$p" 2>/dev/null | wc -l)
  printf "   %-22s input=%-5s survived=%-5s\n" "$p" "$i" "$s"
done
echo "   pcaps: $OUT/input.pcap  $OUT/survived.pcap"
