#!/usr/bin/env bash
# xdp-selftest-load.sh - stress-test the dataplane entirely ON the box, with no
# external traffic. Useful when you are off the LAN (Twingate cannot reach the
# XDP hook). It creates a veth pair, attaches the real xdp_main program to one
# end in NATIVE mode (veth supports it, unlike Wi-Fi), and blasts frames at it
# from the other end with the in-kernel packet generator (pktgen) at millions
# of pps. Watch the drops climb in `sentinelctl stats` / Grafana in real time.
#
#   sudo scripts/xdp-selftest-load.sh [seconds] [pps_flags...]
#
# Env:
#   OBJ=ebpf/build/xdp_main.bpf.o   compiled program (default)
#   CTL=sentinelctl                 control tool
#   RATELIMIT=20000                 per-source pps limit to arm (0 = none)
#   DROP_UDP=1                      also arm drop_udp (service-port UDP)
#   COUNT=20000000                  packets to send (0 = for the whole duration)
set -eu

DUR="${1:-15}"
OBJ="${OBJ:-ebpf/build/xdp_main.bpf.o}"
CTL="${CTL:-sentinelctl}"
RATELIMIT="${RATELIMIT:-20000}"
DROP_UDP="${DROP_UDP:-0}"
COUNT="${COUNT:-0}"
NS=xsload
VE=xsl0          # XDP end (root ns)
VP=xsl1          # generator end (in $NS)
PING_IP=10.244.0.1
DST_IP=10.244.0.2
PIN=/sys/fs/bpf/xdp-sentinel/$VE

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$OBJ" ] || { echo "no program object at $OBJ (run 'make -C ebpf')"; exit 2; }

cleanup() {
  set +e
  "$CTL" detach -i "$VE" --force >/dev/null 2>&1
  ip link del "$VE" >/dev/null 2>&1
  ip netns del "$NS" >/dev/null 2>&1
  echo "cleaned up."
}
trap cleanup EXIT

echo "=== building veth $VE <-> $VP (netns $NS) ==="
ip netns add "$NS"
ip link add "$VE" type veth peer name "$VP" netns "$NS"
ip addr add "$PING_IP/24" dev "$VE"
ip link set "$VE" up
ip -n "$NS" addr add "$DST_IP/24" dev "$VP"
ip -n "$NS" link set "$VP" up
ip -n "$NS" link set lo up

echo "=== attaching xdp_main to $VE in NATIVE mode ==="
"$CTL" attach -i "$VE" --obj "$OBJ" --mode native
if [ "$RATELIMIT" != 0 ]; then "$CTL" ratelimit -i "$VE" --pps "$RATELIMIT"; fi
if [ "$DROP_UDP" = 1 ]; then "$CTL" config -i "$VE" --drop-udp on; fi
"$CTL" status -i "$VE" | grep -E "mode|program id|config" | sed 's/^/  /'

echo "=== pktgen flood from $VP -> $VE for ${DUR}s ==="
modprobe pktgen 2>/dev/null || { echo "pktgen module unavailable; falling back to flood.py"; USE_FLOOD=1; }

before=$("$CTL" stats -i "$VE" --prometheus 2>/dev/null | awk '/xs_rx_packets_total/{print $NF}')

if [ "${USE_FLOOD:-0}" = 1 ]; then
  ip netns exec "$NS" python3 benchmarks/stress/flood.py udp "$PING_IP" -p 80 -d "$DUR" -w "$(nproc)" || true
else
  PG=/proc/net/pktgen
  pgset() { echo "$1" > "$2"; }
  ip netns exec "$NS" bash -c '
    PG=/proc/net/pktgen
    echo "rem_device_all" > $PG/kpktgend_0 2>/dev/null || true
    echo "add_device '"$VP"'@'"$NS"'" > $PG/kpktgend_0 2>/dev/null || \
      echo "add_device '"$VP"'" > $PG/kpktgend_0
    D=$PG/'"$VP"'
    echo "count '"$COUNT"'"        > $D
    echo "pkt_size 64"             > $D
    echo "dst '"$PING_IP"'"        > $D
    echo "dst_mac $(cat /sys/class/net/'"$VP"'/address)" > $D
    echo "flag QUEUE_MAP_CPU"      > $D
  ' 2>/dev/null || { echo "pktgen setup failed; use USE_FLOOD=1"; USE_FLOOD=1; }
  # Run pktgen for the duration, then stop.
  ( sleep "$DUR"; echo stop > /proc/net/pktgen/pgctrl 2>/dev/null ) &
  ip netns exec "$NS" bash -c 'echo start > /proc/net/pktgen/pgctrl' 2>/dev/null || \
    echo "start via pgctrl failed"
fi

after=$("$CTL" stats -i "$VE" --prometheus 2>/dev/null | awk '/xs_rx_packets_total/{print $NF}')
echo "=== result on $VE ==="
"$CTL" stats -i "$VE" 2>/dev/null | grep -E "rx|verdict|rate_limited" | sed 's/^/  /'
echo "  (rx delta this run: $(( ${after:-0} - ${before:-0} )) packets)"
echo "Watch live in another shell:  sudo $CTL stats -i $VE --interval 1"
