#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Traffic GENERATOR side (run on a separate machine, never on the DUT).
# Drives the in-kernel pktgen module: one kernel thread per TX queue, UDP
# frames of a fixed size, randomised source address/ports so the DUT's RSS
# spreads the load over all RX queues.
#
#   pktgen_tx.sh -i <iface> -d <dst_ip> -m <dst_mac> [-s <wire size>] [-t threads]
#                [-n count per thread (0 = forever)] [-r src range, e.g. 10.0.0.0/16]
#
# A single modern core usually generates 3-7 Mpps with pktgen; 14.88 Mpps
# (10GbE, 64 B) needs several threads and a NIC with enough TX queues.
# Measure what the generator actually achieved (printed at the end) and
# compare it with what the DUT received: a DUT result is only valid if the
# generator was not the bottleneck. For reproducible multi-profile runs
# (IMIX, SYN floods at fixed rates, latency) use TRex; see docs/performance.md.
set -euo pipefail

SIZE=64; THREADS=4; COUNT=0; SRC_RANGE=10.0.0.0/16
while getopts "i:d:m:s:t:n:r:" o; do
	case $o in
	i) IFACE=$OPTARG ;; d) DST=$OPTARG ;; m) DMAC=$OPTARG ;; s) SIZE=$OPTARG ;;
	t) THREADS=$OPTARG ;; n) COUNT=$OPTARG ;; r) SRC_RANGE=$OPTARG ;;
	*) sed -n '4,20p' "$0"; exit 2 ;;
	esac
done
: "${IFACE:?-i required}" "${DST:?-d required}" "${DMAC:?-m required}"
(( SIZE >= 64 && SIZE <= 1518 )) || { echo "wire size must be 64..1518"; exit 2; }

modprobe pktgen
PG=/proc/net/pktgen
pgset() { echo "$2" > "$1"; local r; r=$(grep -m1 "Result:" "$1" || true); [[ $r == *OK* || -z $r ]] || { echo "$1: $2 -> $r"; exit 1; }; }

python3 - "$SRC_RANGE" > /tmp/xs_pktgen_range <<'PY'
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1])
print(n[0], n[-1])
PY
read -r SRC_MIN SRC_MAX < /tmp/xs_pktgen_range

echo "reset" > $PG/pgctrl
for ((t = 0; t < THREADS; t++)); do
	dev="$IFACE@$t"
	pgset "$PG/kpktgend_$t" "rem_device_all"
	pgset "$PG/kpktgend_$t" "add_device $dev"
	pgset "$PG/$dev" "count $COUNT"
	pgset "$PG/$dev" "clone_skb 1000"      # reuse skbs: generator efficiency
	pgset "$PG/$dev" "pkt_size $((SIZE - 4))" # pktgen size excludes the FCS
	pgset "$PG/$dev" "burst 32"
	pgset "$PG/$dev" "delay 0"
	pgset "$PG/$dev" "queue_map_min $t"
	pgset "$PG/$dev" "queue_map_max $t"
	pgset "$PG/$dev" "dst $DST"
	pgset "$PG/$dev" "dst_mac $DMAC"
	pgset "$PG/$dev" "src_min $SRC_MIN"
	pgset "$PG/$dev" "src_max $SRC_MAX"
	pgset "$PG/$dev" "flag IPSRC_RND"
	pgset "$PG/$dev" "udp_src_min 1024"
	pgset "$PG/$dev" "udp_src_max 65535"
	pgset "$PG/$dev" "flag UDPSRC_RND"
	pgset "$PG/$dev" "udp_dst_min 9"
	pgset "$PG/$dev" "udp_dst_max 9"
done

echo "pktgen: $THREADS threads, ${SIZE}B frames on the wire, Ctrl-C to stop"
trap 'echo stop > $PG/pgctrl' INT TERM
echo start > $PG/pgctrl || true
for ((t = 0; t < THREADS; t++)); do
	grep -h -A2 "Result:" "$PG/$IFACE@$t" | head -3
done
