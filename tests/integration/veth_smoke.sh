#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end smoke test of the Phase 1 dataplane on a veth pair, using
# native (driver-mode) XDP, which veth supports.
#
#   root netns: xs0 (10.99.0.1)  <-- XDP attached here
#   netns xs-ns: xs1 (10.99.0.2) --> sends traffic to xs0
#
# Requires root, iproute2, python3, a bpffs, and the built artefacts:
#   ebpf/build/xdp_main.bpf.o, target/release/sentinelctl
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTL=${CTL:-$ROOT/target/release/sentinelctl}
OBJ=${OBJ:-$ROOT/ebpf/build/xdp_main.bpf.o}
PIN_ROOT=${PIN_ROOT:-/sys/fs/bpf/xdp-sentinel-test}
NS=xs-ns-$$
SEND="ip netns exec $NS python3 $ROOT/tests/integration/send_frames.py xs1"
PASS=0
FAIL=0

cleanup() {
	"$CTL" --pin-root "$PIN_ROOT" detach -i xs0 >/dev/null 2>&1 || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del xs0 2>/dev/null || true
	rm -rf "$PIN_ROOT"
}
trap cleanup EXIT

check() { # description, condition (arithmetic expression)
	if (( $2 )); then
		echo "ok   - $1"
		PASS=$((PASS + 1))
	else
		echo "FAIL - $1  [$2]"
		FAIL=$((FAIL + 1))
	fi
}

counter() { # json, name, field
	python3 -c 'import json,sys; print(json.loads(sys.argv[1])["counters"][sys.argv[2]][sys.argv[3]])' "$1" "$2" "$3"
}

stats() { "$CTL" --pin-root "$PIN_ROOT" stats -i xs0 --json; }

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

ip netns add "$NS"
ip link add xs0 type veth peer name xs1
ip link set xs1 netns "$NS"
ip addr add 10.99.0.1/24 dev xs0
ip -6 addr add fd00::1/64 dev xs0 nodad
ip link set xs0 up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev xs1
ip netns exec "$NS" ip -6 addr add fd00::2/64 dev xs1 nodad
ip netns exec "$NS" ip link set xs1 up
ip netns exec "$NS" ip link set lo up
MAC=$(cat /sys/class/net/xs0/address)

echo "# attach (native mode)"
"$CTL" --pin-root "$PIN_ROOT" attach -i xs0 --obj "$OBJ" --mode native
STATUS=$("$CTL" --pin-root "$PIN_ROOT" status -i xs0)
echo "$STATUS"
check "program attached in native mode" "$(echo "$STATUS" | grep -c 'attach mode: native') == 1"
check "pinned program is the attached one" "$(echo "$STATUS" | grep -c '(attached)') == 1"

echo "# legitimate traffic passes with default config"
PING_OK=0; ip netns exec "$NS" ping -c 5 -i 0.2 -W 1 10.99.0.1 >/dev/null && PING_OK=1
check "ping succeeds through XDP" "$PING_OK == 1"
S=$(stats)
check "ICMP echo counted (>= 5)" "$(counter "$S" l4_icmp packets) >= 5"
check "nothing dropped by default" "$(counter "$S" verdict_drop packets) == 0"

echo "# malformed and anomalous frames are classified, still passed"
$SEND "$MAC" xmas 10
$SEND "$MAC" tcp_trunc 7
$SEND "$MAC" udp_len_bad 5
$SEND "$MAC" udp53 5
$SEND "$MAC" ipv6_frag_later 3
sleep 0.2
S=$(stats)
check "xmas scans counted (10)" "$(counter "$S" anom_tcp_bad_flags packets) == 10"
check "truncated TCP counted (7)" "$(counter "$S" parse_err_tcp_trunc packets) == 7"
check "bad UDP length counted (5)" "$(counter "$S" parse_err_udp_len packets) == 5"
check "UDP packets counted (including fragments)" "$(counter "$S" l4_udp packets) >= 5"
check "IPv6 non-first fragments counted (3)" "$(counter "$S" frag_later packets) >= 3"
check "still nothing dropped" "$(counter "$S" verdict_drop packets) == 0"

echo "# enable validity mitigation"
"$CTL" --pin-root "$PIN_ROOT" config -i xs0 --drop-bad-tcp-flags on --drop-malformed on --drop-udp-dns on
BEFORE=$(counter "$(stats)" verdict_drop packets)
$SEND "$MAC" xmas 10
$SEND "$MAC" tcp_trunc 4
$SEND "$MAC" udp53 5
$SEND "$MAC" syn 6
sleep 0.2
S=$(stats)
check "xmas + truncated + UDP/53 dropped (19)" "$(counter "$S" verdict_drop packets) - $BEFORE == 19"
PING_OK=0; ip netns exec "$NS" ping -c 3 -i 0.2 -W 1 10.99.0.1 >/dev/null && PING_OK=1
check "legitimate ping unaffected by strict mode" "$PING_OK == 1"

echo "# counters are consistent"
S=$(stats)
RX=$(counter "$S" rx packets)
V=$(( $(counter "$S" verdict_pass packets) + $(counter "$S" verdict_drop packets) ))
check "rx ($RX) == pass + drop ($V)" "$RX == $V"

echo "# atomic replace keeps pinned counters and config"
"$CTL" --pin-root "$PIN_ROOT" attach -i xs0 --obj "$OBJ" --mode native --replace
S=$(stats)
check "counters survived replace" "$(counter "$S" rx packets) >= $RX"
check "config survived replace" "$("$CTL" --pin-root "$PIN_ROOT" status -i xs0 | grep -c 'drop_malformed|drop_bad_tcp_flags|drop_udp_dns') == 1"

echo "# refuses to attach over an existing program without --replace"
if "$CTL" --pin-root "$PIN_ROOT" attach -i xs0 --obj "$OBJ" --mode native 2>/dev/null; then
	check "second attach refused" "0"
else
	check "second attach refused" "1"
fi

echo "# detach"
"$CTL" --pin-root "$PIN_ROOT" detach -i xs0
check "no XDP program left on xs0" "$(ip link show xs0 | grep -c 'prog/xdp') == 0"
check "pins removed" "$(ls "$PIN_ROOT" 2>/dev/null | wc -l) == 0"

echo
echo "veth smoke: $PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
