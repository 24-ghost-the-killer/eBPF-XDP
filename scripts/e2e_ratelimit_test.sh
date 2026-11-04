#!/usr/bin/env bash
# =============================================================================
# e2e_ratelimit_test.sh — real-wire test WITH the rate-limiters enabled.
# =============================================================================
# Like e2e_wire_test.sh, but runs a DEDICATED agent instance on the veth so the
# risk engine (not just CLI drop flags) is in the loop: a sustained real flood
# escalates the ladder and arms global_rl + per-source ratelimit, which THROTTLE
# the flood to a survivable budget. Shows that an aggregate rate-limit sheds the
# flood down to ~CAP_PPS rather than hard-blocking everything.
# Isolated veth; production agent (vlan10/vlan20 on :9464) untouched.
# -----------------------------------------------------------------------------
set -uo pipefail
IF0=veth-xs0; IF1=veth-xs1
AGENT=${AGENT:-/usr/local/bin/sentinel-agent}
OBJ=${XS_BPF_OBJ:-/usr/lib/xdp-sentinel/xdp_main.bpf.o}
CTL=${CTL:-sentinelctl}
OUT=${OUT:-/tmp/xs_rl}; mkdir -p "$OUT"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOOD=${FLOOD:-$SELF_DIR/e2e_flood.py}
export XS_PENTEST_DIR="${XS_PENTEST_DIR:-$(cd "$SELF_DIR/../pentest" 2>/dev/null && pwd)}"
CFG=/tmp/veth-agent.toml
MPORT=9465
CAP_PPS=${CAP_PPS:-500}      # aggregate-cap budget for a clear demo
DUR=${DUR:-14}
APID=""

cleanup(){
  [ -n "$APID" ] && kill "$APID" 2>/dev/null || true
  sleep 1
  "$CTL" detach -i "$IF0" --force >/dev/null 2>&1 || true
  ip link del "$IF0" >/dev/null 2>&1 || true
  rm -f "$CFG"
}
trap cleanup EXIT

echo "== 1. isolated veth =="
ip link del "$IF0" >/dev/null 2>&1 || true
ip link add "$IF0" type veth peer name "$IF1"
ip link set "$IF0" up; ip link set "$IF1" up

echo "== 2. dedicated agent on $IF0 (risk engine + rate-limiters; cap=${CAP_PPS}pps) =="
cat > "$CFG" <<EOF
metrics_addr = "127.0.0.1:${MPORT}"
pin_root = "/sys/fs/bpf/xdp-sentinel"
bpf_obj = "${OBJ}"
[[interface]]
name = "${IF0}"
mode = "native"
attach = true
EOF
XS_AUTO_MITIGATE=1 XS_GLOBAL_RL_PPS="$CAP_PPS" nohup "$AGENT" --config "$CFG" > "$OUT/agent.log" 2>&1 &
APID=$!
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:${MPORT}/metrics" >/dev/null 2>&1 && break; sleep 0.5; done
"$CTL" status -i "$IF0" | grep -E "attach mode|program id|config:" | sed 's/^/   /'

echo "== 3. capture both ends (survived full; input sampled) =="
tcpdump -i "$IF1" -w "$OUT/input.pcap"    -n -c 30000 >/dev/null 2>&1 & TD1=$!
tcpdump -i "$IF0" -w "$OUT/survived.pcap" -n >/dev/null 2>&1 & TD0=$!
sleep 1

echo "== 4. sustained real UDP flood for ${DUR}s; watch the ladder arm global_rl =="
python3 "$FLOOD" "$IF1" udp_flood "$DUR" & FPID=$!
rlflag(){ curl -s "http://127.0.0.1:${MPORT}/metrics" | awk -v f="$1" '$0 ~ ("flag=\""f"\"") {print $NF; exit}'; }
rlval(){  curl -s "http://127.0.0.1:${MPORT}/metrics" | awk -v m="$1" '/^#/{next} $0 ~ m {print $NF; exit}'; }
for t in $(seq 1 "$DUR"); do
  printf "   t=%2ss risk_level=%s global_rl=%s ratelimit=%s drop_udp=%s\n" \
    "$t" "$(rlval xs_risk_level)" "$(rlflag global_rl)" "$(rlflag ratelimit)" "$(rlflag drop_udp)"
  sleep 1
done
wait "$FPID" 2>/dev/null || true

sleep 1; kill "$TD0" "$TD1" 2>/dev/null || true; wait "$TD0" "$TD1" 2>/dev/null || true

echo "== 5. result: input rate vs survived rate (throttling) =="
in_n=$(tcpdump -r "$OUT/input.pcap"    -n 2>/dev/null | wc -l | tr -d ' ')
sv_n=$(tcpdump -r "$OUT/survived.pcap" -n 2>/dev/null | wc -l | tr -d ' ')
sv_udp=$(tcpdump -r "$OUT/survived.pcap" -n udp 2>/dev/null | wc -l | tr -d ' ')
echo "   input.pcap (sampled, cap 30k): $in_n frames"
echo "   survived.pcap (ALL that passed over ${DUR}s): $sv_n frames  (UDP: $sv_udp)"
echo "   => survived UDP rate ~ $(( sv_udp / DUR )) pps  (aggregate cap target: ${CAP_PPS} pps)"
echo "   agent verdict counters:"; "$CTL" stats -i "$IF0" 2>/dev/null | awk '/verdict|rate_limited|pass|drop/{print "     "$0}' | head
echo "   pcaps: $OUT/input.pcap  $OUT/survived.pcap   agent log: $OUT/agent.log"
