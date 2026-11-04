#!/usr/bin/env bash
# =============================================================================
# ddos-test.sh — containerized multi-source UDP DDoS test for xdp-sentinel.
# =============================================================================
# Spins up N Docker attacker containers that simultaneously flood an ISOLATED
# veth (random-source UDP), where the real xdp_main.bpf.o is attached and a
# dedicated agent runs the risk engine. Shows the dataplane absorb a large,
# distributed-looking UDP attack. Nothing touches enp1s0/vlan10/vlan20, so the
# management plane is untouched.
#
#   sudo ATTACKERS=8 DUR=20 CAP_PPS=500 bash scripts/docker-ddos/ddos-test.sh
#
# Env: ATTACKERS (containers, default 6), DUR (seconds, default 20),
#      CAP_PPS (aggregate-cap budget, default 500).
# -----------------------------------------------------------------------------
set -uo pipefail
IF0=veth-xs0; IF1=veth-xs1
AGENT=${AGENT:-/usr/local/bin/sentinel-agent}
OBJ=${XS_BPF_OBJ:-/usr/lib/xdp-sentinel/xdp_main.bpf.o}
CTL=${CTL:-sentinelctl}
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export XS_PENTEST_DIR="${XS_PENTEST_DIR:-$(cd "$SELF_DIR/../../pentest" 2>/dev/null && pwd)}"
export XS_VICTIM=${XS_VICTIM:-10.123.0.2}
export ATK_IFACE=$IF1 ATK_VECTOR=${ATK_VECTOR:-udp_flood}
OUT=${OUT:-/tmp/xs_ddos}; mkdir -p "$OUT"
CFG=/tmp/veth-agent.toml; MPORT=9465
ATTACKERS=${ATTACKERS:-6}; export DUR=${DUR:-20}; CAP_PPS=${CAP_PPS:-500}
APID=""
DC(){ docker compose -f "$SELF_DIR/docker-compose.yml" "$@"; }

cleanup(){
  DC down --remove-orphans >/dev/null 2>&1 || true
  [ -n "$APID" ] && kill "$APID" 2>/dev/null || true; sleep 1
  "$CTL" detach -i "$IF0" --force >/dev/null 2>&1 || true
  ip link del "$IF0" >/dev/null 2>&1 || true
  rm -f "$CFG"
}
trap cleanup EXIT

echo "== 1. isolated veth (10.123.0.0/30) =="
ip link del "$IF0" >/dev/null 2>&1 || true
ip link add "$IF0" type veth peer name "$IF1"
ip addr add 10.123.0.2/30 dev "$IF0"; ip addr add 10.123.0.1/30 dev "$IF1"
ip link set "$IF0" up; ip link set "$IF1" up

echo "== 2. dedicated agent + live XDP on $IF0 (cap=${CAP_PPS}pps) =="
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
"$CTL" status -i "$IF0" | grep -E "attach mode|program id" | sed 's/^/   /'

echo "== 3. capture what SURVIVES on $IF0 (post-XDP) =="
tcpdump -i "$IF0" -w "$OUT/survived.pcap" -n >/dev/null 2>&1 & TD0=$!
sleep 1

echo "== 4. launch $ATTACKERS Docker attackers (random-source UDP, ${DUR}s) =="
DC up -d --scale attacker="$ATTACKERS" --remove-orphans 2>&1 | tail -3
echo "   running containers: $(DC ps -q | wc -l)"

echo "== 5. watch the dataplane absorb the attack =="
rlflag(){ curl -s "http://127.0.0.1:${MPORT}/metrics" | awk -v f="$1" '$0 ~ ("flag=\""f"\"") {print $NF; exit}'; }
rlval(){  curl -s "http://127.0.0.1:${MPORT}/metrics" | awk -v m="$1" '/^#/{next} $0 ~ m {print $NF; exit}'; }
vdrop(){ "$CTL" stats -i "$IF0" --prometheus 2>/dev/null | awk '/iface="'"$IF0"'".*verdict="drop"/{print $NF; exit}'; }
for t in $(seq 1 "$DUR"); do
  printf "   t=%2ss risk=%s global_rl=%s ratelimit=%s drop_udp=%s total_dropped=%s\n" \
    "$t" "$(rlval xs_risk_level)" "$(rlflag global_rl)" "$(rlflag ratelimit)" "$(rlflag drop_udp)" \
    "$(vdrop)"
  sleep 1
done

echo "== 6. stop attack & captures =="
DC down --remove-orphans >/dev/null 2>&1 || true
sleep 1; kill "$TD0" 2>/dev/null || true; wait "$TD0" 2>/dev/null || true

echo "== 7. result =="
sv_udp=$(tcpdump -r "$OUT/survived.pcap" -n udp 2>/dev/null | wc -l | tr -d ' ')
echo "   UDP that SURVIVED XDP over ${DUR}s: $sv_udp frames (~$(( sv_udp / DUR )) pps; cap target ${CAP_PPS})"
echo "   agent verdict counters:"; "$CTL" stats -i "$IF0" 2>/dev/null | awk '/verdict|rate_limited/{print "     "$0}' | head
echo "   dashboard (production) still up: $(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:9091/-/healthy)"
echo "   survived pcap: $OUT/survived.pcap   agent log: $OUT/agent.log"
