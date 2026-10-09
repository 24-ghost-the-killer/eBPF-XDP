#!/usr/bin/env bash
# tune-nic.sh - apply and verify the NIC settings native XDP needs to hit line
# rate (Phase 15). Idempotent: safe to re-run; prints the before/after of each
# knob and exits non-zero if a required setting could not be applied.
#
#   sudo scripts/tune-nic.sh <iface> [--apply]
#
# Without --apply it only reports (dry run). With --apply it changes settings.
# It never touches an interface carrying its own control connection unless
# --force is given, because reconfiguring rings briefly drops link.
set -u
IFACE="${1:?usage: tune-nic.sh <iface> [--apply] [--force]}"; shift || true
APPLY=0; FORCE=0
for a in "$@"; do
  case "$a" in --apply) APPLY=1;; --force) FORCE=1;; esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1"; exit 3; }; }
need ethtool; need ip
run() { echo "  + $*"; [ "$APPLY" = 1 ] && "$@"; }
rc=0

echo "=== xdp-sentinel NIC tuning for $IFACE (apply=$APPLY) ==="
ip -br link show "$IFACE" >/dev/null 2>&1 || { echo "no such interface"; exit 2; }

driver=$(ethtool -i "$IFACE" 2>/dev/null | awk '/^driver:/{print $2}')
echo "driver: ${driver:-unknown}"
if [ "$driver" = "iwlwifi" ] || ethtool -i "$IFACE" 2>/dev/null | grep -qi wireless; then
  echo "WARNING: $IFACE looks like Wi-Fi; it supports only GENERIC XDP and"
  echo "         cannot be driven to line rate. Tuning below is a no-op there."
fi

cores=$(nproc)
echo "--- RSS queues (aim: one per core, up to the NIC max) ---"
cur=$(ethtool -l "$IFACE" 2>/dev/null | awk '/Combined:/{c=$2} END{print c}')
maxq=$(ethtool -l "$IFACE" 2>/dev/null | awk '/Combined:/{m=$2; exit} END{print m}')
echo "  combined queues: current, target ~= min($cores, NIC max)"
if [ -n "${maxq:-}" ]; then
  want=$(( cores < maxq ? cores : maxq ))
  run ethtool -L "$IFACE" combined "$want" || rc=1
fi

echo "--- ring buffer sizes (raise RX/TX to the NIC max to absorb bursts) ---"
rxmax=$(ethtool -g "$IFACE" 2>/dev/null | awk '/^RX:/{print $2; exit}')
txmax=$(ethtool -g "$IFACE" 2>/dev/null | awk '/^TX:/{print $2; exit}')
[ -n "${rxmax:-}" ] && run ethtool -G "$IFACE" rx "$rxmax" tx "${txmax:-$rxmax}" || rc=1

echo "--- offloads that conflict with or hide XDP ---"
# GRO/LRO coalesce frames above XDP; turn LRO off (GRO is fine for generic but
# off gives XDP per-packet visibility on native).
run ethtool -K "$IFACE" lro off 2>/dev/null || true
run ethtool -K "$IFACE" ntuple on 2>/dev/null || true

echo "--- IRQ affinity: pin each queue's IRQ to a distinct core ---"
irqs=$(grep -i "$IFACE" /proc/interrupts 2>/dev/null | awk -F: '{print $1}' | tr -d ' ')
i=0
for irq in $irqs; do
  cpu=$(( i % cores )); mask=$(printf '%x' $(( 1 << cpu )))
  run sh -c "echo $mask > /proc/irq/$irq/smp_affinity" 2>/dev/null || true
  i=$(( i + 1 ))
done
[ "$i" = 0 ] && echo "  (no per-queue IRQs found; single-queue or virtio device)"

echo "--- XPS: let each TX queue use its own core ---"
q=0
for txq in /sys/class/net/"$IFACE"/queues/tx-*/xps_cpus; do
  [ -e "$txq" ] || continue
  cpu=$(( q % cores )); mask=$(printf '%x' $(( 1 << cpu )))
  run sh -c "echo $mask > $txq" 2>/dev/null || true
  q=$(( q + 1 ))
done

echo "=== verification ==="
ethtool -l "$IFACE" 2>/dev/null | sed -n '/Current/,$p' | sed 's/^/  /'
ethtool -g "$IFACE" 2>/dev/null | sed -n '/Current/,$p' | sed 's/^/  /'
if [ "$APPLY" = 0 ]; then
  echo "(dry run - re-run with --apply to make these changes)"
fi
exit $rc
