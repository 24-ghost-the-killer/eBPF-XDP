#!/usr/bin/env bash
# =============================================================================
# tune_host.sh — host / NIC / kernel tuning for an xdp-sentinel appliance
# =============================================================================
# Raises the host's packet-absorption ceiling (backlog, NIC rings, RSS, IRQ
# affinity) and sets safe net sysctls. Safe-by-default:
#   * never touches an interface's addressing (SSH/dashboard stay up);
#   * skips anything the NIC/kernel does not support (best-effort ethtool);
#   * idempotent — writes /etc/sysctl.d/99-xdp-sentinel.conf and re-applies;
#   * IRQ pinning is OPT-IN (--pin-irqs) because it is only a win on a
#     multi-queue NIC with spare cores, and can hurt a 1–2 core box.
#
# NOTE on this appliance's current hardware: a Realtek r8169 runs XDP in
# GENERIC (SKB) mode and is typically single-queue, so NIC ring/RSS/IRQ steps
# will mostly report "unsupported" — that is expected. The sysctls below still
# help, and the NIC steps light up automatically on an Intel/Mellanox NIC in
# native XDP mode.
#
# RX core-spreading is AUTO-DETECTED per NIC:
#   * multi-queue NIC (ethtool reports Combined > 1): HARDWARE RSS — set the
#     combined channel count and pin each RX IRQ to its own core, so XDP runs in
#     parallel across cores.
#   * single-queue NIC (e.g. the r8169 here): SOFTWARE RSS via RPS — spread the
#     one queue's RX softirq across cores in sysfs. (Note: on a 1 GbE link the
#     per-core ceiling already exceeds the ~1.49 Mpps the link can deliver, so
#     this mostly buys management-plane isolation, not more throughput.)
# Either way, --reserve-cores N keeps the top N cores off the RX set so the
# control plane (agent, SSH, dashboard) has dedicated CPU under a flood;
# --pin-agent also taskset-pins the running agent onto those reserved cores.
#
# Usage:
#   sudo bash scripts/tune_host.sh                      # tune + auto RSS/RPS, reserve 1 core
#   sudo bash scripts/tune_host.sh --iface enp1s0
#   sudo bash scripts/tune_host.sh --reserve-cores 2    # keep 2 cores for the control plane
#   sudo bash scripts/tune_host.sh --pin-agent          # also pin the agent to the reserved cores
#   sudo bash scripts/tune_host.sh --no-rxspread        # skip RSS/RPS core-spreading
#   sudo bash scripts/tune_host.sh --revert             # remove the sysctl drop-in
# -----------------------------------------------------------------------------
set -euo pipefail

SYSCTL_FILE=/etc/sysctl.d/99-xdp-sentinel.conf
CONFIG=${XS_CONFIG:-/etc/xdp-sentinel/config.toml}
IFACES=()
PIN_IRQS=no
REVERT=no
RESERVE=1          # cores kept off the RX set for the control plane
PIN_AGENT=no
RXSPREAD=yes       # auto RSS (multi-queue) or RPS (single-queue)

c(){ printf '\033[%sm' "$1"; }
info(){ printf '   %s\n' "$*"; }
ok(){ printf '   %s✓%s %s\n' "$(c '1;32')" "$(c 0)" "$*"; }
warn(){ printf '%s!! %s%s\n' "$(c '1;33')" "$*" "$(c 0)" >&2; }
die(){ printf '%sxx %s%s\n' "$(c '1;31')" "$*" "$(c 0)" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACES+=("$2"); shift 2;;
    --pin-irqs) PIN_IRQS=yes; shift;;
    --reserve-cores) RESERVE="$2"; shift 2;;
    --pin-agent) PIN_AGENT=yes; shift;;
    --no-rxspread) RXSPREAD=no; shift;;
    --revert) REVERT=yes; shift;;
    -h|--help) sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) die "unknown option: $1";;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)."
case "$RESERVE" in ''|*[!0-9]*) die "--reserve-cores must be a non-negative integer";; esac

if [ "$REVERT" = yes ]; then
  rm -f "$SYSCTL_FILE" && sysctl --system >/dev/null 2>&1 || true
  ok "removed $SYSCTL_FILE (NIC ring/RSS/IRQ changes are not persisted, so a reboot restores them)"
  exit 0
fi

# Interfaces: explicit --iface wins; else the agent's attached interfaces.
if [ "${#IFACES[@]}" -eq 0 ] && [ -r "$CONFIG" ]; then
  while IFS= read -r n; do [ -n "$n" ] && IFACES+=("$n"); done < <(
    awk -F'"' '/^[[:space:]]*name[[:space:]]*=/{print $2}' "$CONFIG")
fi
[ "${#IFACES[@]}" -gt 0 ] || die "no interfaces (pass --iface NIC, or populate $CONFIG)."

# =============================================================================
# 1. Kernel net sysctls (persisted)
# =============================================================================
# Rationale:
#  * netdev_max_backlog / netdev_budget[_usecs]: how many packets the softirq
#    path can queue/process per poll — the main generic-XDP absorption lever.
#  * rmem_max/wmem_max + tcp_rmem/tcp_wmem: socket buffers for THIS box's own
#    connections (dashboard, SSH); forwarded/bridged traffic does not use them.
#  * tcp_syncookies + tcp_max_syn_backlog: protect the box's OWN listeners.
#  * rp_filter is intentionally NOT set — on an L2 bridge it can drop legit
#    forwarded traffic; the dataplane's bogon-source check is the right tool.
cat > "$SYSCTL_FILE" <<'EOF'
# Managed by scripts/tune_host.sh — xdp-sentinel host tuning.
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.somaxconn = 4096
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
EOF
if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
  ok "applied net sysctls -> $SYSCTL_FILE (persists across reboot)"
else
  warn "some sysctls were rejected by this kernel (applied the rest); see: sysctl -p $SYSCTL_FILE"
fi

# =============================================================================
# 2. Per-NIC tuning (best-effort; skips what the driver doesn't support)
# =============================================================================
for IF in "${IFACES[@]}"; do
  # Resolve the physical NIC behind a VLAN/bridge member (ethtool wants the PHY).
  PHY="$IF"
  [ -e "/sys/class/net/$IF/lower_"* ] 2>/dev/null && PHY="$(basename "$(readlink -f /sys/class/net/"$IF"/lower_* 2>/dev/null | head -1)")"
  case "$IF" in *.*|vlan*) base="$(cat "/sys/class/net/$IF/../$IF/link" 2>/dev/null || true)";; esac
  [ -d "/sys/class/net/$PHY" ] || { warn "$IF: no such interface, skipping"; continue; }
  command -v ethtool >/dev/null || { warn "ethtool not installed (apt install ethtool) — skipping NIC rings/RSS"; break; }

  printf '\n%s== NIC: %s ==%s\n' "$(c '1;36')" "$PHY" "$(c 0)"

  # Driver + XDP capability note.
  drv="$(ethtool -i "$PHY" 2>/dev/null | awk -F': ' '/^driver/{print $2}' || true)"
  info "driver: ${drv:-unknown}  (native XDP + RSS/IRQ tuning apply mostly to ixgbe/i40e/mlx5)"

  # 2a. Maximize RX/TX ring buffers to the hardware max.
  rxmax="$(ethtool -g "$PHY" 2>/dev/null | awk '/^RX:/{print $2; exit}' || true)"
  # Current setting = the second "RX:" line (under "Current hardware settings").
  rxcur="$(ethtool -g "$PHY" 2>/dev/null | awk '/^RX:/{n++; if (n==2) {print $2; exit}}' || true)"
  if [ -n "${rxmax:-}" ] && [ "${rxcur:-}" = "$rxmax" ]; then
    # Already at max: don't resize again. On many drivers `ethtool -G` resets the
    # link, and xs-tune.timer re-runs this every few minutes.
    info "$PHY: RX/TX rings already at max ($rxmax)"
  elif [ -n "${rxmax:-}" ] && [ "$rxmax" -gt 0 ] 2>/dev/null; then
    ethtool -G "$PHY" rx "$rxmax" tx "$rxmax" 2>/dev/null \
      && ok "$PHY: RX/TX rings -> $rxmax" \
      || warn "$PHY: could not set rings (driver may be fixed-size)"
  else
    info "$PHY: ring resize unsupported (common on r8169) — skipped"
  fi

  # 2b. RX core-spreading — AUTO: hardware RSS on a multi-queue NIC, software
  #     RPS on a single-queue NIC. Reserve the top $RESERVE core(s) so the RX
  #     set is cores 0..usable-1 and the control plane keeps dedicated CPU.
  if [ "$RXSPREAD" = yes ]; then
    ncpu="$(nproc)"
    res=$RESERVE
    if [ "$res" -ge "$ncpu" ]; then res=$((ncpu - 1)); fi
    usable=$((ncpu - res)); if [ "$usable" -lt 1 ]; then usable=1; fi
    mask=$(printf '%x' $(( (1 << usable) - 1 )))   # CPU mask for cores 0..usable-1
    chmax="$(ethtool -l "$PHY" 2>/dev/null | awk '/^Combined:/{print $2; exit}' || true)"
    if [ -n "${chmax:-}" ] && [ "$chmax" -gt 1 ] 2>/dev/null; then
      # ---- multi-queue: HARDWARE RSS ----
      want=$usable; if [ "$want" -gt "$chmax" ]; then want=$chmax; fi
      if ethtool -L "$PHY" combined "$want" 2>/dev/null; then
        ok "$PHY: multi-queue NIC detected -> HARDWARE RSS, $want queues (reserved $res core(s))"
      else
        warn "$PHY: multi-queue, but could not set combined channels"
      fi
      systemctl stop irqbalance 2>/dev/null || true
      systemctl disable irqbalance 2>/dev/null || true
      cpu=0
      for irq in $(awk -v d="$PHY" '$0 ~ d {gsub(":","",$1); print $1}' /proc/interrupts); do
        printf '%x' $((1 << (cpu % usable))) > "/proc/irq/$irq/smp_affinity" 2>/dev/null \
          && info "$PHY irq $irq -> cpu $((cpu % usable))" || true
        cpu=$((cpu + 1))
      done
    else
      # ---- single-queue: SOFTWARE RSS via RPS ----
      n=0
      for q in /sys/class/net/"$PHY"/queues/rx-*/rps_cpus; do
        [ -e "$q" ] || continue
        if echo "$mask" > "$q" 2>/dev/null; then n=$((n + 1)); fi
      done
      echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
      for q in /sys/class/net/"$PHY"/queues/rx-*/rps_flow_cnt; do echo 4096 > "$q" 2>/dev/null || true; done
      for irq in $(awk -v d="$PHY" '$0 ~ d {gsub(":","",$1); print $1}' /proc/interrupts); do
        echo 0 > "/proc/irq/$irq/smp_affinity_list" 2>/dev/null || true
      done
      if [ "$n" -gt 0 ]; then
        ok "$PHY: single-queue NIC detected -> SOFTWARE RSS (RPS) across cores 0-$((usable - 1)) on $n queue(s) (reserved $res core(s))"
        [ "$usable" -lt "$ncpu" ] || info "$PHY: tip — pass --reserve-cores 1 to keep a core free for the control plane"
      else
        info "$PHY: single-queue and RPS unavailable — skipped"
      fi
    fi
  else
    info "$PHY: RX core-spreading disabled (--no-rxspread)"
  fi

  # 2c. Offloads that get in XDP's way: GRO/LRO coalesce frames and hide per-
  # packet signal. Turn LRO off always; leave GRO on for generic XDP (it runs
  # post-GRO anyway) — turn it off only in native mode on a capable NIC.
  ethtool -K "$PHY" lro off 2>/dev/null && info "$PHY: LRO off" || true
done

# =============================================================================
# 3. IRQ affinity (OPT-IN: only sensible on a multi-queue NIC with spare cores)
# =============================================================================
if [ "$PIN_IRQS" = yes ]; then
  ncpu="$(nproc)"
  if [ "$ncpu" -lt 2 ]; then
    warn "only $ncpu CPU — IRQ pinning skipped (nothing to spread across)."
  else
    systemctl stop irqbalance 2>/dev/null && systemctl disable irqbalance 2>/dev/null \
      && info "stopped irqbalance (it would undo manual pinning)" || true
    for IF in "${IFACES[@]}"; do
      PHY="$IF"; [ -d "/sys/class/net/$PHY" ] || continue
      cpu=0
      for irq in $(awk -v d="$PHY" '$0 ~ d {gsub(":","",$1); print $1}' /proc/interrupts); do
        printf '%x' $((1 << (cpu % ncpu))) > "/proc/irq/$irq/smp_affinity" 2>/dev/null \
          && info "$PHY irq $irq -> cpu $((cpu % ncpu))" || true
        cpu=$((cpu + 1))
      done
    done
    warn "IRQ pinning is NOT persisted across reboot — re-run with --pin-irqs, or add a systemd unit."
  fi
fi

# =============================================================================
# 4. Reserve core(s) for the control plane: pin the running agent onto the top
#    $RESERVE core(s) (the ones kept off the RX set above), so a flood's RX
#    softirq can never starve detection / SSH / the dashboard.
# =============================================================================
if [ "$PIN_AGENT" = yes ]; then
  ncpu="$(nproc)"; res=$RESERVE
  if [ "$res" -ge "$ncpu" ]; then res=$((ncpu - 1)); fi
  if [ "$res" -lt 1 ]; then
    warn "--pin-agent: nothing reserved (--reserve-cores 0); skipping agent pin."
  elif ! command -v taskset >/dev/null; then
    warn "--pin-agent: taskset not installed (apt install util-linux)."
  else
    lo=$((ncpu - res)); hi=$((ncpu - 1))
    apid="$(pgrep -f 'sentinel-agent --config' | head -1 || true)"
    if [ -n "${apid:-}" ]; then
      taskset -pc "$lo-$hi" "$apid" >/dev/null 2>&1 \
        && ok "pinned agent (pid $apid) -> reserved core(s) $lo-$hi" \
        || warn "could not pin agent pid $apid"
      info "to persist, add 'CPUAffinity=$lo-$hi' to the agent's systemd unit [Service] section"
    else
      warn "--pin-agent: no running 'sentinel-agent --config ...' process found."
    fi
  fi
fi

echo
ok "host tuning done. sysctls persist via $SYSCTL_FILE; NIC RSS/RPS/IRQ/affinity reset on reboot."
info "Revert the sysctls with:  sudo bash scripts/tune_host.sh --revert"
