#!/usr/bin/env bash
# =============================================================================
# tune_network_stack.sh — network-stack optimization for xdp-sentinel.
# =============================================================================
# Deliverable alias for scripts/tune_host.sh, which already implements the full
# kernel + NIC + IRQ tuning described in the Benchmark & Bottleneck Report:
#   * net sysctls (netdev_max_backlog/budget, socket buffers, syncookies) —
#     persisted to /etc/sysctl.d/99-xdp-sentinel.conf; the real absorption
#     lever on a generic-XDP box.
#   * NIC RX/TX ring-max + RSS combined channels + LRO off (best-effort; the
#     ring/RSS/IRQ steps light up only on a multi-queue native-XDP NIC and are
#     safely skipped on the r8169).
#   * --pin-irqs (opt-in) IRQ affinity; --revert to remove the sysctl drop-in.
#
# All arguments pass straight through. See `tune_host.sh --help`.
# -----------------------------------------------------------------------------
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tune_host.sh" "$@"
