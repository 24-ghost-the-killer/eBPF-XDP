#!/usr/bin/env bash
# Install the auto-detecting host/NIC tuner as a system service, so the
# appliance self-configures RSS (multi-queue) or RPS (single-queue) + a
# reserved control-plane core on every boot. Idempotent; run as root.
set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNITS="$(cd "$SELF_DIR/../deploy/systemd" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

install -m 0755 "$SELF_DIR/tune_host.sh" /usr/local/sbin/tune_host.sh
install -m 0644 "$UNITS/xs-tune.service" /etc/systemd/system/xs-tune.service
install -m 0644 "$UNITS/xs-tune.timer"   /etc/systemd/system/xs-tune.timer
systemctl daemon-reload
systemctl enable --now xs-tune.service xs-tune.timer
echo "installed. current state:"
systemctl --no-pager status xs-tune.service | sed -n '1,4p' || true
echo "--- last tune run output ---"
journalctl -u xs-tune.service --no-pager -n 20 2>/dev/null || true
