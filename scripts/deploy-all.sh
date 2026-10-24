#!/usr/bin/env bash
# deploy-all.sh - one-shot deploy of everything staged in ~/xs-stage:
#   new sentinelctl + sentinel-agent + XDP object, reorder + service-allowlist,
#   the ufw-sync automation, the rebuilt dashboard, and the ufw->allowlist sync.
#
# Run as the normal user (NOT `sudo bash`): the script sudo's the individual
# root steps itself, so the dashboard swap keeps running as you. One sudo
# password prompt is cached for the rest.
#
#   bash ~/xs-stage/deploy-all.sh
#
# Backups are left in ~ (xdp_main.bpf.o.bak, sentinelctl.bak, sentinel-agent.bak)
# and the previous dashboard as ~/xdp-sentinel-dashboard.bak.<ts>.
set -euo pipefail

STAGE=~/xs-stage
OBJ=/usr/lib/xdp-sentinel/xdp_main.bpf.o
IFACES="vlan10 vlan20"
PROTECT_IP=192.168.1.193          # the box's own IP, from protect.conf
PROTECT_IF=vlan10

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*" >&2; }

on_err() {
  warn "deploy failed. Roll back the dataplane with:"
  cat >&2 <<EOF
  sudo install -m0644 ~/xdp_main.bpf.o.bak $OBJ
  sudo cp ~/sentinelctl.bak /usr/local/bin/sentinelctl
  sudo cp ~/sentinel-agent.bak /usr/local/bin/sentinel-agent
  for i in $IFACES; do sudo sentinelctl attach --iface \$i --obj $OBJ --mode generic --replace; done
  sudo systemctl restart sentinel-agent
  ~/swap-dashboard.sh rollback   # if the dashboard was already swapped
EOF
}
trap on_err ERR

cd "$STAGE"

say "1/7 backup current artifacts"
sudo cp -f "$OBJ" ~/xdp_main.bpf.o.bak
cp -f /usr/local/bin/sentinelctl   ~/sentinelctl.bak
cp -f /usr/local/bin/sentinel-agent ~/sentinel-agent.bak

say "2/7 install binaries, object and automation"
sudo install -m0755 target/release/sentinelctl    /usr/local/bin/sentinelctl
sudo install -m0755 target/release/sentinel-agent /usr/local/bin/sentinel-agent
sudo install -m0644 ebpf/build/xdp_main.bpf.o     "$OBJ"
sudo install -m0755 scripts/xs-ufw-sync           /usr/local/sbin/xs-ufw-sync
sudo install -m0644 deploy/systemd/xdp-sentinel-ufw-sync.service /etc/systemd/system/
sudo install -m0644 deploy/systemd/xdp-sentinel-ufw-sync.path    /etc/systemd/system/
sudo systemctl daemon-reload

say "3/7 reload the XDP dataplane (atomic --replace)"
for i in $IFACES; do
  sudo sentinelctl attach --iface "$i" --obj "$OBJ" --mode generic --replace
done

say "4/7 restart the agent and wait for it to re-attach"
sudo systemctl restart sentinel-agent
for _ in $(seq 30); do
  sudo test -e "/sys/fs/bpf/xdp-sentinel/$PROTECT_IF/xs_service_v4" && break
  sleep 1
done
sudo test -e "/sys/fs/bpf/xdp-sentinel/$PROTECT_IF/xs_service_v4" \
  || { warn "service map never appeared; agent did not attach"; false; }

say "5/7 swap in the rebuilt dashboard"
~/swap-dashboard.sh

say "6/7 apply ufw -> allowlist (and protect $PROTECT_IP per protect.conf)"
sudo systemctl start xdp-sentinel-ufw-sync.service || warn "ufw-sync reported a problem (see: journalctl -u xdp-sentinel-ufw-sync)"
sudo systemctl enable --now xdp-sentinel-ufw-sync.path >/dev/null 2>&1 || true

say "7/7 safety check: is the box's own outbound still working?"
# .193 is the box itself; the stateless allowlist can drop replies to its own
# outbound connections. SSH (inbound) survives regardless. If outbound DNS is
# dead, lift default-deny on the box automatically so nothing is left broken.
if timeout 5 getent hosts deb.debian.org >/dev/null 2>&1 \
   || timeout 5 getent hosts one.one.one.one >/dev/null 2>&1; then
  echo "outbound OK"
else
  warn "box outbound resolution is failing after protecting $PROTECT_IP."
  warn "rolling back default-deny on $PROTECT_IP (comment it out of /etc/xdp-sentinel/protect.conf to keep it off)."
  sudo sentinelctl unprotect -i "$PROTECT_IF" "$PROTECT_IP" || true
fi

trap - ERR
say "done"
echo "dataplane:"; sudo sentinelctl status --iface "$PROTECT_IF" | sed 's/^/  /'
echo "dashboard: $(systemctl is-active xdp-dashboard)  ->  http://192.168.1.193:3000/analytics/protect"
echo "agent:     $(systemctl is-active sentinel-agent)"
