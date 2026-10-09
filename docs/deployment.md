# Deployment

The appliance runs on a plain Linux server under systemd. No container
runtime or orchestrator is in the packet path or required by the
dataplane.

## Supported platforms

Linux ≥ 6.1 with `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_SYSCALL=y`,
`CONFIG_BPF_JIT=y` (and `bpf_jit_enable=1`, the default on x86-64/arm64),
bpffs mounted at `/sys/fs/bpf` (systemd does this by default). Tested
distributions: Debian 12/13, Ubuntu 24.04. x86-64 is the target; arm64
works (the CI runs on arm64).

## Installed layout

```
/usr/bin/sentinelctl
/usr/bin/sentinel-agent                    (Phase 4)
/usr/bin/sentinel-inference                (Phase 10)
/usr/lib/xdp-sentinel/xdp_main.bpf.o       dataplane object (sentinelctl default --obj)
/etc/xdp-sentinel/config.toml              agent config (root:xs 0640)
/var/lib/xdp-sentinel/models/              model registry (read-only for inference)
/sys/fs/bpf/xdp-sentinel/<ifname>/         pinned program and maps
```

## Phase 1 operation (no agent yet)

```sh
# attach in native mode; maps are pinned and survive sentinelctl exiting
sudo sentinelctl attach -i ens1f0 --mode native
sudo sentinelctl status -i ens1f0
sudo sentinelctl stats  -i ens1f0 --interval 1          # live rates
sudo sentinelctl stats  -i ens1f0 --json                # for scripts
# opt-in validity mitigation (default: observe only)
sudo sentinelctl config -i ens1f0 --drop-malformed on --drop-bad-tcp-flags on
# block incoming UDP DNS requests to destination port 53 (only if this host
# is not serving DNS on that interface)
sudo sentinelctl config -i ens1f0 --drop-udp-dns on
# upgrade the program atomically, keeping counters and config
sudo sentinelctl attach -i ens1f0 --mode native --replace --obj ./xdp_main.bpf.o
# remove (emergency: this is the "off switch")
sudo sentinelctl detach -i ens1f0
```

Emergency without our tooling: `ip link set dev ens1f0 xdp off` (native
attachment) detaches the program; `rm -r /sys/fs/bpf/xdp-sentinel/ens1f0`
removes the pins.

## systemd units (Phase 4 onwards)

`deploy/systemd/sentinel-agent.service`:

```ini
[Unit]
Description=xdp-sentinel agent (dataplane control, telemetry, policy)
After=network-online.target sys-fs-bpf.mount
Wants=network-online.target

[Service]
Type=notify
User=xs
Group=xs
ExecStart=/usr/bin/sentinel-agent --config /etc/xdp-sentinel/config.toml
Restart=always
RestartSec=1
# Only the capabilities BPF and XDP need.
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
NoNewPrivileges=yes
LimitMEMLOCK=infinity
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf/xdp-sentinel /var/lib/xdp-sentinel
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service bpf perf_event_open
# Keep the control plane off the RX cores (see hardware-tuning.md D.1).
CPUAffinity=10-15
# The dataplane must survive the agent: never detach on stop.
KillMode=mixed

[Install]
WantedBy=multi-user.target
```

`deploy/systemd/sentinel-inference.service`: `DynamicUser=yes`,
`PrivateNetwork=yes`, `ReadOnlyPaths=/var/lib/xdp-sentinel/models`,
`RuntimeDirectory=xdp-sentinel` (for the Unix socket),
`CapabilityBoundingSet=` (empty), `MemoryMax=4G`, `CPUAffinity=14-15`.

Stopping the agent **does not detach** the dataplane: stopping a service
must never change forwarding. Detaching is an explicit operator action.

## Host preparation

`scripts/tune-nic.sh` (Phase 15) applies and verifies the settings from
[hardware-tuning.md](hardware-tuning.md): queue count, RSS hash fields,
IRQ pinning, ring sizes, LRO off, pause frames off, governor, C-states. It
is idempotent and prints a diff of what it changed.

## Upgrades

1. Build and verify: `make all test test-bpf` on a staging host with the
   same kernel.
2. `sentinelctl attach --replace` (or the agent's upgrade path) loads the
   new object through the verifier first, then swaps it atomically with
   `XDP_FLAGS_REPLACE`. On any error the old program keeps running.
3. Pinned maps are reused when their definitions are unchanged. A release
   that changes a map definition ships a migration (dump → new map →
   swap) and says so in its release notes.

For a direct upgrade from a checkout, `scripts/deploy-xdp.sh` syncs the source
to a temporary directory on the Linux server, builds there, installs
`sentinelctl`, `sentinel-agent`, and the BPF object, then replaces the program
on the selected interface. For example:

```sh
scripts/deploy-xdp.sh xs@10.0.0.12 ens1f0 native
```

The interface and attach mode must match the server (`native` is the default;
use `generic` where driver-mode XDP is unavailable). The script preserves
`/etc/xdp-sentinel/config.toml`, restarts `sentinel-agent` only if it is
already active, and prints the resulting interface status. The server needs
the Linux build dependencies listed at the top of the [Makefile](../Makefile),
`rsync`, SSH access, and sudo permission. The selected interface must already
have this project's XDP program attached; initial installation is not an
`--replace` operation. Run the documented staging tests before production
upgrades.

## Monitoring (Phase 1 interim: `deploy/monitoring/`)

Until `sentinel-agent` exports `/metrics` (Phase 4), counters reach
Prometheus through node_exporter's textfile collector:

```
XDP per-CPU counters ──sentinelctl stats --prometheus──▶ xs-textfile-exporter (systemd, every 5 s)
   ──▶ /var/lib/xdp-sentinel/textfile/xdp-sentinel-<if>.prom ──▶ node_exporter :9101
   ──▶ Prometheus :9091 (15 d, rules/alerts) ──▶ Grafana :3001 (provisioned dashboard)
```

Metric names already follow [observability.md](observability.md), so the
dashboard and rules keep working when the agent takes over.

The stack is independent of any other Prometheus on the host (own ports,
volumes, config) and binds to 127.0.0.1 only. Install:

```sh
sudo install -D -m 0755 target/release/sentinelctl /usr/local/bin/sentinelctl
sudo install -D -m 0755 deploy/monitoring/xs-textfile-exporter /usr/local/lib/xdp-sentinel/xs-textfile-exporter
sudo install -m 0644 deploy/systemd/xs-textfile-exporter.service /etc/systemd/system/
echo 'XS_IFACES=<iface>' | sudo tee /etc/xdp-sentinel/exporter.env
sudo systemctl daemon-reload && sudo systemctl enable --now xs-textfile-exporter

sudo cp -r deploy/monitoring /opt/xdp-sentinel/monitoring
cd /opt/xdp-sentinel/monitoring
sudo sh -c 'umask 077; echo "GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 18)" > .env'
sudo docker compose up -d
```

By default Grafana listens only on localhost. To update an existing install
for Twingate, run these from the repository checkout on the server:

```sh
sudo cp deploy/monitoring/docker-compose.yml /opt/xdp-sentinel/monitoring/
sudo cp deploy/monitoring/grafana/dashboards/xdp-sentinel-dataplane.json /opt/xdp-sentinel/monitoring/grafana/dashboards/
sudoedit /opt/xdp-sentinel/monitoring/.env
```

Set `GRAFANA_HTTP_ADDR` in `.env` to the server's private IP address used by
its Twingate resource, then apply the setting from the stack directory:

```sh
cd /opt/xdp-sentinel/monitoring
sudo docker compose up -d
```

Open `http://<server-private-ip>:3001` from a device connected to Twingate
(user `admin`, password in `/opt/xdp-sentinel/monitoring/.env`). Grant access
to this resource in the Twingate policy. Keep the host firewall restricted to
trusted/private networks; do not forward port 3001 from the public internet.
To keep Grafana local-only, leave `GRAFANA_HTTP_ADDR` unset and use
`ssh -L 3001:127.0.0.1:3001 <user>@<host>`, then open http://localhost:3001.

The dashboard is generated: edit `deploy/monitoring/grafana/build_dashboard.py`
and regenerate `grafana/dashboards/xdp-sentinel-dataplane.json`; Grafana
reloads provisioned files within ~10 s. Alert rules are in
`prometheus/rules/xdp-sentinel.yml` (validate with `promtool check config`);
no Alertmanager is deployed yet, so firing alerts are visible in Prometheus
(`/alerts`) and Grafana only.
