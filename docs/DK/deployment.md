<!-- Sprog: **Dansk** · [English](../EN/deployment.md) -->

# Deployment

Appliancen kører på en almindelig Linux-server under systemd. Ingen
container-runtime eller orchestrator er i pakke-stien eller krævet af dataplanet.

## Understøttede platforme

Linux ≥ 6.1 med `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_SYSCALL=y`,
`CONFIG_BPF_JIT=y` (og `bpf_jit_enable=1`, standarden på x86-64/arm64), bpffs
monteret på `/sys/fs/bpf` (systemd gør dette som standard). Testede
distributioner: Debian 12/13, Ubuntu 24.04. x86-64 er target'et; arm64 virker
(CI kører på arm64).

## Installeret layout

```
/usr/bin/sentinelctl
/usr/bin/sentinel-agent                    (Fase 4)
/usr/bin/sentinel-inference                (Fase 10)
/usr/lib/xdp-sentinel/xdp_main.bpf.o       dataplan-objekt (sentinelctl standard --obj)
/etc/xdp-sentinel/config.toml              agent-konfig (root:xs 0640)
/var/lib/xdp-sentinel/models/              model-register (read-only for inferens)
/sys/fs/bpf/xdp-sentinel/<ifname>/         pinnet program og maps
```

## Fase 1-drift (ingen agent endnu)

```sh
# attach i native mode; maps pinnes og overlever at sentinelctl afslutter
sudo sentinelctl attach -i ens1f0 --mode native
sudo sentinelctl status -i ens1f0
sudo sentinelctl stats  -i ens1f0 --interval 1          # live rates
sudo sentinelctl stats  -i ens1f0 --json                # til scripts
# opt-in validitets-mitigering (standard: kun observér)
sudo sentinelctl config -i ens1f0 --drop-malformed on --drop-bad-tcp-flags on
# blokér indkommende UDP-DNS-forespørgsler til destinationsport 53 (kun hvis denne
# host ikke serverer DNS på det interface)
sudo sentinelctl config -i ens1f0 --drop-udp-dns on
# opgradér programmet atomisk, behold tællere og konfig
sudo sentinelctl attach -i ens1f0 --mode native --replace --obj ./xdp_main.bpf.o
# fjern (nødsituation: dette er "off-switchen")
sudo sentinelctl detach -i ens1f0
```

Nødsituation uden vores værktøj: `ip link set dev ens1f0 xdp off` (native
attachment) detacher programmet; `rm -r /sys/fs/bpf/xdp-sentinel/ens1f0` fjerner
pins.

## systemd-units (Fase 4 og frem)

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
# Kun de capabilities BPF og XDP har brug for.
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
# Hold control plane væk fra RX-cores (se hardware-tuning.md D.1).
CPUAffinity=10-15
# Dataplanet skal overleve agenten: detach aldrig ved stop.
KillMode=mixed

[Install]
WantedBy=multi-user.target
```

`deploy/systemd/sentinel-inference.service`: `DynamicUser=yes`,
`PrivateNetwork=yes`, `ReadOnlyPaths=/var/lib/xdp-sentinel/models`,
`RuntimeDirectory=xdp-sentinel` (til Unix-socketen), `CapabilityBoundingSet=`
(tom), `MemoryMax=4G`, `CPUAffinity=14-15`.

At stoppe agenten **detacher ikke** dataplanet: at stoppe en service må aldrig
ændre forwarding. Detach er en eksplicit operatørhandling.

## Host-forberedelse

`scripts/tune-nic.sh` (Fase 15) anvender og verificerer indstillingerne fra
[hardware-tuning.md](hardware-tuning.md): kø-antal, RSS-hash-felter,
IRQ-pinning, ring-størrelser, LRO slået fra, pause-frames slået fra, governor,
C-states. Den er idempotent og printer en diff af hvad den ændrede.

## Opgraderinger

1. Byg og verificér: `make all test test-bpf` på en staging-host med samme kerne.
2. `sentinelctl attach --replace` (eller agentens opgraderingssti) loader det nye
   objekt gennem verifieren først, og bytter det så atomisk med
   `XDP_FLAGS_REPLACE`. Ved enhver fejl fortsætter det gamle program med at køre.
3. Pinnede maps genbruges når deres definitioner er uændrede. En release der
   ændrer en map-definition leverer en migration (dump → nyt map → swap) og siger
   det i sine release notes.

Til en direkte opgradering fra et checkout synkroniserer `scripts/deploy-xdp.sh`
kildekoden til en midlertidig mappe på Linux-serveren, bygger der, installerer
`sentinelctl`, `sentinel-agent` og BPF-objektet, og erstatter så programmet på
det valgte interface. For eksempel:

```sh
scripts/deploy-xdp.sh xs@10.0.0.12 ens1f0 native
```

Interfacet og attach-mode skal matche serveren (`native` er standard; brug
`generic` hvor driver-mode-XDP er utilgængelig). Scriptet bevarer
`/etc/xdp-sentinel/config.toml`, genstarter kun `sentinel-agent` hvis den allerede
er aktiv, og printer det resulterende interface-status. Serveren har brug for de
Linux-byggeafhængigheder der er listet øverst i [Makefile](../../Makefile),
`rsync`, SSH-adgang og sudo-tilladelse. Det valgte interface skal allerede have
dette projekts XDP-program tilkoblet; førstegangs-installation er ikke en
`--replace`-operation. Kør de dokumenterede staging-tests før
produktions-opgraderinger.

## Monitorering (Fase 1 midlertidig: `deploy/monitoring/`)

Indtil `sentinel-agent` eksporterer `/metrics` (Fase 4), når tællere Prometheus
gennem node_exporters textfile-collector:

```
XDP per-CPU-tællere ──sentinelctl stats --prometheus──▶ xs-textfile-exporter (systemd, hvert 5 s)
   ──▶ /var/lib/xdp-sentinel/textfile/xdp-sentinel-<if>.prom ──▶ node_exporter :9101
   ──▶ Prometheus :9091 (15 d, rules/alerts) ──▶ Grafana :3001 (provisioneret dashboard)
```

Metric-navne følger allerede [observability.md](observability.md), så dashboardet
og reglerne bliver ved med at virke når agenten overtager.

Stakken er uafhængig af enhver anden Prometheus på hosten (egne porte, volumes,
konfig) og binder kun til 127.0.0.1. Installér:

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

Som standard lytter Grafana kun på localhost. For at opdatere en eksisterende
installation til Twingate, kør disse fra repository-checkoutet på serveren:

```sh
sudo cp deploy/monitoring/docker-compose.yml /opt/xdp-sentinel/monitoring/
sudo cp deploy/monitoring/grafana/dashboards/xdp-sentinel-dataplane.json /opt/xdp-sentinel/monitoring/grafana/dashboards/
sudoedit /opt/xdp-sentinel/monitoring/.env
```

Sæt `GRAFANA_HTTP_ADDR` i `.env` til serverens private IP-adresse brugt af dens
Twingate-resource, og anvend så indstillingen fra stak-mappen:

```sh
cd /opt/xdp-sentinel/monitoring
sudo docker compose up -d
```

Åbn `http://<server-private-ip>:3001` fra en enhed forbundet til Twingate (bruger
`admin`, password i `/opt/xdp-sentinel/monitoring/.env`). Giv adgang til denne
resource i Twingate-politikken. Hold host-firewallen begrænset til
betroede/private netværk; forward ikke port 3001 fra det offentlige internet. For
at holde Grafana kun-lokal, lad `GRAFANA_HTTP_ADDR` være usat og brug
`ssh -L 3001:127.0.0.1:3001 <user>@<host>`, og åbn så http://localhost:3001.

Dashboardet er genereret: redigér
`deploy/monitoring/grafana/build_dashboard.py` og regenerér
`grafana/dashboards/xdp-sentinel-dataplane.json`; Grafana genindlæser
provisionerede filer inden for ~10 s. Alarm-regler er i
`prometheus/rules/xdp-sentinel.yml` (validér med `promtool check config`); ingen
Alertmanager er udrullet endnu, så aktive alarmer er kun synlige i Prometheus
(`/alerts`) og Grafana.
