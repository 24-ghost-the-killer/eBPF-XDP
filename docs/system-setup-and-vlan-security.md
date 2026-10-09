# xdp-sentinel — whole-system setup & VLAN interception analysis

This document does three things:

1. **Inventory** — what the system actually is: the managed switch, the Linux
   appliance, the router, and every connection between them (with the results
   of a live reachability check).
2. **Setup** — how to build and stand up the *whole* system end to end: the XDP
   dataplane, the switch, the agents, the ML training, and monitoring.
3. **Interception / VLAN jumping** — how an attacker could get in the middle of
   this network, with each attack mapped against *this specific* topology and
   the concrete defence for it.

It is a companion to [architecture.md](architecture.md),
[inline-vlan-deployment.md](inline-vlan-deployment.md),
[deployment.md](deployment.md), [ml.md](ml.md) and
[threat-model.md](threat-model.md); it does not replace them, it ties them
together for this install.

---

## 1. System inventory

### 1.1 Physical topology

```
                         ZyXEL GS1900-24HP  (managed L2 switch, mgmt 192.168.1.50)
                       ┌───────────────────────────────────────────────────────┐
  internet ── router ──┤ P1  VLAN10 untagged, PVID 10                            │
  (192.168.1.1)        │                                                         │
                       │ P3  VLAN10 + VLAN20 tagged  ─── enp1s0 ── xdp-sentinel  │
                       │     (the trunk)                         appliance       │
  LAN / machines ──────┤ P2  VLAN20 untagged, PVID 20          (br0 192.168.1.193)│
  (Proxmox etc.)       └───────────────────────────────────────────────────────┘
```

The appliance has **one** physical NIC (`enp1s0`). The switch hands it both
VLANs tagged on that single cable (a "router-on-a-stick" / **VLAN hairpin**).
Inside the appliance:

```
enp1s0 ──┬── vlan10  (802.1Q id 10, router / internet side)   ──┐
         └── vlan20  (802.1Q id 20, machines / LAN side)      ──┤
                                                                ├── br0 (bridge)
                                   XDP attached to vlan10 and vlan20
                                   br0 holds the management IP 192.168.1.193/24
```

Because P1 (router) and P2 (machines) **share no VLAN**, the switch physically
cannot forward a router↔machine frame on its own. The only port in both VLANs
is P3, the trunk to the appliance. So every packet between the internet and the
machines is forced up the trunk, through `vlan10`/`vlan20`, across the bridge
— **past XDP** — and back down. The appliance is unavoidable *by design*.

### 1.2 Addresses and roles (this install)

| Thing | Value | Notes |
|---|---|---|
| Appliance management IP (`br0`) | `192.168.1.193/24`, gw `192.168.1.1` | SSH + Grafana live here |
| Switch management IP | `192.168.1.50`, **management VLAN 10** | web UI |
| Router / gateway | `192.168.1.1` | VLAN 10 (upstream) side |
| Grafana | `http://192.168.1.193:3001` | dashboards |
| Agent metrics (Prometheus) | `127.0.0.1:9464` | localhost only; `/metrics /healthz /readyz` |
| VLAN 10 | router / internet (upstream) | |
| VLAN 20 | machines to protect (LAN) | |
| Trunk NIC | `enp1s0` (Realtek r8169) | generic-mode XDP only |

### 1.3 Software planes

- **Dataplane (kernel):** `ebpf/build/xdp_main.bpf.o`, one XDP program instance
  per RX queue/CPU, attached to `vlan10` and `vlan20`. Parses L2–L4, checks the
  allowlist, applies per-source policy + rate limits + per-service budgets,
  writes counters/sketches/samples to pinned BPF maps, returns `PASS`/`DROP`.
  **Never waits for userspace.**
- **Control plane (userspace, Rust):**
  - `sentinel-agent` — reads the maps, aggregates flows, builds feature
    windows, runs the risk/policy engine, and writes policies *with TTLs* back
    into the maps. Exposes Prometheus metrics. Runs as user `xs` with only
    `CAP_BPF CAP_PERFMON CAP_NET_ADMIN`.
  - `sentinel-inference` — loads the ML models (ONNX/portable JSON) in a
    separate, sandboxed, network-less process; the agent calls it over a Unix
    socket with a deadline.
  - `sentinelctl` / the `xdp` wrapper — operator CLI (attach/detach, status,
    stats, block, allow, ratelimit, flags, reset).
- **ML (offline):** `ml/` Python pipeline — synthetic dataset generator and
  three trainers (anomaly / classifier / bot) that emit portable JSON models
  the Rust scorers load byte-identically.
- **Observability:** Prometheus scrapes the agent; Grafana renders; ClickHouse
  (optional, `deploy/clickhouse/`) stores telemetry for training.

### 1.4 Live reachability check (performed read-only from the dev machine over the VPN)

| Target | Result |
|---|---|
| `192.168.1.193` (appliance `br0`) | **up** — ICMP replies |
| `192.168.1.50` (switch) | **up** — ICMP replies |
| `192.168.1.1` (router) | no ICMP reply (expected: VLAN‑10 side / ping filtered) |
| SSH to appliance | reachable but **requires a key not on this machine** |

The "does XDP see traffic, is the bridge forwarding, is the allowlist loaded"
checks can only be answered from on-box; run the commands in §2.11 over SSH.

---

## 2. Setup — standing up the whole system

Order matters. Build and stage everything on the appliance **while it is still
a flat box on the LAN**, and only reconfigure the switch (which splits the
network) as the last step, with the auto-rollback cutover armed.

### 2.1 Build dependencies (appliance, Debian 12/13 or Ubuntu 24.04)

```sh
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                        pkg-config bpftool make
# Rust ≥ 1.85
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rustfmt
```

Kernel must be ≥ 6.1 with `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_SYSCALL=y`,
`CONFIG_BPF_JIT=y`, and bpffs mounted at `/sys/fs/bpf` (systemd default).

### 2.2 Build and test

```sh
make all                                   # BPF object + sentinelctl + agent + inference
make test                                  # unprivileged: parser + Rust tests
sudo make test-bpf                         # verifier + in-kernel corpus
sudo make test-integration                 # veth end-to-end, native XDP
```

All must pass **on the target kernel** before you go further.

### 2.3 Install the binaries, object, and models

```sh
sudo install -D -m0755 target/release/sentinelctl        /usr/local/bin/sentinelctl
sudo install -D -m0755 target/release/sentinel-agent     /usr/local/bin/sentinel-agent
sudo install -D -m0755 target/release/sentinel-inference /usr/local/bin/sentinel-inference
sudo install -D -m0644 ebpf/build/xdp_main.bpf.o         /usr/lib/xdp-sentinel/xdp_main.bpf.o
for m in anomaly bot classifier; do
  sudo install -D -m0644 -t /usr/lib/xdp-sentinel/models/$m/v1 \
       ml/models/$m/v1/model.json ml/models/$m/v1/manifest.json
done
```

### 2.4 The switch (ZyXEL GS1900-24HP)

Web UI at `http://192.168.1.50`, `Configuration → VLAN → VLAN`. The same logic
applies to any 802.1Q managed switch.

1. **Create VLANs** — `VLAN` tab → Add → VLAN List `10,20`.
2. **Port membership** (`VLAN Port` tab, per VLAN):

   | VLAN | P1 (router) | P2 (LAN) | P3 (trunk) | all other ports |
   |---|---|---|---|---|
   | **10** | Untagged | Excluded | **Tagged** | Excluded |
   | **20** | Excluded | Untagged | **Tagged** | Excluded |

3. **PVID** (`Port` tab → Edit): P1 → `10`, P2 → `20`, P3 → leave default
   (its traffic is tagged). *(See §3.2 — this PVID choice is also a security
   decision; consider setting P3's PVID to an unused, empty VLAN.)*
4. **Management VLAN** — `Configuration → System → IP` → Management VLAN = `10`
   so the switch admin page stays reachable from the admin side after the split.
5. **Do not Save yet** — until you hit Save, a switch power-cycle reverts
   everything. That is your safety net while configuring.

**The golden check:** after configuring, P1 and P2 must share **no** VLAN; the
only port in both 10 and 20 is P3. If P1 and P2 ever share a VLAN, traffic
bypasses the appliance entirely (see §3.8).

### 2.5 Appliance network — the VLAN bridge (netplan)

Stage, don't apply live yet. Template:
[../configs/netplan-vlan-bridge.yaml](../configs/netplan-vlan-bridge.yaml) →
`/etc/netplan/01-xdp-vlan-bridge.yaml`:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0: {}                         # trunk NIC, no IP of its own
  vlans:
    vlan10: { id: 10, link: enp1s0 }   # router side (from the internet)
    vlan20: { id: 20, link: enp1s0 }   # machines side (from the LAN)
  bridges:
    br0:
      interfaces: [vlan10, vlan20]
      addresses: [192.168.1.193/24]
      routes: [{to: default, via: 192.168.1.1}]
      nameservers: {addresses: [192.168.1.1]}
      parameters: { stp: false, forward-delay: 0 }
```

Validate before anything goes live: `sudo netplan generate --root-dir <tmp>`.

### 2.6 Agent — attach XDP to both VLANs

Template [../configs/agent-vlan.toml](../configs/agent-vlan.toml) →
`/etc/xdp-sentinel/config.toml`:

```toml
metrics_addr = "127.0.0.1:9464"
pin_root = "/sys/fs/bpf/xdp-sentinel"
bpf_obj  = "/usr/lib/xdp-sentinel/xdp_main.bpf.o"

[[interface]]
name = "vlan10"   # from the internet
mode = "generic"
attach = true

[[interface]]
name = "vlan20"   # from the machines
mode = "generic"
attach = true
```

`generic` mode because VLAN sub-interfaces and the r8169 NIC have no native
XDP. Fine behind a SOHO router (the router is the bottleneck, ~1 Gbps), not a
line-rate 10G claim.

### 2.7 Operator allowlist (never lock yourself out)

Template [../configs/allowlist.conf](../configs/allowlist.conf) →
`/etc/xdp-sentinel/allowlist.conf`, re-applied every boot by
`xs-baseline.service`. The LAN prefix is `dynamic-exempt` so auto-mitigation
can never rate-limit or block the admin network:

```
192.168.1.0/24          dynamic-exempt   # LAN (admin SSH, Grafana)
fe80::/10               dynamic-exempt   # IPv6 link-local
2001:6c8:ff15:2633::/64 dynamic-exempt   # LAN IPv6 prefix (update if ISP changes)
```

`dynamic-exempt` = never auto-blocked/limited but still validity-checked.
`full` = bypasses every check — use sparingly (see §3.7).

### 2.8 Enable services

```sh
sudo systemctl enable --now xs-baseline.service       # applies allowlist on boot
sudo systemctl enable      xs-cutover-auto.timer       # arms the safe cutover (§2.9)
sudo systemctl enable --now sentinel-agent             # (after cutover, see §2.9)
```

Optional **auto-mitigation**: the drop-in
`sentinel-agent.service.d/auto-mitigate.conf` sets `XS_AUTO_MITIGATE=1`, letting
the risk engine tighten rate limits / drop flags during a detected attack and
restore the baseline afterward. Remove the drop-in to return to observe-only.
The dataplane default is **observe-only**; validity dropping is opt-in:
`sentinelctl config -i vlan10 --drop-malformed on`.

### 2.9 The cutover (the dangerous step) — made safe

A single-NIC hairpin has a bootstrap problem: the appliance can only bridge once
the switch sends it tagged frames, but the instant the switch splits the network
the still-flat appliance is briefly cut off. Two mechanisms handle it:

- **`scripts/xs-cutover`** flips between plain and bridge mode, runs detached
  (survives a dropped SSH session), **pings the gateway after switching and
  rolls back automatically if unreachable**. Manual: `sudo xs-cutover` /
  `sudo xs-cutover --rollback`.
- **`scripts/xs-cutover --auto`** on `xs-cutover-auto.timer` checks every 30 s
  and switches to bridge mode the moment it sees inbound VLAN-tagged frames on
  the trunk *and* loses the flat gateway — i.e. the moment you finish the switch
  config. It then drops `/etc/xdp-sentinel/.cutover-done` and disables its timer.

**Sequence:** configure switch ports **2 and 3 first** (doesn't disturb a
management session arriving on P1), then **port 1 last** — that completes the
hairpin and triggers the auto-cutover. Watch it with
`journalctl -t xs-cutover -f`. Then **Save** the switch config.

### 2.10 ML training

ML is a control-plane *advisor* — it never touches the packet path. The shipped
models are trained on **synthetic** data; the statistical baseline detector is
what actually drives mitigation until you retrain on captured real traffic.

```sh
# 1. generate / regenerate a labelled synthetic dataset (feature-vector windows)
python3 ml/dataset/generate.py -o ml/dataset/synthetic.csv -n 500

# 2. train each model → portable JSON + manifest (schema_hash pinned)
python3 ml/train/train_anomaly.py    --data ml/dataset/synthetic.csv --version v1 --trees 128 --sample 256
python3 ml/train/train_classifier.py --data ml/dataset/synthetic.csv --version v1
python3 ml/train/train_bot.py        --version v1

# 3. the trainers write ml/models/<name>/v1/{model.json,manifest.json}
#    install them (same as §2.3) and restart the agent to pick them up
```

Exit criteria built into the trainers: anomaly beats a pps-threshold baseline on
PR-AUC; classifier ≥ 0.95 per-type recall; bot ≥ 0.9 precision at the operating
point. For production-grade detection, replace the synthetic set with captured
real-traffic feature windows (see [ml.md](ml.md) §23) — critically, **exclude
windows under active mitigation** from training so the model can't be poisoned
into learning attacks as normal (threat #10).

### 2.11 Monitoring

```sh
# agent metrics (localhost): scrape via Prometheus in deploy/monitoring/
cd deploy/monitoring && cp .env.example .env && docker compose up -d   # Prometheus + Grafana
# optional telemetry store for training data
cd deploy/clickhouse && docker compose up -d && \
  docker compose exec clickhouse clickhouse-client --multiquery < schema.sql
```

Grafana at `http://192.168.1.193:3001` (dashboards provisioned from
`deploy/monitoring/grafana/`). Prometheus alert rules in
`deploy/monitoring/prometheus/rules/`.

### 2.12 Verification (run on-box)

```sh
# On the appliance
ip -br addr show br0                        # br0 UP with 192.168.1.193
bridge link show | grep -E 'vlan10|vlan20'  # both forwarding
ping -c1 1.1.1.1                            # appliance has internet via the router
sudo sentinelctl status -i vlan10           # XDP attached
sudo sentinelctl status -i vlan20           # XDP attached
sudo sentinelctl stats  -i vlan10 --interval 1   # rx climbs with internet traffic
sudo sentinelctl stats  -i vlan20 --interval 1   # rx climbs with LAN traffic
sudo sentinelctl list   -i vlan10           # allowlist present
sudo tcpdump -eni enp1s0 -c 20              # should show BOTH 'vlan 10' and 'vlan 20' frames

# From an admin box on VLAN 10
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.50/            # switch admin
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.193:3001/login # Grafana
```

A LAN machine on VLAN 20 reaching the internet proves the hairpin forwards
end-to-end.

### 2.13 Emergency off-switch / rollback

- Detach XDP: `sudo sentinelctl detach -i vlan10` (and `vlan20`), or
  `ip link set dev vlan10 xdpgeneric off`.
- Back to a flat network: `sudo xs-cutover --rollback`, **and** move the router
  cable from switch P1 straight to the LAN switch (or revert the switch VLANs).
  Fastest emergency: unplug the appliance and patch the router to the LAN switch
  directly. **The appliance is in-path — if it is down, the LAN loses internet.
  Keep a bypass cable.**

---

## 3. Interception & VLAN jumping — how an attacker gets in the middle

> This section is a defensive threat model of **your own** network. Each item
> says how the attack works, whether *this* topology is exposed, and the
> concrete fix. The goal is to make the appliance an unavoidable chokepoint and
> to keep anyone from stepping around it or turning the switch into a hub.

The whole security value of this design rests on one assumption: **router↔machine
traffic has no path except through the appliance's bridge.** Every attack below
is ultimately an attempt to break that assumption — to reach another VLAN
directly, to make the switch leak frames, or to sit between two hosts inside a
VLAN the appliance cannot see.

### 3.1 VLAN hopping by double tagging (802.1Q double-encapsulation) — the classic "VLAN jump"

**How it works.** The attacker, sitting on an *access* port, sends a frame with
**two** stacked 802.1Q tags: an outer tag matching the trunk's **native
(untagged / PVID) VLAN**, and an inner tag naming the **target** VLAN. The first
switch sees the outer tag equals the native VLAN, strips it (native VLAN frames
leave a trunk untagged), and forwards the frame on the trunk. The *next* hop
then reads the inner tag and delivers the frame into the target VLAN — one-way,
but enough to inject into a VLAN you were never a member of.

**Exposure here.** This is *the* attack the name "VLAN jumping" refers to, and
this topology has the ingredient it needs: a trunk (P3) that carries tagged
VLANs. The mitigating facts:

- Double tagging only works when the trunk's **native VLAN equals a VLAN an
  attacker's access port can inject untagged into**. On P3 both 10 and 20 are
  **tagged**, and P3's PVID is left at the default (VLAN 1), which is not used
  for data. An attacker on P2 (access VLAN 20, PVID 20) emits untagged frames;
  the switch tags them 20 on ingress. To double-tag, the attacker's injected
  *outer* tag must survive to the trunk as the native VLAN — but the trunk's
  native VLAN (1) is empty and no access port uses it.
- It is strictly one-way (no return path), so it is an injection/spoofing
  primitive, not a full session MITM, on an L2 hairpin like this.

**Fix / harden.**
- **Set the trunk's native VLAN to a dedicated, empty, unused VLAN** (e.g. 999)
  that exists on no access port, and don't leave it as VLAN 1. On the GS1900,
  make P3's PVID an otherwise-unused VLAN and ensure that VLAN is `Excluded`
  everywhere else. An outer tag the attacker can produce then never matches the
  trunk native VLAN, so the first-hop strip never happens.
- Keep **every data VLAN tagged on the trunk** (already the case) and never make
  an access port a member of VLAN 1.
- XDP backstop: both directions already cross `vlan10`/`vlan20` through the
  bridge, so an injected frame that *does* reach a VLAN still passes the
  dataplane's validity and policy checks — but do not rely on that for VLAN
  segmentation; fix it at the switch.

### 3.2 Switch spoofing / rogue trunk negotiation (DTP)

**How it works.** On Cisco-style switches, a port left in dynamic/auto trunk
mode can be coerced into forming a trunk by an attacker speaking DTP, instantly
giving them every VLAN.

**Exposure here.** The GS1900-24HP is a smart/web-managed switch with **no DTP**
— trunking is static per-port VLAN membership, not negotiated. So classic DTP
switch-spoofing does not apply. The residual risk is *misconfiguration*: an
access port accidentally made a tagged member of both VLANs becomes an
unintended trunk.

**Fix.** Audit `VLAN Port` membership: only **P3** may be tagged in both 10 and
20. Everything else: each access port in exactly one VLAN, untagged, with a
matching PVID; all other ports `Excluded` from 10 and 20. The "golden check"
(§2.4) is exactly this audit.

### 3.3 Plugging into the recovery port (the escape hatch is also an entry point)

**How it works.** [inline-vlan-deployment.md](inline-vlan-deployment.md) keeps
"an unused switch port on the management VLAN" for recovery. Anyone with
physical access can plug into that port and land directly on **management VLAN
10**, reaching the switch admin UI (`192.168.1.50`) and the appliance's `br0`
(`192.168.1.193`) — *beside* the hairpin, not through it.

**Exposure here.** Real and often overlooked. The management VLAN is the
crown-jewel VLAN (it controls the switch and the appliance).

**Fix.**
- Keep unused ports **administratively shut / `Excluded` from all VLANs** until
  needed; enable the recovery port only when you are physically at it.
- Put switch + appliance management behind strong auth and, ideally, a dedicated
  management VLAN that is *not* a data VLAN (today management shares VLAN 10 with
  the router/internet side — see §3.6).
- Physical security of the switch closet is part of the control.

### 3.4 CAM-table (MAC) flooding → switch degrades to a hub

**How it works.** The attacker floods the switch with thousands of bogus source
MACs. When the MAC/CAM table overflows, many switches **fail open**: unknown-
unicast frames get flooded out all ports in the VLAN, so the attacker on the
same VLAN now sniffs traffic meant for others.

**Exposure here.** Intra-VLAN only — it would let an attacker on VLAN 20 sniff
other VLAN‑20 traffic, or on VLAN 10 sniff the router segment. It does **not**
cross VLANs. The appliance sees inter-VLAN traffic but not intra-VLAN flooding
on a downstream LAN switch.

**Fix.**
- Enable the GS1900's **port security / MAC-limit** per access port (limit the
  number of learned MACs; shut or alarm on violation).
- Enable **storm control** (broadcast/multicast/unknown-unicast rate limits).
- Segment further: fewer hosts per VLAN limits the blast radius.

### 3.5 ARP spoofing / intra-VLAN MITM (and the appliance's blind spot)

**How it works.** Within one VLAN, an attacker sends forged ARP (or IPv6 ND)
replies to poison neighbours' tables and insert themselves between two hosts (or
between a host and its gateway) — a full bidirectional MITM, no VLAN hop needed.

**Exposure here.** This is the biggest practical gap. The design explicitly
**does not see traffic between two machines that share the P2 LAN switch** — the
LAN switch forwards it locally and it never reaches the trunk. So an attacker who
is *already a machine on VLAN 20* can ARP-spoof its VLAN‑20 neighbours and MITM
them, and the appliance never sees it. The appliance only inspects traffic that
crosses between VLAN 20 and VLAN 10 (i.e. to/from the internet).

**Fix.**
- **Dynamic ARP Inspection (DAI)** + **DHCP snooping**, and **IPv6 RA-Guard / ND
  inspection**, on the downstream LAN switch if it supports them (the GS1900 has
  DHCP snooping and some L2 protections; check the feature set).
- For true per-machine inspection you'd need **one VLAN per machine** (private
  VLANs / port isolation) so even intra-LAN traffic hairpins through the
  appliance — this is the documented path to closing the intra-LAN blind spot,
  at the cost of more VLANs.
- Static ARP entries for critical hosts; monitor for ARP anomalies.

### 3.6 Management plane on a data VLAN

**How it works.** Management VLAN 10 is **also** the router/internet-facing VLAN.
Anything that reaches VLAN 10 (a compromised router, a double-tag injection per
§3.1, the recovery port per §3.3) is adjacent to the switch admin UI and the
appliance management IP. If the switch admin UI is plain **HTTP**, credentials
and sessions cross the wire in clear.

**Exposure here.** The switch UI is reachable at `http://192.168.1.50` and the
appliance at `192.168.1.193` on VLAN 10. Threat-model item #15 ("management
plane") recommends a *separate* management NIC/network; this single-NIC hairpin
collapses management onto a data VLAN out of necessity.

**Fix.**
- Prefer **HTTPS** for the switch UI if the firmware supports it; otherwise
  restrict the admin UI to a single admin host and strong credentials, and never
  from the internet side.
- If a second NIC or a dedicated management VLAN (distinct from both 10 and 20)
  is possible, move management there and allowlist it `full` **on that interface
  only** (threat-model #15).
- Keep `metrics_addr` on `127.0.0.1` (already the case) and reach Grafana/
  Prometheus over SSH tunnel or the VPN, not an exposed port.

### 3.7 Allowlist / trust abuse

**How it works.** An attacker who can spoof a source inside an allowlisted CIDR,
or who compromises a host in one, inherits that trust. A `full` allowlist entry
**bypasses every check** in the dataplane — spoof that source and you are invisible
to mitigation.

**Exposure here.** `192.168.1.0/24` and the IPv6 prefixes are `dynamic-exempt`,
which is the safe choice: never auto-blocked, but **still validity-checked**. No
`full` entries ship by default.

**Fix.** Keep LAN/admin prefixes `dynamic-exempt`, not `full`. Reserve `full`
for a dedicated management interface only. Because the appliance is an L2 bridge,
also remember source IPs from the internet side are trivially spoofable — the
design leans on destination/service-centric mitigation and short TTLs for
exactly this (threat-model #12).

### 3.8 Bypassing the chokepoint entirely (the real worst case)

**How it works.** Forget clever tags — if any path lets router↔machine traffic
avoid the trunk, the appliance inspects nothing. Ways that happens: P1 and P2
accidentally sharing a VLAN; someone patching the router straight into the LAN
switch; a second uplink; Wi-Fi bridging the two segments.

**Exposure here.** Entirely a wiring/config risk, and the single most important
one — it silently turns the appliance into a no-op.

**Fix.**
- The **golden check** after every switch change: P1 and P2 share no VLAN; P3 is
  the only port in both.
- Verify with the switch MAC table that each device is on its expected port, and
  with `tcpdump -eni enp1s0` on the appliance that you see **both** `vlan 10`
  and `vlan 20` frames (§2.12).
- Physically control cabling; no secondary router↔LAN links or bridging APs.

### 3.9 Attacking / starving the appliance itself

**How it works.** The appliance is a deliberate single point in the wired path.
A DoS that saturates the ~1 Gbps generic-XDP path, exhausts CPU, or crashes the
agent could blind detection or (if it could force drops) cut the LAN off.

**Exposure here.** Bounded by design: the dataplane does **fixed per-packet
work**, policies carry TTLs enforced *inside* XDP, and **a crashed control plane
stops mitigating rather than starting to drop** (fail-open for availability).
Generic XDP + r8169 caps throughput at ~1 Gbps — fine behind a SOHO router, but
it is the ceiling. Telemetry flooding is bounded by per-CPU sample token buckets
(threat-model #6).

**Fix.** Keep the bypass cable (§2.13); watch the Prometheus alerts for NIC
drops and CPU headroom; don't enable `--drop-*` validity rules without
understanding the traffic; keep auto-mitigation's collateral circuit breaker on.

### 3.10 Summary — exposure at a glance

| Attack | Crosses VLANs? | Exposed here? | Primary fix |
|---|---|---|---|
| Double tagging (§3.1) | yes (1-way) | low, if native VLAN hardened | dedicated empty native VLAN on P3 |
| DTP switch spoofing (§3.2) | yes | **no** (GS1900 has no DTP) | static membership audit |
| Recovery-port access (§3.3) | lands on mgmt | yes (physical) | shut unused ports; lock closet |
| CAM flooding (§3.4) | no (intra-VLAN) | yes, limited | port security + storm control |
| ARP/ND MITM (§3.5) | no (intra-VLAN) | **yes — blind spot** | DAI/ND-guard; VLAN-per-host |
| Mgmt on data VLAN (§3.6) | — | yes | HTTPS/separate mgmt VLAN |
| Allowlist/spoof abuse (§3.7) | — | low (dynamic-exempt only) | no `full` on data ifaces |
| Chokepoint bypass (§3.8) | — | config risk, **critical** | golden check + tcpdump |
| Appliance DoS (§3.9) | — | bounded by design | bypass cable; alerts |

### 3.11 Hardening checklist

- [ ] Trunk P3 native/PVID VLAN = a dedicated **empty** VLAN, excluded everywhere else.
- [ ] Golden check passes: P1 and P2 share no VLAN; P3 is the only port in both 10 and 20.
- [ ] Unused switch ports `Excluded` / shut; recovery port enabled only when in use.
- [ ] Port security (MAC limit) + storm control on access ports.
- [ ] DHCP snooping + Dynamic ARP Inspection + IPv6 RA-Guard on the LAN switch.
- [ ] Switch admin over HTTPS, strong creds, restricted to one admin host; never from the internet side.
- [ ] Management reachable only via VPN/SSH tunnel; `metrics_addr` stays on localhost.
- [ ] Allowlist uses `dynamic-exempt` (not `full`) for LAN/admin prefixes.
- [ ] `tcpdump -eni enp1s0` shows both VLAN 10 and VLAN 20 frames (traffic really hairpins).
- [ ] Retrain ML on captured real traffic, excluding mitigation windows.
- [ ] Bypass cable staged; Prometheus alerts for NIC drops / CPU headroom wired up.
- [ ] Consider VLAN-per-machine (private VLANs) to close the intra-LAN MITM blind spot.
```
