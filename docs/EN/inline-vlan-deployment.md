<!-- Language: **English** · [Dansk](../DK/inline-vlan-deployment.md) -->

# Inline VLAN-bridge deployment (one-NIC hairpin)

How the xdp-sentinel appliance was placed **in the path** of a network using a
single managed switch and a single-NIC server, so that all traffic between the
machines and the internet is inspected by XDP before reaching anything else.

This is the `inline` topology from [architecture.md](architecture.md), realised
as a **router-on-a-stick / VLAN hairpin** because the appliance has only one
Ethernet port.

---

## 1. What was built

```
                         ZyXEL GS1900-24HP (managed switch)
   internet router ──[ P1  VLAN10 untagged, PVID10 ]
                                                      P3  VLAN10+VLAN20 tagged ── enp1s0  xdp-sentinel
   LAN switch / machines ─[ P2  VLAN20 untagged, PVID20 ]        (trunk)          (bridges vlan10 <-> vlan20)
```

- The **router** (WAN/upstream side) sits alone on **VLAN 10**.
- The **machines to protect** (a second switch with Proxmox VMs, etc.) sit on
  **VLAN 20**.
- P1 and P2 **share no VLAN**, so the switch cannot forward router<->machine
  traffic directly. The only port in both VLANs is **P3**, the trunk to the
  appliance.
- The appliance receives both VLANs tagged on one cable, splits them into
  `vlan10` and `vlan20` sub-interfaces, and **bridges** them (`br0`). Every
  packet crossing between the internet and the machines therefore traverses the
  bridge, where **XDP is attached to both `vlan10` and `vlan20`** and inspects
  each direction.

### Why the hairpin is forced

A managed switch only forwards a frame between two ports if they share a VLAN.
With the router on VLAN 10 and the machines on VLAN 20, a packet from a machine
to the internet has nowhere to go on the switch except up the trunk to the
appliance (tagged VLAN 20), through the bridge, and back down the trunk (tagged
VLAN 10) to the router. The appliance is physically unavoidable.

### What it does and does not see

- **Sees:** all traffic between the machines (VLAN 20) and the internet
  (VLAN 10).
- **Does not see:** traffic between two machines that share the LAN switch on
  P2 — the LAN switch forwards that locally and it never reaches the trunk.
  Inspecting intra-LAN traffic would require one VLAN per machine.

### Addresses and roles (this install)

| Thing | Value |
|---|---|
| Appliance management IP (`br0`) | `192.168.1.193/24`, gw `192.168.1.1` |
| Switch management IP | `192.168.1.50`, **management VLAN 10** |
| Router / gateway | `192.168.1.1` (VLAN 10 side) |
| Grafana | `http://192.168.1.193:3001` |
| VLAN 10 | router / internet (upstream) |
| VLAN 20 | machines to protect (LAN) |
| Trunk NIC | `enp1s0` (Realtek r8169 → generic-mode XDP) |

---

## 2. Switch configuration (ZyXEL GS1900-24HP)

Done in the web UI (`Configuration → VLAN → VLAN`). The same logic applies to
any 802.1Q managed switch; only the menus differ.

### 2.1 Create the VLANs
`VLAN` tab → **Add** → VLAN List `10,20`.

### 2.2 Port membership (`VLAN Port` tab, per VLAN)

| VLAN | P1 (router) | P2 (LAN) | P3 (trunk) | all other ports |
|---|---|---|---|---|
| **10** | Untagged | Excluded | **Tagged** | Excluded |
| **20** | Excluded | Untagged | **Tagged** | Excluded |

### 2.3 PVID (`Port` tab → select port → Edit)

| Port | PVID |
|---|---|
| P1 | 10 |
| P2 | 20 |
| P3 | 1 (leave default; its traffic is tagged) |

### 2.4 Management VLAN
`Configuration → System → IP` → **Management VLAN = 10** (so the switch admin
page stays reachable from the VLAN-10 / admin side after the split).

### 2.5 Save
Top-right **Save** (writes running config to flash). **Until you Save, a
power-cycle reverts everything** — which is itself the safety net while
configuring.

### The golden check
After configuring, **P1 and P2 must not share any VLAN**. The only port in both
10 and 20 is P3. If P1 and P2 share a VLAN, traffic bypasses the appliance.

---

## 3. Appliance (server) configuration

### 3.1 Base install
See [deployment.md](deployment.md). In short, on the Linux box:

```sh
# build deps: clang, llvm, libbpf-dev, libelf-dev, zlib1g-dev, pkg-config, rustc, cargo, rustfmt
make all                       # BPF object + sentinelctl + sentinel-agent + sentinel-inference
sudo make test test-bpf test-integration   # all must pass on the target kernel
sudo install -D -m0755 target/release/sentinelctl      /usr/local/bin/sentinelctl
sudo install -D -m0755 target/release/sentinel-agent   /usr/local/bin/sentinel-agent
sudo install -D -m0755 target/release/sentinel-inference /usr/local/bin/sentinel-inference
sudo install -D -m0644 ebpf/build/xdp_main.bpf.o       /usr/lib/xdp-sentinel/xdp_main.bpf.o
# trained ML models used by the agent
for m in anomaly bot classifier; do
  sudo install -D -m0644 -t /usr/lib/xdp-sentinel/models/$m/v1 ml/models/$m/v1/model.json ml/models/$m/v1/manifest.json
done
```

### 3.2 Network: the VLAN bridge (netplan)
Installed as `/etc/netplan/01-xdp-vlan-bridge.yaml` (template in
[../configs/netplan-vlan-bridge.yaml](../../configs/netplan-vlan-bridge.yaml)):

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

`br0` keeps the appliance's management IP, so SSH and Grafana stay at the same
address. STP off + zero forward-delay = the bridge forwards immediately.

### 3.3 Agent: attach XDP to both VLANs
`/etc/xdp-sentinel/config.toml` (template in
[../configs/agent-vlan.toml](../../configs/agent-vlan.toml)):

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

`generic` mode because VLAN sub-interfaces (and the r8169 NIC) do not support
native XDP. That is fine behind a home/SOHO router, which is the bottleneck.

Enable the agent: `sudo systemctl enable --now sentinel-agent`.

### 3.4 Operator allowlist (never lock yourself out)
`/etc/xdp-sentinel/allowlist.conf` ([../configs/allowlist.conf](../../configs/allowlist.conf)),
re-applied on every boot by `xs-baseline.service` (script
[../scripts/xs-baseline](../../scripts/xs-baseline)). It marks the LAN prefixes
`dynamic-exempt`, so auto-mitigation can never rate-limit or block the admin
network.

### 3.5 Auto-mitigation (optional)
Drop-in `sentinel-agent.service.d/auto-mitigate.conf` sets
`XS_AUTO_MITIGATE=1`, letting the risk engine tighten rate limits / drop flags
during a detected attack and restore the baseline afterwards. Remove the
drop-in to return to observe-only.

---

## 4. The cutover (the dangerous bit) and how it was made safe

A single-NIC hairpin has a bootstrap problem: the appliance can only bridge once
the switch sends it tagged frames, but the moment the switch splits the network
the appliance (still in plain/flat mode) is briefly cut off. Doing this remotely
can strand the box.

Two mechanisms handle it:

1. **`scripts/xs-cutover`** — flips the box between plain mode and bridge mode.
   It runs detached (survives a dropped SSH session) and **pings the gateway
   after switching; if unreachable it rolls back automatically**. Manual use:
   `sudo xs-cutover` / `sudo xs-cutover --rollback`.

2. **`scripts/xs-cutover --auto`** on a timer (`xs-cutover-auto.timer`) — checks
   every 30 s and switches to bridge mode automatically **once it sees inbound
   VLAN-tagged frames on the trunk and loses the flat gateway**, i.e. the moment
   the switch is reconfigured. This is what fired in this install:

   ```
   xs-cutover: gateway lost and VLAN-tagged frames seen on enp1s0: switch reconfigured
   xs-cutover: switching enp1s0 to VLAN bridge mode
   xs-cutover: bridge mode active: XDP on vlan10 (from internet) and vlan20 (from LAN)
   ```
   After a successful cutover it drops a `/etc/xdp-sentinel/.cutover-done` flag
   and disables its own timer.

Because nothing is saved on the switch until the final step, **a switch
power-cycle reverts to the flat network** at any point during switch
configuration — the escape hatch if anything goes wrong.

---

## 5. Reproduce from scratch (checklist)

1. **Prep the appliance in plain mode**, reachable on the LAN (static or DHCP on
   `enp1s0`). Build, install, and stage the files (§3). Enable
   `xs-cutover-auto.timer` and `xs-baseline.service`. Confirm the staged
   `/etc/xdp-sentinel/staged/01-xdp-vlan-bridge.yaml` validates:
   `sudo netplan generate --root-dir <tmp>`.
2. **Cable the switch**: router → P1, LAN switch → P2, appliance → P3. Confirm
   with the switch MAC table that each device is on the expected port.
3. **Configure the switch** (§2): create VLAN 10/20, set membership + PVID,
   set management VLAN 10. Configure ports **2 and 3 first** (does not disturb a
   management session arriving on P1), then **port 1 last** — that completes the
   hairpin and triggers the appliance's auto-cutover.
4. **Watch the appliance bridge itself** (`journalctl -t xs-cutover -f`), or run
   `sudo xs-cutover` manually.
5. **Save** the switch config.
6. **Verify** (§6).

> Order matters: do not move port 1 / the management VLAN before ports 2–3 are
> set, and keep physical access to the switch (an unused port stays on the
> management VLAN) in case you need to recover.

---

## 6. Verification

```sh
# On the appliance
ip -br addr show br0                       # br0 UP with the management IP
bridge link show | grep -E 'vlan10|vlan20' # both in forwarding
ping -c1 1.1.1.1                           # appliance has internet via the router
sudo sentinelctl status -i vlan10          # XDP attached
sudo sentinelctl status -i vlan20          # XDP attached
sudo sentinelctl stats  -i vlan10          # rx climbs with internet traffic
sudo sentinelctl stats  -i vlan20          # rx climbs with the machines' traffic
sudo sentinelctl list   -i vlan10          # allowlist present

# From an admin box on VLAN 10
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.50/     # switch admin
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.193:3001/login  # Grafana
```

A LAN machine on VLAN 20 should still reach the internet (proves the hairpin
forwards end-to-end), and `sudo tcpdump -eni enp1s0 -c 20` should show `vlan 10`
and `vlan 20` tagged frames.

---

## 7. Operations & recovery

- **`xdp` wrapper** (`/usr/local/bin/xdp`): `xdp status|stats|list|block|allow|
  flags|ratelimit|reset`. It targets `$XDP_IFACE` (set in
  `/etc/profile.d/xdp-sentinel.sh`; use `vlan10`, or `XDP_IFACE=vlan20 xdp ...`).
- **Roll back to a flat network**: `sudo xs-cutover --rollback` on the
  appliance, **and** move the router cable from switch P1 straight to the LAN
  switch (or revert the switch VLANs). Fastest emergency: unplug the appliance
  and patch the router to the LAN switch directly.
- **If the appliance is down**, the LAN loses internet (it is in-path). Keep a
  cable to bypass it.
- **Switch admin unreachable** after a VLAN mistake: plug a laptop into any
  unused switch port (still on the management VLAN) and browse to
  `192.168.1.50`, or use the switch console/reset.
- **XDP off switch**: `sudo sentinelctl detach -i vlan10` (and `vlan20`), or
  `ip link set dev vlan10 xdpgeneric off`.

---

## 8. Limitations specific to this setup

- **~1 Gbps / generic XDP.** VLAN sub-interfaces + r8169 → generic mode. Fine
  behind a SOHO router; not a line-rate 10G claim (see
  [performance.md](performance.md)).
- **No intra-LAN visibility** (machines sharing the P2 switch).
- **ML models are trained on synthetic data** (see [ml.md](ml.md)); the
  statistical baseline detector drives mitigation. Retrain on captured
  real-traffic features for production-grade detection.
- **Single point of failure** on the wired path, by design of an inline scrubber.
