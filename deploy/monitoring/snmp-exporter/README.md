# Switch metrics in Grafana via SNMP

This wires the managed switch (**ZyXEL GS1900-24HP**, `192.168.1.50`) into the
existing Prometheus + Grafana stack so its per-port traffic, link status and
errors show up on a dashboard.

```
  switch (SNMP v2c)  ──poll──▶  snmp_exporter        Prometheus          Grafana
  192.168.1.50                  127.0.0.1:9116/snmp  127.0.0.1:9091      :3001
  (community = read pw)         IF-MIB → metrics     scrapes /snmp       "Switch (SNMP)"
```

Prometheus tells the exporter which target to poll (`?target=192.168.1.50`); the
exporter does the SNMP, Prometheus stores the result, Grafana graphs it.

There are **two halves** and both must be done: (A) turn SNMP on *in the switch*
and (B) point the monitoring stack at it. After a factory reset only (B) is in
this repo — (A) is gone and must be redone in the switch web UI.

---

## A. Switch side — enable SNMP on the GS1900-24HP

You reset the switch, so SNMP is off. Do this in the web UI
(`http://192.168.1.50`, admin login). Menu labels vary slightly by firmware;
the GS1900 series keeps SNMP under **Management → SNMP**.

1. **Enable SNMP.** `Management → SNMP → General` (or "SNMP" / "Setting"):
   set **SNMP State = Enabled**. Leave SNMP **v1/v2c** enabled (this setup uses
   v2c). **Apply**.

2. **Make sure a read View exists.** `Management → SNMP → View`. There is
   usually a default view covering the whole tree (OID subtree `1` /
   `1.3.6.1`, type *Included*). If not, add one — name it e.g. `all`, subtree
   `1`, **Included**. This is what lets the community read IF-MIB.

3. **Add the read-only community.** `Management → SNMP → Community`:
   - **Community String:** `Awk22T0tbX09mZQadFw6`
   - **Access / Privilege:** **Read-Only**
   - **View:** the read view from step 2 (e.g. `all`)
   - (If the UI asks for a **Group** instead of a view, create a v2c
     read-only group bound to that view, then map the community to it.)
   **Apply.**

4. **(Recommended) Restrict who may query.** If the firmware offers an SNMP
   host/manager allowlist, limit it to the appliance's management IP
   `192.168.1.193`. Otherwise anyone on the management VLAN who knows the
   community can read the switch.

5. **Save** the running config to flash (top-right **Save**), or a power-cycle
   loses it — same as the VLAN config.

> The community string is effectively a **read password**. Keep it only on the
> management VLAN, never expose SNMP (UDP/161) to the internet side, and prefer
> SNMPv3 (auth+priv) if you later want it encrypted (the exporter supports it —
> see the `auths` block in `snmp.yml.example`).

### Quick switch-side test (from the appliance)
```sh
# if net-snmp is installed; confirms the switch answers with your community
snmpwalk -v2c -c 'Awk22T0tbX09mZQadFw6' 192.168.1.50 1.3.6.1.2.1.1.3.0   # sysUpTime
snmpwalk -v2c -c 'Awk22T0tbX09mZQadFw6' 192.168.1.50 1.3.6.1.2.1.31.1.1.1.1  # ifName list
```
No answer → SNMP not enabled, wrong community, or a host allowlist is blocking
the appliance. Fix that before touching the exporter.

---

## B. Server side — already configured in this repo

The monitoring stack (`deploy/monitoring/`) now includes SNMP:

| File | What changed |
|---|---|
| `snmp-exporter/snmp.yml.example` | exporter config template (IF-MIB `if_mib` module + `switch_v2` auth) |
| `snmp-exporter/snmp.yml` | **real** config with the community — **gitignored**, created from the example |
| `docker-compose.yml` | new `snmp-exporter` service on `127.0.0.1:9116` |
| `prometheus/prometheus.yml` | new `snmp-switch` scrape job (30 s) targeting `192.168.1.50` |
| `grafana/dashboards/switch-snmp.json` | the **"Switch (SNMP)"** dashboard (auto-provisioned) |

The real `snmp.yml` (with the community `Awk22T0tbX09mZQadFw6`) has already been
generated next to the template and is ignored by git. If you ever need to
recreate it:

```sh
cd deploy/monitoring/snmp-exporter
cp snmp.yml.example snmp.yml
# set auths.switch_v2.community to the switch's read community
chmod 600 snmp.yml
```

### Bring it up / reload

```sh
cd deploy/monitoring
docker compose up -d            # starts/updates snmp-exporter, reloads others
# if Prometheus was already running, reload its config without a restart:
curl -X POST http://127.0.0.1:9091/-/reload
```

---

## C. Verify end to end

```sh
# 1. exporter can poll the switch (should print many ifHCInOctets / ifOperStatus lines)
curl -s 'http://127.0.0.1:9116/snmp?target=192.168.1.50&module=if_mib&auth=switch_v2' | grep -E '^if(OperStatus|HCInOctets)' | head

# 2. the exporter's own health
curl -s http://127.0.0.1:9116/metrics | grep snmp_request_errors_total

# 3. Prometheus sees the target as UP
#    Status → Targets in the UI, or:
curl -s 'http://127.0.0.1:9091/api/v1/targets' | grep -o '"job":"snmp-switch"[^}]*"health":"[a-z]*"'

# 4. a query returns data
curl -s 'http://127.0.0.1:9091/api/v1/query?query=ifOperStatus' | head -c 300
```

Then open Grafana (`http://192.168.1.193:3001`) → dashboard **"Switch (SNMP)"**.
Pick the switch and ports from the dropdowns. Throughput appears after two scrape
intervals (~1 min) because rates need two samples.

---

## D. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `curl .../snmp?...` empty or `snmp_request_errors` rising | SNMP off, wrong community, or host allowlist on the switch | redo section A; test with `snmpwalk` |
| Prometheus target **DOWN**, error "context deadline exceeded" | switch unreachable from the appliance, or UDP/161 filtered | check `192.168.1.50` reachable on the mgmt VLAN; firewall |
| Target **DOWN**, exporter up | wrong `auth`/`module` name, or exporter can't read `snmp.yml` | names must match `snmp.yml` (`switch_v2`, `if_mib`); check the file is mounted |
| Data present but ports show as `ifIndex` numbers, no names | switch doesn't fill `ifName`/`ifDescr` | harmless; graph by `ifIndex`, or add an `ifAlias` per port on the switch |
| Dashboard empty but query works in Explore | datasource mismatch | dashboard uses datasource uid `xs-prometheus` (provisioned) |
| Counter resets / spikes | switch reboot or 32-bit wrap | this config uses 64-bit HC counters; `rate()` handles resets |

## E. Adding more switches / more OIDs

- **Another switch:** add its IP under the `snmp-switch` job's `static_configs`
  in `prometheus.yml` (give it a `device` label). Same community → nothing else
  changes. Different community → add another `auth` in `snmp.yml` and a second
  scrape job referencing it.
- **More metrics** (PoE, CPU, temperature, VLAN tables): those live under
  vendor-private enterprise OIDs. Add the OIDs to a new `walk`/`metrics` block
  in `snmp.yml`, or regenerate a fuller config with the upstream
  `snmp_exporter` generator and a ZyXEL MIB. The IF-MIB covered here is the
  portable, standards-based core that works on any managed switch.
