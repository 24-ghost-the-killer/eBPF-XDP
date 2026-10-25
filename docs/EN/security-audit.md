<!-- Language: **English** · [Dansk](../DK/security-audit.md) -->

# Security audit & production-hardening

Audit of the xdp-sentinel dataplane, control plane, ML pipeline and the live
deployment, for a school-network production rollout (router + managed switches
+ inline server). Grounded in a line-level review of `ebpf/src/` and the
running appliance.

## Verdict

- **Design: sound.** Fixed-cost XDP pipeline, safe-default-zero config, strong
  RFC-compliant parsing, fail-open-for-availability / fail-closed-for-privilege.
- **Production-ready: no — needs hardening.** The gaps are operational, not
  architectural.
- **Overall risk as deployed: HIGH** (committed credential, agent runs as root
  with CAP_SYS_ADMIN, SSH password auth, no standing spoofed-flood cap).

## Top findings (ranked)

### P1 — Committed SNMP community (Critical)
`deploy/monitoring/snmp-exporter/README.md` contained the live read community
in plaintext (4 places) **and in git history**. A v2c community is a read
password for the switch.
- **Fix:** working tree sanitized to `<SWITCH_SNMP_COMMUNITY>`. **Still required:**
  rotate the community on the switch (it is burned — it was public), and scrub
  git history:
  ```sh
  pip install git-filter-repo
  # put the OLD community (now burned) on the left of ==>, do NOT commit this file:
  printf '%s==><SWITCH_SNMP_COMMUNITY>\n' "$OLD_COMMUNITY" > /tmp/scrub.txt
  git filter-repo --replace-text /tmp/scrub.txt && rm -f /tmp/scrub.txt
  git push --force-with-lease --all     # coordinate: rewrites public history
  ```
  Keep the real value only in the gitignored `snmp.yml` / `.env`.

### P2 — Agent runs as root with CAP_SYS_ADMIN (High)
Deployed `sentinel-agent.service` runs as **root**, bounding set
`CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_SYS_ADMIN CAP_NET_BIND_SERVICE`
— far broader than the threat model's "CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN,
dedicated user." An agent compromise = full box + dataplane control.
- **Fix (step 1, low risk):** drop to `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN`.
- **Fix (step 2, follow-on):** `User=xs` + `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN`,
  with the bpffs pins chowned to the `xs` group (the pins are mode-700 root
  today, which is why it runs as root). `KillMode=process` means the dataplane
  survives the restart, so this is recoverable.

### P3 — SSH password auth + weak password (High)
`PasswordAuthentication yes`; the operator password is weak. Inline box.
- **Fix:** `PasswordAuthentication no` (key-only) after confirming key access
  from every admin machine; rotate the password.

### P4 — No standing spoofed-flood mitigation (High, deployed)
Per-source rate-limiting seeds-and-passes every "new" source
(`policy.h:xs_autorl_*`), so a spoofed-source flood is never per-source limited.
The aggregate backstop `XS_CFG_GLOBAL_RL` (`xdp_main.c:108`) is **off** and has
**no CLI** — only the risk engine (auto-mitigate, which is enabled) turns it on
reactively.
- **Fix:** add a `sentinelctl` global-RL knob (or config field) and set a static
  aggregate cap sized to the uplink; until then, rely on auto-mitigate + alerting.

### P5 — No saturation / collateral alerting (Medium)
No alerts for NIC RX drops, softirq saturation, ringbuf sample drops, policy-map
fullness, or collateral (drops of `dynamic_exempt` sources).
- **Fix:** Prometheus rules (see `deploy/monitoring/prometheus/rules/`).

### P6 — CPU isolation (Medium)
Deployed unit has no `CPUAffinity`; the documented `CPUAffinity=10-15` is invalid
on this 8-core box. A flood on RX cores can starve the control plane.
- **Fix:** steer NIC IRQs to cores 0–3; `CPUAffinity=4-7` on the agent.

### P7 — Parser-evasion: UNSUP frames pass all L4 mitigations (Medium)
`XS_PARSE_UNSUP_VLAN_DEPTH` (>2 VLAN tags) and `XS_PARSE_UNSUP_IPV6_EXT_DEPTH`
(>6 ext headers) return `XDP_PASS` (`xdp_main.c:34-35`) and leave `l4_parsed=0`,
so UDP/TCP/flag/ICMP/port drops and conntrack never apply. An attacker can wrap
a flood in extra VLAN tags / ext headers to skip L4 mitigations.
- **Fix:** add `XS_CFG_DROP_UNSUP`, or at minimum alert on `parse_unsup_*` rate.

### P8 — No CI secret scanning / dependency audit (Medium)
The committed secret proves the gap.
- **Fix:** `.github/workflows/security.yml` added (gitleaks + cargo-audit/deny).

### P9 — ML not operational (detection gap, not a vuln)
Models ship trained on `synthetic.csv` (pr_auc=1.0, i.e. trivially separable);
no ClickHouse sink, empty feature tables, inference not wired into the agent.
- **Fix:** real-data collector now running
  (`/var/lib/xdp-sentinel/realdata/`); retrain the unsupervised anomaly/baseline
  on real benign after days of collection; lab (pktgen/TRex) for labeled attacks.

### P10 — Manual mitigation flags are not durable (Medium)
`sentinelctl config --drop-*` changes are **overwritten at runtime by the
auto-mitigate risk engine's baseline-restore** on the interfaces it manages
(observed: `vlan10`'s `drop_malformed|drop_bad_tcp_flags` reverted to
`check_allow|conntrack` with no agent restart; `vlan20`, which auto-mitigate does
not manage, kept them). The agent `Config` struct (`userspace/agent/src/config.rs`,
`deny_unknown_fields`) has **no field for baseline protective flags**, so they
cannot be set durably via config.
- **Impact:** always-on validity drops can't be pinned on the internet-facing
  interface; it is protected only *reactively* (auto-mitigate enables drops
  during an attack, then restores the observe-only baseline).
- **Fix (agent feature):** add optional per-interface baseline flags to
  `Interface` (e.g. `drop_malformed`, `drop_bad_tcp_flags`), have the agent write
  them to `xs_config` on attach, and make the auto-mitigate *restore* target
  those flags instead of zero. Files: `userspace/agent/src/config.rs` +
  the attach/apply and risk-engine restore paths. Needs rebuild+deploy.

### P11 — Feature collector could poison the benign ML set (Fixed)
The real-data collector labelled every window `benign`, so a real attack during
collection contaminated the training set (observed: 126 windows from an hping
burst). **Fixed:** the collector now routes anomalous windows (high
pps_zscore/udp_pps/pps/bad-flags/frag) to a separate `windows.csv.suspect` file;
the existing 126 were quarantined to `windows.quarantine.csv`.

## Dataplane review (ebpf/src/) — strengths confirmed

- `xdp_main.c` — fixed-cost; safe default `XDP_PASS`; `xs_parse` is a `__noinline`
  global fn (verifier-state firewall); `xs_opaque(rc)` defeats a clang-21
  bounds-check deletion.
- `parsers.h` — every read bounded vs `data_end`; IHL/totlen/plen/UDP-len
  masked+validated; VLAN depth ≤2, IPv6 ext ≤6 via scalar-offset+mask; RFC 1858
  tiny-fragment, RFC 6946 atomic fragments, LAND, bad-flags. `SEC("xdp")` (not
  `.frags`) ⇒ no multi-buffer truncation evasion.
- `policy.h` — block table is HASH not LRU (attacker can't churn a live block);
  IPv6 keyed on /64; in-dataplane TTL expiry (CLOCK_MONOTONIC); unknown action
  fails open.
- `rate_limit.h` — GCRA correct; CAS retried once then nonconforming (safe).
- `telemetry*.h` — per-CPU counters; bounded sampling (geometric skip + per-CPU
  token bucket + no-wakeup ringbuf, failed reserve counted, never blocks).

Residual dataplane risks: UNSUP evasion (P7); LRU eviction of conntrack/rate
state under high-cardinality floods (keep `DROP_UNTRACKED` off except under a
confirmed ACK/RST flood); fixed compile-time map sizes need an agent-side entry
budget + expired-entry GC.

## School-network deployment

Topology: Router (isolated from Switch 1) → Switch 1 → Middleman switch →
**Server (xdp-sentinel)** → Middleman → Switch 2.

- **Mode:** inline bridge. One VLAN per segment, tagged on the server trunk;
  bridge them; XDP on each VLAN subif. The middleman switch forces all
  inter-segment traffic through the server.
- **Golden check:** no two segments share a VLAN except via the server trunk, or
  traffic silently bypasses the appliance. Verify with switch MAC tables +
  `tcpdump -eni <trunk>` (all VLAN tags present).
- **Risks:** single in-path point (keep a labeled bypass cable); ~1 Gbps
  generic-XDP ceiling; intra-segment traffic on one switch is invisible
  (one-VLAN-per-host to close it); VLAN double-tagging (set each trunk's
  native/PVID to a dedicated empty VLAN, never VLAN 1).
- **Management:** separate management VLAN (not shared with data); switch admin
  over HTTPS, restricted; Grafana over VPN/tunnel; allowlist the mgmt prefix
  `full` only on the mgmt interface.
- **Fail-safe:** STP off, bridge forwards immediately; agent death ⇒
  observe-only; keep `xs-cutover` auto-rollback armed.

## Hardening checklist

- [ ] Rotate SNMP community; (done) sanitize README; scrub git history
- [ ] Agent caps → `CAP_BPF CAP_PERFMON CAP_NET_ADMIN`; then `User=xs`
- [ ] SSH key-only + rotate operator password
- [ ] Standing aggregate rate cap (`GLOBAL_RL`) sized to uplink
- [ ] Alerts: NIC RX drops, softirq, ringbuf drops, map fullness, collateral
- [ ] `CPUAffinity` to valid cores; NIC IRQ steering
- [ ] Handle UNSUP parser-evasion (drop flag or alert)
- [ ] (done) CI secret scanning + dependency audit
- [ ] Verify config-writer strictness (`deny_unknown_fields`, TTL/budget/overlap)
- [ ] Wire real-data retrain; lab for labeled attacks
- [ ] Runbooks, tested rollback, bypass drill; validate on target kernel
