<!-- Language: **English** · [Dansk](../DK/feature-schema.md) -->

# I. Feature schema

This document is the normative definition of every feature the control
plane computes. In Phase 6 it is materialised as
`ml/feature_schema/v1.yaml`; the SHA-256 of the canonicalised YAML is the
**schema hash** carried by every feature batch, every ClickHouse row and
every model artefact. A model is only ever fed vectors whose schema hash
matches the one it was trained on.

## Conventions

* **Window:** 1 s tumbling windows aligned to the monotonic clock
  (`window_start` stored in wall-clock UTC). Per-source tables are read every
  5 s, so per-source features use 5 s windows.
* **Sub-window:** the collector reads the (single-lookup) global and
  service counters every 100 ms, giving 10 sub-samples per window for
  burstiness and periodicity.
* **Scopes:** `global` (per interface), `service` (per protected
  destination; [bpf-maps.md](bpf-maps.md#7-9-destination-services)),
  `source` (per admitted heavy hitter; IPv4 /32 or IPv6 /64), `l7`
  (optional, from reverse-proxy logs).
* **Provenance:**
  * `C` exact per-CPU counters (XDP),
  * `H` HyperLogLog (XDP registers, userspace estimate, ~1.6% error),
  * `P` exact per-port histogram (XDP),
  * `S` sampled headers (ring buffer, 1-in-N, capped): estimates,
  * `D` derived in userspace from other features or history.
  `S` features carry a companion `sample_coverage` (samples used / packets
  in window); models receive it as an input and the risk engine discounts
  confidence when it is low.
* **Rates** are per second over the *measured* window duration. **Ratios**
  use `x / (y + 1)` to stay finite. **Entropies** are Shannon entropy in
  bits normalised by `log2(k)` for k observed symbols (0..1).
* **Missing** (e.g. no TCP in the window): `NaN`, never 0; tree models
  handle missing values natively and 0 is a meaningful value.

## Global and service features

### Traffic volume

| Feature | Prov | Definition |
|---|---|---|
| `packets` | C | packets in window |
| `bytes` | C | bytes in window (L2 frame length, no FCS) |
| `pps` | C | `packets / dt` |
| `bps` | C | `8 · bytes / dt` |
| `drop_pps` | C | packets dropped by any mitigation / dt |
| `pps_baseline_ratio` | D | `pps / baseline_pps(scope, hour_of_week)`; baseline = rolling median of the same hour-of-week over the last 4 weeks |

### TCP

| Feature | Prov | Definition |
|---|---|---|
| `tcp_syn_rate` | C | SYN without ACK per s |
| `tcp_synack_rate` | C | SYN+ACK per s |
| `tcp_ack_rate` | C | pure ACK (no SYN/FIN/RST) per s |
| `tcp_rst_rate` | C | RST per s |
| `tcp_fin_rate` | C | FIN per s |
| `tcp_syn_ack_ratio` | D | `syn / (ack + 1)`; SYN-flood signature: many SYNs, few handshake-completing ACKs |
| `tcp_syn_share` | D | `syn / (tcp + 1)` |
| `tcp_bad_flags_rate` | C | NULL/XMAS/SYN+FIN/... per s |

### UDP, ICMP, fragments

| Feature | Prov | Definition |
|---|---|---|
| `udp_pps`, `udp_bps` | C | |
| `udp_dport_top1_share` | P | share of UDP packets going to the most-hit destination port (destination concentration) |
| `udp_sport_top1_share` | S | share of UDP packets from the most common source port (53, 123, 1900, 11211, 389… = reflection) |
| `udp_len_mismatch_rate` | C | |
| `icmp_pps`, `icmp_share` | C | ICMP + ICMPv6 |
| `frag_rate`, `frag_share` | C | first + later fragments |

### Addresses

| Feature | Prov | Definition |
|---|---|---|
| `unique_src` | H | distinct source addresses |
| `unique_dst` | H | distinct destination addresses |
| `new_src` | H+D | `|HLL(t) ∪ HLL(t-1..t-10)| − |HLL(t-1..t-10)|`: sources not seen in the previous 10 s (HLL union is an exact register max) |
| `src_entropy` | S | normalised entropy of source addresses in samples |
| `dst_entropy` | S | same for destinations |
| `top1_src_share`, `top10_src_share` | C (heavy hitters) | share of scope packets from the top 1 / top 10 sources |
| `src_prefix24_diversity` | S | distinct /24 (v4) or /48 (v6) prefixes per distinct source in samples: ~1 for random spoofing, ≪ 1 for botnets clustered in providers |
| `src_ttl_stddev` | S | std-dev of TTL/hop limit; spoofed floods from one generator show implausible uniformity or randomness |

### Ports

| Feature | Prov | Definition |
|---|---|---|
| `unique_dport` | H | distinct destination ports |
| `unique_sport` | S | distinct source ports in samples |
| `dport_entropy` | P | normalised entropy of the exact destination-port histogram |
| `sport_entropy` | S | |

### Packet sizes

| Feature | Prov | Definition |
|---|---|---|
| `mean_pkt_size` | C | `bytes / packets` |
| `pkt_size_stddev` | S | |
| `pkt_size_p05`, `pkt_size_p50`, `pkt_size_p95` | S | |
| `pkt_size_mode_share` | S | share of the most common exact size (generators repeat one size) |

### Flows and connections

| Feature | Prov | Definition |
|---|---|---|
| `unique_flows` | H | distinct 5-tuples |
| `new_flow_rate` | H+D | new 5-tuples per s (HLL union method, as `new_src`) |
| `flows_per_src` | D | `unique_flows / unique_src` |
| `connection_rate` | C | = `tcp_syn_rate` (connection attempts observable at L3/L4) |
| `handshake_completion` | D | `tcp_ack_rate / (tcp_syn_rate + 1)` over 5 s; meaningful only where return traffic is symmetric |
| `flow_duration_p50`, `flow_duration_p95` | S | from userspace reconstruction of sampled flows; biased towards long/heavy flows, so used as a relative feature |

### Temporal

| Feature | Prov | Definition |
|---|---|---|
| `pps_accel` | D | `(pps_t − pps_{t−1}) / dt` |
| `pps_zscore` | D | `(pps − median) / (1.4826 · MAD)` against the same hour-of-week baseline (robust) |
| `burstiness_cv` | C (sub-windows) | coefficient of variation of the 10 × 100 ms packet counts |
| `fano_factor` | C (sub-windows) | variance / mean of sub-window counts (≫ 1 bursty, ≈ 1 Poisson, ≪ 1 paced) |
| `periodicity_strength`, `periodicity_period` | D | maximum autocorrelation (lags 200 ms – 30 s) of the last 60 s of 100 ms counts, and its lag |

### Protocol distribution and validity

`share_tcp`, `share_udp`, `share_icmp`, `share_other`, `share_ipv6` (C);
`malformed_rate` (C, sum of `parse_err_*`), `unsupported_rate` (C).

### Coordinated / distributed attack features (`service` scope)

The inputs to [ml.md, distributed attack detection](ml.md#distributed-attack-detection-14):
many sources, one target, same behaviour, same time.

| Feature | Prov | Definition |
|---|---|---|
| `sig_top1_share` | S | share of the service's sampled packets carrying the most common *behaviour signature* `(proto, dport, tcp_flags, size bucket (32 B), ttl bucket (8))` |
| `sig_top1_sources` | S | distinct sources contributing to that signature |
| `onset_sync` | D | fraction of this window's active sources first seen (userspace) within the last 10 s |
| `known_good_share` | S+D | share of packets from the service's *known-good* sources (completed handshakes / normal traffic in the 24 h before the anomaly; Bloom filter in userspace) |
| `src_cv_pps` | C (heavy hitters) | coefficient of variation of per-source pps among active heavy hitters; botnets under one controller are unusually uniform |

## Per-source features (`source` scope, 5 s windows)

For admitted heavy hitters (bounded count) and sources under investigation
(the `SAMPLE` action raises their sampling rate).

| Feature | Prov | Definition |
|---|---|---|
| `src_pps`, `src_bps` | C | per-CPU sums, corrected for admission (+1/p) |
| `src_syn_rate`, `src_udp_pps`, `src_icmp_pps` | C | |
| `src_syn_share` | D | SYN / TCP |
| `src_distinct_dports` | C | linear-counting estimate from OR-merged 64-bit `dport_bits` (saturates at ~250 = "many") |
| `src_distinct_dsts` | S | |
| `src_bad_share` | C | malformed + bad-flag packets / packets |
| `src_pkt_size_mode_share` | S | repeated packet sizes |
| `src_iat_cv` | S | coefficient of variation of the source's sampled inter-arrival times (≥ 20 samples; very low = machine-paced) |
| `src_ttl_distinct` | S | distinct TTL values; > 2 from one address suggests spoofing |
| `src_active_windows` | D | consecutive active windows (persistence) |
| `src_age_s` | D | time since first seen (userspace history, capped at 24 h) |
| `src_prefix_cohort` | D | active heavy hitters in the same /24 (/48) |
| `src_share_of_service` | D | this source's share of its top destination service |

## Optional L7 features (`l7` scope)

Only when a reverse proxy (nginx/Envoy/HAProxy) ships access logs to
ClickHouse; computed by the agent from ClickHouse, never in XDP:
`req_rate`, `method_entropy`, `path_entropy`, `path_top1_share`,
`status_4xx_share`, `status_5xx_share`, `ua_distinct`, `ua_entropy`,
`tls_fp_distinct` (JA4/JA3 if exported), `req_iat_cv`,
`session_duration_p50`, per client address and per service.

## What is computed where

See [architecture.md F.5](architecture.md#f5-what-is-computed-in-xdp-vs-userspace).
XDP maintains counters, registers, histograms and samples (fixed-cost,
mergeable); anything with division, logarithms, sorting, history or joins
is userspace.

## Flow key

### Definition

Userspace flow records are keyed by:

```rust
#[repr(C)]
struct FlowKey {            // 40 bytes, hashed with ahash
    src: [u8; 16],          // IPv4 as ::ffff:a.b.c.d
    dst: [u8; 16],
    sport: u16,             // 0 for port-less protocols / non-first fragments
    dport: u16,
    proto: u8,
    dir: u8,                // 0 = ingress on outside iface, 1 = egress / inside
    ifindex: u16,           // compressed interface id, not the raw ifindex
}
```

VLAN id is **not** in the default key: with RX VLAN offload it is not
reliably visible, and in most deployments addresses are unique across VLANs.
Deployments with overlapping address space per VLAN set
`flow_key.include_vlan = true`, replacing `ifindex` with `(ifindex, vid)`.

### Why flows are not tracked in XDP

A per-5-tuple table in XDP makes per-packet cost and memory a function of
attacker behaviour: a random-spoofed SYN flood creates a new "flow" per
packet (14.88 M/s at 64-byte line rate). An LRU of any practical size would
turn over every few milliseconds and retain nothing, while paying an insert
(allocation + possible eviction, ~100–200 ns) per packet, more than the
whole per-packet budget. Instead:

| Need | Mechanism | Cost |
|---|---|---|
| number of flows, new-flow rate | per-CPU HLL over the 5-tuple hash | ~5–10 ns/packet, 4 KiB/CPU |
| per-source behaviour | LRU_PERCPU_HASH with probabilistic admission | one lookup per packet; inserts ≤ pps/1024 |
| flow durations, per-flow sizes, IAT | userspace reconstruction from samples | bounded by the sampling cap |

### Userspace memory and CPU

`hashbrown` map `FlowKey → FlowRec` (FlowRec 88 B: first/last seen, sampled
packets/bytes, flag union, size min/max, IAT accumulator), ~150 B/entry with
overhead. Input is bounded by the sample cap (default 20 k samples/s/CPU ×
8 RX CPUs = 160 k/s); capacity 2 M flows (~300 MiB) with eviction by
`last_seen` from a timer wheel. One insert/update per sample ≈ 160 k ops/s,
well under 5% of one core.
