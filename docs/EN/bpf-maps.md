<!-- Language: **English** · [Dansk](../DK/bpf-maps.md) -->

# G. BPF map design

All maps are defined in `ebpf/src/maps.h` (added phase by phase), pinned per
interface under `/sys/fs/bpf/xdp-sentinel/<ifname>/`, and mirrored in
`userspace/common/src/abi.rs`. Every value struct has a fixed size with
reserved padding, because libbpf refuses to reuse a pinned map whose
key/value size changed, and an upgrade must not silently reset policies.

Status: `xs_stats` and `xs_config` are implemented (Phase 1). The rest is the
design that later phases implement.

## Map-type evaluation

| Type | Lookup cost from XDP | Writes from many CPUs | Memory | Used for | Rejected for |
|---|---|---|---|---|---|
| `ARRAY` | inlined by the verifier (a few instructions) | shared cache lines → read-mostly data only | `max_entries × value` | config, service config | any per-packet counter (false sharing) |
| `PERCPU_ARRAY` | helper call (inlined on ≥ 6.10 kernels) | none: each CPU owns its copy | `× nr_possible_cpus` | counters, per-service state, HLL, port histogram, sampling state | large sparse key spaces |
| `HASH` | jhash + bucket walk; ~20–50 ns, dominated by cache misses | per-bucket lock on update; lookups lock-free (RCU) | preallocated by default | control-plane-owned exact-match tables (source policies) | attacker-keyed tables (exhaustion) |
| `LRU_HASH` | as HASH, plus LRU maintenance on insert | eviction lock (global LRU) or per-CPU lists (`BPF_F_NO_COMMON_LRU`) | preallocated | — | policies (would silently evict active mitigations) |
| `PERCPU_HASH` | as HASH | none for values | `entries × cpus × value` | — (no attacker-keyed table may be non-LRU) | |
| `LRU_PERCPU_HASH` | as LRU_HASH | none for values | `entries × cpus × value` | per-source heavy-hitter statistics | anything large (memory × CPUs) |
| `LPM_TRIE` | trie walk; tens of ns for small tries, more for large IPv6 tries | lock on update | `BPF_F_NO_PREALLOC` mandatory | allowlists, CIDR rules, destination → service | per-packet exact matches (HASH is faster) |
| `RINGBUF` | `bpf_ringbuf_reserve/submit` (spinlock on reserve, shared) | MPSC | fixed power-of-two size | sampled headers, rare events | per-packet telemetry |
| `ARRAY_OF_MAPS` | +1 lookup | — | — | atomic whole-set replacement of allowlist/CIDR tries | — |

Principles:

1. **Per-packet writes go to per-CPU memory.** The only shared writable
   state on the packet path is the GCRA word of a *rate-limited* source, and
   those are rare by construction
   ([policy-engine.md](policy-engine.md#rate-limiting)).
2. **Attacker-keyed tables are LRU and admission-controlled**; tables the
   attacker cannot insert into (policies, services) are plain HASH/ARRAY/LPM
   owned by the control plane.
3. **Exact match before prefix match**; LPM tries are consulted only when
   non-empty (config bits).
4. **Large maps live on the NIC's NUMA node** (`numa_node` map attribute
   set by the loader from `/sys/class/net/<if>/device/numa_node`).

## Map inventory

Default sizes (configurable); memory for 32 possible CPUs.

| # | Name | Type | Key → value | Entries | Memory | Phase | Requirement |
|---|---|---|---|---|---|---|---|
| 1 | `xs_stats` | PERCPU_ARRAY | `u32` → `struct xs_stats` (128 × {pkts, bytes}) | 1 | 64 KiB | **1 ✅** | per-CPU packet and byte counters |
| 2 | `xs_config` | ARRAY | `u32` → `struct xs_config` (64 B) | 1 | 64 B | **1 ✅** | configuration |
| 3 | `xs_allow_v4` / `xs_allow_v6` | LPM_TRIE (inner) via ARRAY_OF_MAPS | `{prefixlen, addr}` → `{trust, rule_id}` | 16 384 each | ~2 MiB | 2 | allowlists |
| 4 | `xs_cidr_policy_v4/v6` | LPM_TRIE (inner) via ARRAY_OF_MAPS | `{prefixlen, addr}` → `struct xs_policy` | 65 536 each | ~16 MiB | 2 | blocked IPv4/IPv6 CIDRs |
| 5 | `xs_src_policy_v4` | HASH | `__be32` → `struct xs_policy` | 1 048 576 | ~180 MiB | 2–3 | blocked IPv4, temporary rate limits, policy state |
| 6 | `xs_src_policy_v6` | HASH | `u64` (/64 prefix) → `struct xs_policy` | 262 144 | ~48 MiB | 2–3 | blocked IPv6, rate limits |
| 7 | `xs_dst_service_v4/v6` | LPM_TRIE | `{prefixlen, addr}` → `u16 service_id` | 4 096 | < 1 MiB | 3 | destination policies |
| 8 | `xs_service_cfg` | ARRAY | `u32 service_id` → `struct xs_service_cfg` | 4 096 | 512 KiB | 3 | destination policies, attack state |
| 9 | `xs_service_state` | PERCPU_ARRAY | `u32 service_id` → `struct xs_service_state` | 4 096 | 16 MiB | 3 | per-destination statistics |
| 10 | `xs_src_stats_v4` / `_v6` | LRU_PERCPU_HASH, `BPF_F_NO_COMMON_LRU` | `__be32` / `u64` → `struct xs_src_stats` (64 B) | 32 768 / 8 192 | ~80 MiB | 5 | per-source statistics |
| 11 | `xs_hll` | PERCPU_ARRAY | `u32 epoch` (0/1) → 4 × 4096 u8 registers | 2 | 1 MiB | 5 | unique src/dst/port/flow counts |
| 12 | `xs_dport_hist` | PERCPU_ARRAY | `u32 dport` → `{u32 tcp, u32 udp}` | 65 536 | 16 MiB | 5 | port distribution / entropy |
| 13 | `xs_cpu_state` | PERCPU_ARRAY | `u32` → `struct xs_cpu_state` | 1 | 2 KiB | 5 | sampling state |
| 14 | `xs_samples` | RINGBUF | 64-byte `struct xs_sample` records | 16 MiB | 16 MiB | 5 | sampled telemetry |
| 15 | `xs_known_good_v4/v6` | BLOOM_FILTER (≥ 5.16) | source address (value-only map) | 1 048 576 | ~1.2 MiB (10 bits/entry, ~1% FP) | 13 | known-good-first service protection ([policy-engine.md](policy-engine.md#service-protection-distributed-attacks)) |

Total at defaults, 32 CPUs: **≈ 380 MiB**, dominated by the preallocated
IPv4 policy hash (sized for 1 M simultaneous mitigations). Halve it on
smaller boxes.

### 1. `xs_stats` (implemented)

One element holding all 128 counter slots, so a packet needs exactly **one**
lookup regardless of how many counters it touches; increments are plain
stores into the CPU's own 2 KiB block. The ~80 unused slots leave room for
new counters without changing the value size (pinned-map compatibility).
Slot numbers are ABI: dashboards and history key on them.

### 2. `xs_config` (implemented)

```c
struct xs_config {              /* 64 bytes */
	__u32 abi_version;
	__u32 flags;                /* P1: DROP_MALFORMED | DROP_BAD_TCP_FLAGS | DROP_FRAGMENTS
	                               P2: ALLOW_NONEMPTY | HAS_CIDR_POLICY
	                               P5: SAMPLING | HLL | DPORT_HIST */
	__u64 reserved[7];          /* P5: hll_epoch, sample_one_in, sample_cap_per_cpu,
	                               hh_admit_mask, ... */
};
```

A plain ARRAY because every CPU reads it on every packet and userspace
writes it rarely: the cache line stays shared and clean everywhere. The
zero value is the safe default (observe only), so a freshly created map
needs no initialisation to be safe.

### 3–4. Allowlists and CIDR policies

LPM tries keyed by `struct { __u32 prefixlen; __u8 addr[4|16]; }`. Each is
the single inner map of an `ARRAY_OF_MAPS`, so the agent builds a complete
new trie off to the side and swaps it in with one update: a reload is never
observed half-applied. The extra outer lookup is paid only when
`ALLOW_NONEMPTY` / `HAS_CIDR_POLICY` is set.

Allowlist `trust` values:
* `full`: pass immediately, skip all mitigation (management networks
  reachable only on trusted paths);
* `dynamic_exempt`: immune to dynamic (ML/heuristic) policies, still
  subject to static safety caps (service budgets). Default for anything
  reachable from the internet, because allowlisted source addresses can be
  spoofed.

### 5–6. Source policies

```c
struct xs_gcra {                /* 16 bytes, see policy-engine.md */
	__u64 tat_ns;               /* theoretical arrival time; CAS-updated by XDP */
	__u32 interval_ns;          /* 1e9 / rate; 0 = class not limited */
	__u32 tolerance_ns;         /* interval × (burst - 1) */
};

struct xs_policy {              /* 128 bytes */
	__u64 expires_ns;           /* CLOCK_MONOTONIC; XDP ignores the entry after it */
	__u32 policy_id;            /* joins to policy_decisions in ClickHouse */
	__u8  action[4];            /* per traffic class: ANY, TCP_SYN, UDP, ICMP */
	__u16 flags;                /* SAMPLE_ALL, COUNT_ONLY, ... */
	__u8  reason;               /* enum, for drop accounting */
	__u8  _pad[5];
	struct xs_gcra pkt[4];      /* per-class packet-rate limiters */
	struct xs_gcra byte_any;    /* bytes/s limiter for class ANY (increment = len) */
	__u8  reserved[16];
};
```

* **HASH, not LRU:** only the control plane inserts; an LRU would silently
  evict an active mitigation under pressure. The policy engine keeps a
  budget below `max_entries` and escalates to CIDR/service-level mitigation
  instead of overflowing.
* **Preallocated** (default): deterministic lookup latency, no allocation
  on update.
* **IPv6 keyed by /64:** an IPv6 end site gets at least a /64, so a /128
  block is trivially evaded by rotating addresses. Finer or coarser IPv6
  blocks go through the LPM map.
* **Expiry enforced in XDP** (`now >= expires_ns` → entry ignored), so
  TTLs hold even if the agent is dead. The agent deletes expired entries in
  a 1 s GC sweep to free capacity. `bpf_ktime_get_ns()` is called only when
  an entry was found.

### 7-9. Destination services

A *service* is a protected destination prefix (a host /32 or a subnet)
with its own thresholds and baselines. Destinations are known in advance
and inserted only by the control plane, so traffic cannot exhaust these
maps.

```c
struct xs_service_cfg {         /* 128 bytes, ARRAY */
	__u32 flags;                /* PROTECT_ACTIVE, KNOWN_GOOD_ONLY, DROP_FRAGMENTS, ... */
	__u32 state;                /* NORMAL / SUSPECT / UNDER_ATTACK (attack state) */
	__u32 budget_pps[4];        /* ANY, TCP_SYN, UDP, ICMP: per-CPU share */
	__u32 burst[4];
	__u32 reserved[18];
};

struct xs_service_state {       /* 128 bytes, PERCPU_ARRAY */
	struct xs_counter total;    /* exact per-service pkts/bytes */
	__u64 syn, synack, rst, udp, icmp, frag, malformed, dropped;
	struct { __u64 tokens_x1024; __u64 last_ns; } tb[4]; /* per-CPU token buckets */
};
```

Budgets are per CPU (`budget / n_rx_queues`): aggregate traffic from many
sources is spread evenly by RSS, so per-CPU buckets approximate one shared
bucket closely with no shared writes. This holds only for many-source
aggregates; per-source limits use shared GCRA state (5–6).

### 10. Per-source heavy-hitter table

```c
struct xs_src_stats {           /* 64 bytes, per CPU */
	__u64 packets, bytes;
	__u32 syn, udp, icmp, rst, fin, bad, dropped, _pad;
	__u64 dport_bits;           /* bit (dport * 0x9E3779B1 >> 26): linear-counting sketch */
	__u64 last_ns;
};
```

LRU_PERCPU_HASH because the key space is attacker controlled (bounded,
evicting) and a single heavy source is spread by RSS across many queues;
per-CPU values avoid cache-line ping-pong between those CPUs. Cost is
memory × CPUs, hence the modest default size (32 k IPv4, 8 k IPv6 →
~80 MiB at 32 CPUs).

**Probabilistic admission.** A lookup miss inserts the source only if
`(bpf_get_prandom_u32() & hh_admit_mask) == 0` (default 1/1024). A source
sending N packets is admitted after ~1024 packets on average, while a
random-spoofed flood (one packet per address) creates at most pps/1024
inserts per second (≤ 14.5 k/s at 64-byte line rate) instead of 14.88 M/s.
Real heavy hitters are touched constantly and never reach the LRU tail.
The undercount (~1/p packets) is corrected in userspace. Sources with an
active policy are admitted unconditionally, so drops per policed source are
exact. A count-min sketch in XDP was considered and rejected: d hash
computations per packet plus epoch management, for the same heavy-hitter
guarantee.

`BPF_F_NO_COMMON_LRU` gives each CPU its own LRU and free list, removing
the global LRU lock that would serialise inserts during churn; lookups
still use one shared hash table.

`dport_bits` is a 64-bit linear-counting sketch of distinct destination
ports (tells 1, ~10 and 100+ ports apart: vertical scans), updated with a
plain OR and merged across CPUs with OR in userspace.

### 11. `xs_hll`

Four HyperLogLog sketches with precision p = 12 (4096 one-byte registers,
standard error 1.04/√4096 ≈ 1.6%): distinct source addresses, destination
addresses, destination ports and 5-tuples. Per packet and sketch: one
64-bit mixing hash (IPv4: multiply–xorshift; IPv6 and 5-tuples: fold then
mix), a branch-free leading-zero count, one compare-and-store into the
CPU's own register. Registers are **max-mergeable**: userspace merges CPUs
with an element-wise max.

HLL registers cannot be diffed like counters, so the map has two epochs.
Each window the collector flips `hll_epoch` in `xs_config`, waits a grace
period (≥ 1 ms, longer than any XDP invocation), reads the now-inactive
epoch from all CPUs and zeroes it. A packet racing the flip lands in the
old epoch and is counted in the next window, an acceptable error for
cardinality estimates.

### 12. `xs_dport_hist`

Exact per-destination-port packet counts (TCP and UDP) per CPU: 512 KiB
per CPU. Monotonic u32 counters; deltas are wrap-safe as long as the read
period is shorter than 2³² / (per-CPU per-port rate), ≥ 200 s at 20 Mpps.
Read with `BPF_MAP_LOOKUP_BATCH` every 5 s. Feeds port-entropy and
port-concentration features. A config bit disables it if a benchmark shows
the extra lookup matters.

### 13. `xs_cpu_state`

Per-CPU sampling state: a randomised countdown to the next sample (a
geometric skip drawn from `bpf_get_prandom_u32()` at each sample, so
periodic traffic cannot alias with the sampler), a token bucket capping
samples per CPU per second (default 20 k/s/CPU), and per-CPU ring-buffer
drop accounting.

### 14. `xs_samples` ring buffer

```c
struct xs_sample {              /* 64 bytes */
	__u64 ts_ns;
	union xs_addr saddr, daddr; /* 32 */
	__be16 sport, dport;
	__u16 pkt_len, ip_id;
	__u8  l4_proto, tcp_flags, ttl, verdict;
	__u8  rx_queue, parse_rc, reason, flags;
	__u16 tcp_window, _pad;
};
```

* **One shared RINGBUF** (MPSC): reservation takes a spinlock, but at the
  capped sample rate contention is negligible. Per-CPU ring buffers (via
  `ARRAY_OF_MAPS` keyed by CPU) are the upgrade path if profiling ever
  shows contention.
* **No per-record wakeups:** records are submitted with `BPF_RB_NO_WAKEUP`
  (each wakeup is an irq_work); the collector drains with
  `ring_buffer__consume()` every 5 ms. Above 50% fill
  (`bpf_ringbuf_query(BPF_RB_AVAIL_DATA)`) XDP forces a wakeup.
* **Loss is counted, never blocking:** a failed reserve increments a
  per-CPU counter and the packet proceeds.
* Sizing: 16 MiB = 262 k records ≈ 400 ms of samples at the maximum
  aggregate cap (32 CPUs × 20 k/s): the collector may stall 400 ms before
  any loss.

## Userspace access patterns

| Map | Reader | Period | Method |
|---|---|---|---|
| `xs_stats` | collector | 1 s (100 ms sub-ticks) | single `lookup` (all CPUs) |
| `xs_service_state` | collector | 1 s | `lookup_batch` over active service ids |
| `xs_hll` | collector | 1 s | epoch flip → lookup inactive → zero |
| `xs_src_stats_*` | collector | 5 s | `lookup_batch` over the table (≤ 40 k keys) |
| `xs_dport_hist` | collector | 5 s | `lookup_batch` |
| `xs_samples` | ringbuf thread | continuous (5 ms) | `ring_buffer__consume` |
| `xs_src_policy_*` | policy engine | on change / 1 s GC | `update_batch` / `delete_batch`; full read at startup |
| config, allowlists, services | agent | on config change | single updates / inner-map swap |
