/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * maps.h - BPF map definitions (BTF-defined maps, libbpf >= 0.x syntax).
 *
 * Phase 1 defines only the maps the parser/counter stage needs. The full map
 * plan (policy, rate limit, telemetry, sampling) is in docs/bpf-maps.md;
 * maps are added here phase by phase so that every map in the object is
 * actually exercised by tests.
 *
 * Pinning is decided by the loader (sentinelctl sets a per-interface pin
 * path on every map before load), not by a `pinning` attribute here, so that
 * tests can load the object without touching /sys/fs/bpf and so two
 * interfaces never silently share maps.
 */
#ifndef XS_MAPS_H
#define XS_MAPS_H

#include "compat.h"
#include "abi.h"

/*
 * Global counters. PERCPU_ARRAY with a single element holding every counter:
 *   - per-CPU: no atomics, no cache-line bouncing between RX cores;
 *   - one element: exactly one map lookup per packet regardless of how many
 *     counters are touched; all increments are plain loads/stores into the
 *     same 2 KiB per-CPU block;
 *   - userspace reads all CPUs' copies with a single lookup syscall.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xs_stats);
} xs_stats SEC(".maps");

/*
 * Runtime configuration. Plain ARRAY (not per-CPU): written rarely by
 * userspace, read on every packet by every CPU; the cache line stays shared
 * and clean. ARRAY lookups are inlined by the verifier (no helper call).
 * A zero-filled element (the state right after map creation) is the safe
 * default: observe and count, never drop.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xs_config);
} xs_config SEC(".maps");

/* ---- Phase 2: per-source policies (block / allow-per-IP / rate) ---- */

/*
 * Per-source policy tables. Plain HASH, not LRU: only the control plane
 * inserts, so the attacker cannot churn them, and an LRU could silently
 * evict an active block. Sized for the appliance; tune per host. IPv6 is
 * keyed by the /64 prefix (the smallest address block an end site gets),
 * so per-source rotation within a /64 cannot evade a block.
 *
 * max_entries here are compile-time ceilings. The loader may shrink them
 * with bpf_map__set_max_entries before load on small hosts.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, __be32);            /* source IPv4, network order */
	__type(value, struct xs_policy);
} xs_policy_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 14);
	__type(key, __u64);             /* first 8 bytes of the source IPv6 (/64) */
	__type(value, struct xs_policy);
} xs_policy_v6 SEC(".maps");

/*
 * Allowlist LPM tries (CIDR). Consulted before the policy tables; a FULL
 * trust match passes the packet and skips every mitigation stage.
 * LPM_TRIE mandates BPF_F_NO_PREALLOC.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xs_lpm_v4);
	__type(value, struct xs_allow);
} xs_allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xs_lpm_v6);
	__type(value, struct xs_allow);
} xs_allow_v6 SEC(".maps");

/* ---- Service allowlist (positive security model, default-deny per dst) ---- */
/*
 * xs_protected_v4 lists the destinations under default-deny; xs_service_v4 lists
 * the {dst,proto,dport} services explicitly permitted on them. A packet to a
 * protected destination that matches no service entry is dropped. Both are plain
 * HASH (only the control plane writes, so an attacker cannot churn them) and are
 * consulted only when XS_CFG_SERVICE_ALLOW is set. The appliance protects a
 * handful of hosts with a handful of services, so these are sized small.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __be32);            /* protected destination IPv4, network order */
	__type(value, __u8);            /* presence marker */
} xs_protected_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct xs_service_key);
	__type(value, __u8);            /* presence marker */
} xs_service_v4 SEC(".maps");

/* ---- Phase 3: automatic per-source rate limiting ---- */

/*
 * Per-source GCRA state (the "theoretical arrival time"), one entry per
 * active source. LRU, and *not* per-CPU: the limiter must be shared across
 * the RX cores a source is spread over by RSS, so the state is one 64-bit
 * word updated with a compare-and-swap. LRU bounds memory under source churn
 * (a spoofed flood evicts old entries rather than growing without limit);
 * proper admission control against spoofed churn is a Phase 5 refinement.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 17);
	__type(key, __be32);   /* source IPv4 */
	__type(value, __u64);  /* GCRA tat_ns */
} xs_rl_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 15);
	__type(key, __u64);    /* source IPv6 /64 */
	__type(value, __u64);  /* GCRA tat_ns */
} xs_rl_v6 SEC(".maps");

/*
 * Aggregate (interface-wide) rate limiter: a single shared GCRA word, updated
 * with compare-and-swap. Caps TOTAL ingress regardless of source, which is the
 * only thing that stops a fully source-spoofed flood (per-source limiting sees
 * every spoofed packet as a brand-new, conforming source). Plain ARRAY, not
 * per-CPU: the cap must be global across all RX cores.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);  /* global GCRA tat_ns */
} xs_global_rl SEC(".maps");

/*
 * Connection tracking table (anti-ACK/RST-flood). Keyed by a 64-bit hash of the
 * ingress 5-tuple; value is the last-seen time. A TCP SYN or SYN-ACK creates an
 * entry; any other TCP packet whose flow is absent is "untracked" (an ACK/RST
 * for a connection that never handshook = flood). LRU bounds memory; a hash
 * collision only ever fails open (a flood packet reusing a live flow's hash is
 * passed), so tracking never drops a real connection by mistake.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 20);
	__type(key, __u64);    /* xs_hash_flow() of the ingress 5-tuple */
	__type(value, __u64);  /* last-seen ns */
} xs_ct SEC(".maps");

/* ---- Phase 5: flow aggregation (HLL, dport histogram, sampling) ---- */

/*
 * HyperLogLog register banks, one per CPU (16 KiB each). Registers are
 * max-mergeable, so userspace merges CPUs with an element-wise max and reads
 * the inactive epoch each window. Single element; indexed [epoch][sketch][r].
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xs_hll);
} xs_hll SEC(".maps");

/*
 * Exact per-destination-port packet counts (TCP+UDP combined), per CPU.
 * PERCPU_ARRAY keyed by the 16-bit destination port so a single element is
 * one u32 (no oversized per-CPU value); read with BPF_MAP_LOOKUP_BATCH.
 * Monotonic; deltas are wrap-safe for read periods well under 2^32/rate.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);    /* destination port */
	__type(value, __u32);  /* packets to that port on this CPU */
} xs_dport_hist SEC(".maps");

/* Per-CPU sampling state (geometric skip + token bucket + drop count). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xs_cpu_state);
} xs_cpu_state SEC(".maps");

/*
 * Sampled packet headers. One shared MPSC ring buffer; reservations take a
 * spinlock but the sample rate is capped, so contention is negligible.
 * 4 MiB = 65536 records; the collector drains it with ring_buffer__consume().
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} xs_samples SEC(".maps");

/* ---- Per-destination victim accounting (dropped packets by dst IPv4) ---- */

/*
 * Attack packets credited per destination IPv4, updated only on an XDP_DROP
 * verdict. The destination accumulating the most drops during an episode is
 * the victim the flood was aimed at. LRU bounds memory (a spoofed-destination
 * flood churns cold entries while the real victim's hot entry survives); an
 * appliance protects few destinations, so 4096 is ample. Shared across RX
 * cores (not per-CPU), updated with __sync_fetch_and_add.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32);              /* destination IPv4, network order */
	__type(value, struct xs_victim);
} xs_victim_v4 SEC(".maps");

/*
 * Attack packets credited per SOURCE IPv4, also only on XDP_DROP. The top
 * sources are the attackers; a fully source-spoofed flood churns many
 * single-packet sources through the LRU (no source dominates = distributed /
 * spoofed), while a real botnet's members accumulate. Larger than the victim
 * map because an attack has many sources but few targets. Same value struct.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __be32);              /* source IPv4, network order */
	__type(value, struct xs_victim);
} xs_attacker_v4 SEC(".maps");

#endif /* XS_MAPS_H */
