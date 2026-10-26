/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * abi.h - the ABI between the XDP dataplane and userspace.
 *
 * Everything in this file is read by userspace (userspace/common/src/abi.rs
 * mirrors it, and a Rust test parses this file to detect drift). Rules:
 *
 *   * enumerators carry explicit values; a value is never reused for a
 *     different meaning once released (dashboards and ClickHouse history
 *     depend on it);
 *   * struct sizes are fixed and padded to reserve room for growth, because
 *     pinned maps are reused across upgrades and libbpf refuses to reuse a
 *     pinned map whose key/value size changed;
 *   * all counters are monotonic. The dataplane never resets them; userspace
 *     computes deltas with wrapping subtraction.
 */
#ifndef XS_ABI_H
#define XS_ABI_H

#include "compat.h"

#define XS_ABI_VERSION 1

/*
 * Counter slots in the per-CPU stats map (xs_stats). Each slot holds a
 * packet and a byte counter.
 */
enum xs_counter_id {
	/* Every frame seen by the program. */
	XS_CNT_RX                     = 0,

	/* Final verdicts. PASS + DROP + TX + REDIRECT == RX. */
	XS_CNT_VERDICT_PASS           = 1,
	XS_CNT_VERDICT_DROP           = 2,
	XS_CNT_VERDICT_TX             = 3,  /* reserved: XDP SYN proxy (later phase) */
	XS_CNT_VERDICT_REDIRECT       = 4,  /* reserved: inline fast-forwarding */

	/* Phase 2 policy sub-counters. These refine, not replace, the verdicts:
	 * a POLICY_DROP is also a VERDICT_DROP, an ALLOW_PASS also a VERDICT_PASS,
	 * so the verdict invariant still holds. */
	XS_CNT_POLICY_DROP            = 5,  /* dropped by a per-source block policy */
	XS_CNT_ALLOW_PASS             = 6,  /* passed because the source is allowlisted */
	XS_CNT_POLICY_EXPIRED         = 7,  /* a matching policy was ignored (TTL expired) */
	XS_CNT_RATE_LIMITED           = 10, /* dropped by the per-source rate limiter (Phase 3) */
	XS_CNT_RATE_TRACKED           = 11, /* IP packets that went through the rate limiter */

	/* Phase 5 flow-aggregation accounting. */
	XS_CNT_SAMPLED                = 12, /* headers copied to the xs_samples ring buffer */
	XS_CNT_SAMPLE_DROP            = 13, /* ring-buffer reserve failed (collector behind) */
	XS_CNT_CT_UNTRACKED           = 14, /* TCP packets matching no tracked flow (ACK/RST flood) */
	XS_CNT_SERVICE_DENY           = 15, /* dropped by the service allowlist (default-deny on a protected dst) */

	/* L2 */
	XS_CNT_L2_VLAN1               = 8,  /* exactly one 802.1Q/802.1ad tag */
	XS_CNT_L2_VLAN2               = 9,  /* two tags (QinQ) */

	/* L3: counted whenever the L3 header itself was valid. */
	XS_CNT_L3_IPV4                = 16,
	XS_CNT_L3_IPV6                = 17,
	XS_CNT_L3_ARP                 = 18,
	XS_CNT_L3_OTHER               = 19, /* any other ethertype / 802.3 length */

	/* L4: counted for fully parsed IP packets (parse rc == OK), including
	 * non-first fragments (protocol known from the IP header). */
	XS_CNT_L4_TCP                 = 24,
	XS_CNT_L4_UDP                 = 25,
	XS_CNT_L4_ICMP                = 26,
	XS_CNT_L4_ICMPV6              = 27,
	XS_CNT_L4_OTHER               = 28,

	/* Fragmentation / IPv6 extension headers (IPv4 and IPv6 combined). */
	XS_CNT_FRAG_FIRST             = 32,
	XS_CNT_FRAG_LATER             = 33,
	XS_CNT_IPV6_EXT               = 34, /* >= 1 extension header traversed */

	/* TCP flag classes (only when the TCP header was parsed). */
	XS_CNT_TCP_SYN                = 40, /* SYN && !ACK */
	XS_CNT_TCP_SYNACK             = 41, /* SYN && ACK */
	XS_CNT_TCP_ACK                = 42, /* ACK && !SYN && !FIN && !RST */
	XS_CNT_TCP_FIN                = 43,
	XS_CNT_TCP_RST                = 44,

	/* Header anomalies on otherwise parseable packets. */
	XS_CNT_ANOM_IPV4_OPTIONS      = 48,
	XS_CNT_ANOM_TCP_BAD_FLAGS     = 49,
	XS_CNT_ANOM_UDP_LEN_MISMATCH  = 50,
	XS_CNT_ANOM_LAND              = 51,
	XS_CNT_ANOM_BOGON_SRC         = 52,
	XS_CNT_ANOM_TTL_ZERO          = 53,
	XS_CNT_ANOM_PORT_ZERO         = 54,

	/* Parse outcome histogram: slot XS_CNT_PARSE_BASE + enum xs_parse_rc.
	 * Exactly one outcome per frame, so the sum over these slots == RX. */
	XS_CNT_PARSE_BASE             = 64,

	XS_CNT_SLOTS                  = 128,
};

/*
 * Parser result. Three classes:
 *   OK / NOT_IP     - well formed.
 *   UNSUP_*         - legal but beyond what the fast path parses; always
 *                     passed, never treated as malformed (RFC 7045 spirit).
 *   ERR_*           - malformed per the relevant RFC; dropped only if
 *                     XS_CFG_DROP_MALFORMED is set.
 */
enum xs_parse_rc {
	XS_PARSE_OK                   = 0,
	XS_PARSE_NOT_IP               = 1,
	XS_PARSE_UNSUP_VLAN_DEPTH     = 2,
	XS_PARSE_UNSUP_IPV6_EXT_DEPTH = 3,

	XS_PARSE_ERR_FIRST            = 8,
	XS_PARSE_ERR_ETH_TRUNC        = 8,
	XS_PARSE_ERR_VLAN_TRUNC       = 9,
	XS_PARSE_ERR_IPV4_TRUNC       = 10,
	XS_PARSE_ERR_IPV4_VERSION     = 11,
	XS_PARSE_ERR_IPV4_IHL         = 12,
	XS_PARSE_ERR_IPV4_TOTLEN      = 13,
	XS_PARSE_ERR_IPV6_TRUNC       = 14,
	XS_PARSE_ERR_IPV6_VERSION     = 15,
	XS_PARSE_ERR_IPV6_PLEN        = 16,
	XS_PARSE_ERR_IPV6_EXT_TRUNC   = 17,
	XS_PARSE_ERR_FRAG_TINY        = 18,
	XS_PARSE_ERR_TCP_TRUNC        = 19,
	XS_PARSE_ERR_TCP_DOFF         = 20,
	XS_PARSE_ERR_UDP_TRUNC        = 21,
	XS_PARSE_ERR_UDP_LEN          = 22,
	XS_PARSE_ERR_ICMP_TRUNC       = 23,

	XS_PARSE_RC_MAX               = 24,
};

struct xs_counter {
	__u64 packets;
	__u64 bytes;
};

/* Value of the single-entry PERCPU_ARRAY xs_stats: 2 KiB per CPU. */
struct xs_stats {
	struct xs_counter c[XS_CNT_SLOTS];
};

/* xs_config.flags. The all-zero config is the safe default: observe only. */
enum xs_config_flags {
	XS_CFG_DROP_MALFORMED     = 1u << 0, /* drop XS_PARSE_ERR_* frames */
	XS_CFG_DROP_BAD_TCP_FLAGS = 1u << 1, /* drop NULL/XMAS/SYN+FIN/SYN+RST/... */
	XS_CFG_DROP_FRAGMENTS     = 1u << 2, /* drop all IPv4/IPv6 fragments */
	XS_CFG_DROP_UDP_DNS       = 1u << 3, /* drop parsed UDP requests to destination port 53 */
	XS_CFG_DROP_UDP           = 1u << 7, /* drop ALL UDP packets (any port) */
	/* Phase 2. Set by userspace only while the corresponding map is non-empty,
	 * so a packet pays for the extra lookup only when there is something to
	 * find. The dataplane treats them purely as a fast "skip this stage" hint. */
	XS_CFG_CHECK_ALLOW        = 1u << 4, /* consult the allowlist LPM tries */
	XS_CFG_CHECK_POLICY       = 1u << 5, /* consult the per-source policy hashes */
	/* Phase 3: per-source automatic rate limiting, parameters in
	 * xs_config.rl_interval_ns / rl_burst. Set by `sentinelctl ratelimit`. */
	XS_CFG_RATELIMIT          = 1u << 6,
	/* Phase 5 flow aggregation. Each gates one telemetry stage so its
	 * per-packet cost is only paid when the collector wants that signal. */
	XS_CFG_SAMPLING           = 1u << 8, /* copy 1-in-N headers to xs_samples */
	XS_CFG_HLL                = 1u << 9, /* update the HyperLogLog sketches */
	XS_CFG_DPORT_HIST         = 1u << 10, /* update the exact dport histogram */
	/* Aggregate (interface-wide) rate limiter: one shared token bucket that
	 * caps TOTAL ingress regardless of source, so a fully source-spoofed flood
	 * (which defeats per-source limiting) is still dropped. Params in
	 * xs_config.global_rl_interval_ns / global_rl_burst. */
	XS_CFG_GLOBAL_RL          = 1u << 11,
	/* Per-vector validity drops, enabled by the risk engine for the detected
	 * attack type (they drop valid packets of that type, so they are used only
	 * under attack and lifted when it ends). */
	XS_CFG_DROP_ICMP          = 1u << 12, /* drop all ICMP/ICMPv6 */
	XS_CFG_DROP_SYN           = 1u << 13, /* drop TCP SYN without ACK */
	XS_CFG_DROP_ACK           = 1u << 14, /* drop pure TCP ACK */
	/* drop ALL UDP incl. ephemeral dports and fragments (no return-traffic
	 * exemption) -- for severe UDP floods and reflection/amplification. */
	XS_CFG_DROP_UDP_STRICT    = 1u << 15,
	/* Connection tracking (Phase: anti-ACK/RST-flood). CONNTRACK maintains the
	 * flow table and counts TCP packets that match no tracked flow (shadow,
	 * never drops). DROP_UNTRACKED additionally drops those untracked packets --
	 * a real ACK/RST flood is all untracked, while real connections are tracked
	 * via their SYN / SYN-ACK, so this is near zero-collateral. Validate in
	 * shadow (CONNTRACK alone) before enabling DROP_UNTRACKED. */
	XS_CFG_CONNTRACK          = 1u << 16,
	XS_CFG_DROP_UNTRACKED     = 1u << 17,
	/* Drop any IPv6 packet carrying >=1 extension header. Extension headers are
	 * rare in normal traffic but are abused for ext-header floods and parser
	 * evasion, so the risk engine arms this only under an IPv6 ext-header flood
	 * and lifts it when the flood ends. */
	XS_CFG_DROP_IPV6_EXT      = 1u << 18,
	/* Positive security model (default-deny per destination). On a destination
	 * listed in xs_protected_v4, drop every packet whose {proto,dport} is not in
	 * xs_service_v4. Set by userspace while those maps are non-empty (managed
	 * like CHECK_ALLOW), so a packet pays the lookup only when there is a policy. */
	XS_CFG_SERVICE_ALLOW      = 1u << 19,
	/* Lockdown kill-switch (operator-set, per interface). When set, every IPv4
	 * packet whose destination is NOT in xs_protected_v4 is dropped. Protected
	 * hosts still follow their service allowlist. ARP and IPv6 are untouched so
	 * the bridge keeps forwarding and never isolates itself. Meant to be armed
	 * only on the ingress interface and lifted by an auto-revert timer. */
	XS_CFG_LOCKDOWN           = 1u << 20,

	/*
	 * Drop "impossible" packets that no conforming stack emits: a source
	 * address that can't exist on the wire (bogon/martian), TTL/hop-limit 0,
	 * or a TCP/UDP port 0. Like DROP_MALFORMED this runs even for allowlist-
	 * exempt sources, since spoofed floods routinely forge an exempt address.
	 * Observe-only by default (the anomalies are always counted; dropping is
	 * opt-in), so it never affects legitimate RFC1918 / link-local traffic.
	 */
	XS_CFG_DROP_SPOOFED       = 1u << 21,
};
#define XS_CFG_KNOWN_FLAGS (XS_CFG_DROP_MALFORMED | XS_CFG_DROP_BAD_TCP_FLAGS | \
			    XS_CFG_DROP_FRAGMENTS | XS_CFG_DROP_UDP_DNS | XS_CFG_DROP_UDP | \
			    XS_CFG_CHECK_ALLOW | XS_CFG_CHECK_POLICY | XS_CFG_RATELIMIT | \
			    XS_CFG_SAMPLING | XS_CFG_HLL | XS_CFG_DPORT_HIST | XS_CFG_GLOBAL_RL | \
			    XS_CFG_DROP_ICMP | XS_CFG_DROP_SYN | XS_CFG_DROP_ACK | XS_CFG_DROP_UDP_STRICT | \
			    XS_CFG_CONNTRACK | XS_CFG_DROP_UNTRACKED | XS_CFG_DROP_IPV6_EXT | \
			    XS_CFG_SERVICE_ALLOW | XS_CFG_LOCKDOWN | XS_CFG_DROP_SPOOFED)
/* Flags an operator sets directly (sentinelctl config); CHECK_* are managed
 * automatically by the block/allow commands as the maps gain or lose entries. */
#define XS_CFG_OPERATOR_FLAGS (XS_CFG_DROP_MALFORMED | XS_CFG_DROP_BAD_TCP_FLAGS | \
			       XS_CFG_DROP_FRAGMENTS | XS_CFG_DROP_UDP_DNS | XS_CFG_DROP_UDP | \
			       XS_CFG_DROP_ICMP | XS_CFG_DROP_SYN | XS_CFG_DROP_ACK | XS_CFG_DROP_UDP_STRICT | \
			       XS_CFG_DROP_SPOOFED)
/* Base validity drops that act on malformed / specific packet shapes, used by
 * the deterministic corpus test. The per-vector drops (ICMP/SYN/ACK/UDP_STRICT)
 * drop *valid* packets of a type and are only enabled under attack, so they are
 * exercised separately, not in the always-valid corpus. */
#define XS_CFG_VALIDITY_FLAGS (XS_CFG_DROP_MALFORMED | XS_CFG_DROP_BAD_TCP_FLAGS | \
			       XS_CFG_DROP_FRAGMENTS | XS_CFG_DROP_UDP_DNS | XS_CFG_DROP_UDP | \
			       XS_CFG_DROP_SPOOFED)

/*
 * First port of the ephemeral range (IANA/Linux default 32768-60999). Inbound
 * UDP addressed to an ephemeral destination port is return traffic for a flow
 * the host itself opened (DNS/NTP replies, and QUIC tunnels such as Twingate or
 * WireGuard) -- there is no service listening there to be flooded -- so the
 * blanket UDP drop always exempts it. This keeps the box's own connectivity,
 * including remote management over the tunnel, alive even under a full UDP
 * drop; single-source floods to ephemeral ports are still caught by the
 * per-source rate limiter.
 */
#define XS_EPHEMERAL_PORT_MIN 32768u

/* Value of the single-entry ARRAY xs_config: 64 bytes. */
struct xs_config {
	__u32 abi_version;     /* written by userspace, informational for the dataplane */
	__u32 flags;           /* enum xs_config_flags */
	__u32 rl_interval_ns;  /* rate limiter: ns between conforming packets = 1e9/pps; 0 = unset */
	__u32 rl_burst;        /* rate limiter: bucket depth in packets (burst tolerance) */
	__u32 hll_epoch;       /* Phase 5: active HLL epoch (0/1), flipped by the collector */
	__u32 sample_shift;    /* Phase 5: sample 1-in-2^sample_shift packets (0 = every packet) */
	__u32 global_rl_interval_ns; /* aggregate limiter: ns/packet = 1e9/global_pps; 0 = unset */
	__u32 global_rl_burst;       /* aggregate limiter: bucket depth in packets */
	__u64 reserved[4];
};

/* ---- Phase 5: flow aggregation (HLL, dport histogram, sampling) ---- */

/*
 * HyperLogLog sketches. Precision p = 12 -> 2^12 = 4096 one-byte registers,
 * standard error 1.04/sqrt(4096) ~= 1.6%. Two epochs so windows can be diffed
 * (registers are max-mergeable, not subtractable): the collector flips
 * xs_config.hll_epoch, waits a grace period, then reads and zeroes the old
 * epoch. Sketches, in order: distinct sources, distinct 5-tuples (flows).
 */
enum xs_hll_sketch {
	XS_HLL_SRC   = 0,
	XS_HLL_FLOW  = 1,
	XS_HLL_N     = 2,
};
#define XS_HLL_P         12
#define XS_HLL_REGISTERS (1u << XS_HLL_P)      /* 4096 */
#define XS_HLL_EPOCHS    2
#define XS_HLL_TOTAL     (XS_HLL_EPOCHS * XS_HLL_N * XS_HLL_REGISTERS) /* 16384 */
/* Flat offset of register `r` in sketch `s`, epoch `e`. */
#define XS_HLL_OFF(e, s, r) ((((e) * XS_HLL_N + (s)) * XS_HLL_REGISTERS) + (r))

/* Value of the single-entry PERCPU_ARRAY xs_hll: 16 KiB per CPU. Flat register
 * array (see XS_HLL_OFF) so the dataplane can index it with one bounded offset. */
struct xs_hll {
	__u8 reg[XS_HLL_TOTAL];
};

/*
 * Per-CPU sampling state (single-entry PERCPU_ARRAY). A geometric skip
 * countdown decorrelates the sampler from periodic traffic; a token bucket
 * caps samples/CPU/second; drops are counted when the ring buffer is full.
 */
struct xs_cpu_state {
	__u32 skip;            /* packets remaining before the next sample */
	__u32 tokens;          /* sampling tokens left in the current second */
	__u64 refill_ns;       /* monotonic time the token bucket was last refilled */
	__u64 ringbuf_drops;   /* reserve failures on this CPU (monotonic) */
	__u64 reserved[2];
};
#define XS_SAMPLE_TOKENS_PER_SEC 20000u  /* max samples per CPU per second */

/* One sampled packet header, pushed to the xs_samples ring buffer: 64 bytes. */
struct xs_sample {
	__u64 ts_ns;
	__u8  saddr[16];       /* IPv4 as ::ffff:a.b.c.d */
	__u8  daddr[16];
	__be16 sport, dport;
	__u16 pkt_len, ip_id;
	__u8  l4_proto, tcp_flags, ttl, verdict;
	__u8  rx_queue, parse_rc, l3, flags;
	__u16 tcp_window, _pad;
	__u32 _pad2;           /* pad to 64 bytes (one cache line) */
};

/*
 * Per-destination victim accounting (value of xs_victim_v4). Credited only on
 * an XDP_DROP verdict, so an un-attacked box never touches the map; the
 * destination with the most dropped packets during an episode is the attack's
 * victim, which the control plane exports as xs_target_packets_total{dst}.
 */
struct xs_victim {
	__u64 packets;
	__u64 bytes;
};

/*
 * Key of xs_service_v4 (service allowlist / positive security model). A packet
 * to a destination present in xs_protected_v4 is dropped unless {proto,dport}
 * is present here. dport is 0 for protocols without ports (e.g. ICMP) and for
 * non-first fragments (no L4 header). Fixed 8-byte layout, no implicit padding,
 * so the Rust control plane and the dataplane agree byte-for-byte.
 */
struct xs_service_key {
	__be32 daddr;  /* destination IPv4, network order */
	__be16 dport;  /* destination port, network order (0 = none) */
	__u8   proto;  /* IP protocol (6 TCP, 17 UDP, 1 ICMP, ...) */
	__u8   _pad;   /* must be zero */
};

/* ---- Phase 2: per-source policies and allowlist ---- */

/* Action a matching per-source policy applies. */
enum xs_action {
	XS_ACTION_PASS       = 0, /* explicit pass (e.g. a temporary exception) */
	XS_ACTION_DROP       = 1, /* drop every packet from the source */
	/* XS_ACTION_RATE_LIMIT = 2 reserved for Phase 3 (uses the reserved
	 * words below for GCRA state). */
	XS_ACTION_MAX        = 2,
};

/* How much an allowlist match is trusted. */
enum xs_trust {
	XS_TRUST_FULL            = 0, /* pass immediately, skip ALL mitigation */
	XS_TRUST_DYNAMIC_EXEMPT  = 1, /* skip dynamic policy, still validity-checked */
	XS_TRUST_MAX             = 2,
};

/* Reason codes recorded on a policy (informational; surfaced by the CLI and,
 * later, in event history). Never reused once released. */
enum xs_policy_reason {
	XS_REASON_UNSPEC     = 0,
	XS_REASON_MANUAL     = 1, /* operator ran `sentinelctl block` */
	XS_REASON_FLOOD      = 2, /* reserved: automatic, volumetric */
	XS_REASON_SCAN       = 3, /* reserved: automatic, port scan */
	XS_REASON_MAX        = 4,
};

/*
 * Value of xs_policy_v4 / xs_policy_v6 (per-source block/allow/rate policies).
 * Keyed by source address (v4 /32 as __be32, v6 /64 as the first 8 address
 * bytes). Fixed 32 bytes; the reserved words hold Phase 3 rate-limiter state.
 */
struct xs_policy {
	__u64 expires_ns;  /* CLOCK_MONOTONIC deadline; 0 = never (static rule) */
	__u32 policy_id;   /* opaque id for correlation with events */
	__u8  action;      /* enum xs_action */
	__u8  reason;      /* enum xs_policy_reason */
	__u16 _pad;
	__u64 reserved[2]; /* Phase 3: GCRA tat_ns / interval+tolerance */
};

/*
 * Value of xs_allow_v4 / xs_allow_v6 (LPM tries keyed by CIDR). Fixed 16 bytes.
 */
struct xs_allow {
	__u64 expires_ns;  /* CLOCK_MONOTONIC deadline; 0 = never */
	__u8  trust;       /* enum xs_trust */
	__u8  _pad[7];
};

/*
 * LPM trie keys. The kernel's LPM_TRIE requires a leading u32 prefix length
 * (in bits) followed by the address bytes in network order.
 */
struct xs_lpm_v4 {
	__u32 prefixlen;
	__u8  addr[4];
};

struct xs_lpm_v6 {
	__u32 prefixlen;
	__u8  addr[16];
};

#if !defined(__bpf__)
_Static_assert(sizeof(struct xs_counter) == 16, "xs_counter ABI");
_Static_assert(sizeof(struct xs_stats) == 2048, "xs_stats ABI");
_Static_assert(sizeof(struct xs_config) == 64, "xs_config ABI");
_Static_assert(sizeof(struct xs_hll) == 16384, "xs_hll ABI");
_Static_assert(sizeof(struct xs_cpu_state) == 40, "xs_cpu_state ABI");
_Static_assert(sizeof(struct xs_sample) == 64, "xs_sample ABI");
_Static_assert(sizeof(struct xs_policy) == 32, "xs_policy ABI");
_Static_assert(sizeof(struct xs_allow) == 16, "xs_allow ABI");
_Static_assert(sizeof(struct xs_lpm_v4) == 8, "xs_lpm_v4 ABI");
_Static_assert(sizeof(struct xs_lpm_v6) == 20, "xs_lpm_v6 ABI");
_Static_assert(XS_CNT_PARSE_BASE + XS_PARSE_RC_MAX <= XS_CNT_SLOTS, "counter slots");
#endif

#endif /* XS_ABI_H */
