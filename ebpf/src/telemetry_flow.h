/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * telemetry_flow.h - Phase 5 flow aggregation in the dataplane.
 *
 * Fixed-cost, mergeable sketches only; anything with division, logarithms,
 * sorting or history is userspace (docs/feature-schema.md). Three stages,
 * each gated by a config flag so an idle collector pays nothing:
 *   - HyperLogLog cardinality (unique sources, unique 5-tuple flows);
 *   - an exact per-destination-port histogram;
 *   - 1-in-N header sampling into a shared ring buffer, rate-capped per CPU.
 */
#ifndef XS_TELEMETRY_FLOW_H
#define XS_TELEMETRY_FLOW_H

#include "compat.h"
#include "abi.h"
#include "maps.h"
#include "parsers.h"

/* 64-bit finaliser (splitmix64). Cheap, good avalanche, no table. */
static __always_inline __u64 xs_mix64(__u64 x)
{
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebULL;
	x ^= x >> 31;
	return x;
}

/* Combine the two halves of an address into 64-bit words. */
static __always_inline __u64 xs_addr_hi(const union xs_addr *a)
{
	return ((__u64)a->v6[0] << 32) | (__u32)a->v6[1];
}
static __always_inline __u64 xs_addr_lo(const union xs_addr *a)
{
	return ((__u64)a->v6[2] << 32) | (__u32)a->v6[3];
}

/* Fold the source address (4 or 16 bytes) into a mixing hash. */
static __always_inline __u64 xs_hash_src(const struct xs_pkt *p)
{
	if (p->l3 == XS_L3_IPV4)
		return xs_mix64((__u64)p->saddr.v4);
	return xs_mix64(xs_addr_hi(&p->saddr) ^ (xs_addr_lo(&p->saddr) * 0x9e3779b97f4a7c15ULL));
}

/* Fold the 5-tuple (src, dst, sport, dport, proto) into a mixing hash. */
static __always_inline __u64 xs_hash_flow(const struct xs_pkt *p)
{
	__u64 a, b;

	if (p->l3 == XS_L3_IPV4) {
		a = ((__u64)p->saddr.v4 << 32) | (__u32)p->daddr.v4;
		b = 0;
	} else {
		a = xs_addr_hi(&p->saddr) ^ xs_addr_lo(&p->daddr);
		b = xs_addr_lo(&p->saddr) ^ xs_addr_hi(&p->daddr);
	}
	a ^= ((__u64)p->sport << 48) ^ ((__u64)p->dport << 32) ^ ((__u64)p->l4_proto << 24);
	return xs_mix64(a ^ (b * 0x9e3779b97f4a7c15ULL));
}

/* One HLL observation: register = max(register, rank). */
static __always_inline void xs_hll_add(struct xs_hll *h, __u32 epoch, __u32 sketch, __u64 hash)
{
	__u32 idx = (__u32)(hash >> (64 - XS_HLL_P)) & (XS_HLL_REGISTERS - 1);
	__u64 shifted = hash << XS_HLL_P;
	__u8 rank = shifted ? (__u8)(__builtin_clzll(shifted) + 1) : (64 - XS_HLL_P + 1);
	__u32 off;

	if (sketch >= XS_HLL_N)
		return;
	off = XS_HLL_OFF(epoch & (XS_HLL_EPOCHS - 1), sketch, idx);
	if (off >= XS_HLL_TOTAL)
		return;
	if (rank > h->reg[off])
		h->reg[off] = rank;
}

/* Update all HLL sketches for one parsed IP packet. */
static __always_inline void xs_hll_update(const struct xs_pkt *p, __u32 epoch)
{
	const __u32 zero = 0;
	struct xs_hll *h = bpf_map_lookup_elem(&xs_hll, &zero);

	if (!h)
		return;
	xs_hll_add(h, epoch, XS_HLL_SRC, xs_hash_src(p));
	if (p->l4_parsed)
		xs_hll_add(h, epoch, XS_HLL_FLOW, xs_hash_flow(p));
}

/*
 * Connection-tracking decision for one TCP packet. A SYN (client open) or
 * SYN-ACK (the box's own outbound connection) records/refreshes the flow; any
 * other TCP packet whose flow is absent is "untracked" -- an ACK/RST/data for a
 * connection that never handshook here, i.e. an ACK/RST flood. Returns 1 if
 * untracked (candidate for drop), else 0. Hash collisions only fail open.
 */
static __always_inline int xs_conntrack_untracked(const struct xs_pkt *p, __u64 now)
{
	__u64 key = xs_hash_flow(p);
	__u64 *seen;

	if (p->tcp_flags & XS_TCP_SYN) {
		bpf_map_update_elem(&xs_ct, &key, &now, BPF_ANY);
		return 0; /* SYN / SYN-ACK: opens or refreshes the flow */
	}
	seen = bpf_map_lookup_elem(&xs_ct, &key);
	if (seen) {
		*seen = now; /* established flow: keep it hot in the LRU */
		return 0;
	}
	return 1; /* no matching flow: untracked */
}

/* Bump the exact destination-port histogram (TCP/UDP with a parsed dport). */
static __always_inline void xs_dport_bump(const struct xs_pkt *p)
{
	__u32 key;
	__u32 *cnt;

	if (!p->l4_parsed)
		return;
	if (p->l4_proto != XS_IPPROTO_TCP && p->l4_proto != XS_IPPROTO_UDP)
		return;
	key = bpf_ntohs(p->dport);
	cnt = bpf_map_lookup_elem(&xs_dport_hist, &key);
	if (cnt)
		(*cnt)++;
}

/* Copy an IPv4 address into the ::ffff:a.b.c.d mapped form. */
static __always_inline void xs_map_v4(__u8 out[16], __be32 v4)
{
	__builtin_memset(out, 0, 10);
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, &v4, 4);
}

/*
 * Sample this packet's header 1-in-2^shift, capped per CPU per second. A
 * geometric skip (drawn from prandom) decorrelates the sampler from periodic
 * traffic. Records go to the shared ring buffer with no per-record wakeup;
 * a failed reserve is counted and the packet proceeds.
 */
static __always_inline void xs_maybe_sample(const struct xs_pkt *p, __u32 shift,
					    __u64 now, int verdict, int rc, __u64 len)
{
	const __u32 zero = 0;
	struct xs_cpu_state *cs = bpf_map_lookup_elem(&xs_cpu_state, &zero);
	struct xs_sample *s;

	if (!cs)
		return;

	/* Refill the token bucket once per second. */
	if (now - cs->refill_ns >= 1000000000ULL) {
		cs->refill_ns = now;
		cs->tokens = XS_SAMPLE_TOKENS_PER_SEC;
	}

	/* Geometric skip: only sample when the countdown reaches zero. */
	if (cs->skip > 0) {
		cs->skip--;
		return;
	}
	/* Draw the next skip: mean 2^shift - 1 packets. prandom masked to the
	 * window keeps it O(1) and unpredictable to periodic senders. */
	cs->skip = shift ? (bpf_get_prandom_u32() & ((1u << shift) - 1)) : 0;

	if (cs->tokens == 0)
		return;
	cs->tokens--;

	s = bpf_ringbuf_reserve(&xs_samples, sizeof(*s), 0);
	if (!s) {
		cs->ringbuf_drops++;
		return;
	}
	__builtin_memset(s, 0, sizeof(*s));
	s->ts_ns = now;
	if (p->l3 == XS_L3_IPV4) {
		xs_map_v4(s->saddr, p->saddr.v4);
		xs_map_v4(s->daddr, p->daddr.v4);
	} else if (p->l3 == XS_L3_IPV6) {
		__builtin_memcpy(s->saddr, &p->saddr, 16);
		__builtin_memcpy(s->daddr, &p->daddr, 16);
	}
	s->sport = p->sport;
	s->dport = p->dport;
	s->pkt_len = (__u16)len;
	s->ip_id = 0;          /* not captured by the fast-path parser */
	s->l4_proto = p->l4_proto;
	s->tcp_flags = p->tcp_flags;
	s->ttl = p->ttl;
	s->verdict = (__u8)verdict;
	s->parse_rc = (__u8)rc;
	s->l3 = p->l3;
	s->flags = p->l4_parsed ? 1 : 0;
	bpf_ringbuf_submit(s, 0);
}

#endif /* XS_TELEMETRY_FLOW_H */
