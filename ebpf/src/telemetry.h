/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * telemetry.h - dataplane accounting.
 *
 * Phase 1: per-CPU monotonic counters only. Later phases add the per-source
 * heavy-hitter table, per-service counters, HyperLogLog cardinality sketches
 * and the sampled ring buffer (docs/bpf-maps.md, "Telemetry maps").
 */
#ifndef XS_TELEMETRY_H
#define XS_TELEMETRY_H

#include "compat.h"
#include "abi.h"
#include "parsers.h"

/*
 * Plain (non-atomic) increments are correct because the block is per-CPU and
 * XDP runs in NAPI context with migration disabled. The one exception is
 * PREEMPT_RT, where two NAPI threads on the same CPU could interleave; a
 * rare lost increment is acceptable for telemetry.
 */
static __always_inline void xs_count(struct xs_stats *st, __u32 id, __u64 bytes)
{
	if (id >= XS_CNT_SLOTS)
		return;
	st->c[id].packets++;
	st->c[id].bytes += bytes;
}

/* Account the parse outcome and the traffic classes of one frame. */
static __always_inline void xs_account_parse(struct xs_stats *st, const struct xs_pkt *p,
					     int rc, __u64 len)
{
	xs_count(st, XS_CNT_PARSE_BASE + (__u32)rc, len);

	if (p->vlan_depth == 1)
		xs_count(st, XS_CNT_L2_VLAN1, len);
	else if (p->vlan_depth == 2)
		xs_count(st, XS_CNT_L2_VLAN2, len);

	if (p->l3 == XS_L3_IPV4)
		xs_count(st, XS_CNT_L3_IPV4, len);
	else if (p->l3 == XS_L3_IPV6)
		xs_count(st, XS_CNT_L3_IPV6, len);
	else if (rc == XS_PARSE_NOT_IP)
		xs_count(st, p->eth_proto == bpf_htons(XS_ETH_P_ARP) ? XS_CNT_L3_ARP
								      : XS_CNT_L3_OTHER, len);

	if (rc != XS_PARSE_OK || p->l3 == XS_L3_NONE)
		return;

	switch (p->l4_proto) {
	case XS_IPPROTO_TCP:
		xs_count(st, XS_CNT_L4_TCP, len);
		break;
	case XS_IPPROTO_UDP:
		xs_count(st, XS_CNT_L4_UDP, len);
		break;
	case XS_IPPROTO_ICMP:
		xs_count(st, p->l3 == XS_L3_IPV4 ? XS_CNT_L4_ICMP : XS_CNT_L4_OTHER, len);
		break;
	case XS_IPPROTO_ICMPV6:
		xs_count(st, p->l3 == XS_L3_IPV6 ? XS_CNT_L4_ICMPV6 : XS_CNT_L4_OTHER, len);
		break;
	default:
		xs_count(st, XS_CNT_L4_OTHER, len);
		break;
	}

	if (p->frag == XS_FRAG_FIRST)
		xs_count(st, XS_CNT_FRAG_FIRST, len);
	else if (p->frag == XS_FRAG_LATER)
		xs_count(st, XS_CNT_FRAG_LATER, len);
	if (p->n_ext)
		xs_count(st, XS_CNT_IPV6_EXT, len);

	if (p->l4_parsed && p->l4_proto == XS_IPPROTO_TCP) {
		__u8 f = p->tcp_flags;

		if (f & XS_TCP_SYN)
			xs_count(st, (f & XS_TCP_ACK) ? XS_CNT_TCP_SYNACK : XS_CNT_TCP_SYN, len);
		else if ((f & (XS_TCP_ACK | XS_TCP_FIN | XS_TCP_RST)) == XS_TCP_ACK)
			xs_count(st, XS_CNT_TCP_ACK, len);
		if (f & XS_TCP_FIN)
			xs_count(st, XS_CNT_TCP_FIN, len);
		if (f & XS_TCP_RST)
			xs_count(st, XS_CNT_TCP_RST, len);
	}

	if (p->anomalies) {
		if (p->anomalies & XS_ANOM_IPV4_OPTIONS)
			xs_count(st, XS_CNT_ANOM_IPV4_OPTIONS, len);
		if (p->anomalies & XS_ANOM_TCP_BAD_FLAGS)
			xs_count(st, XS_CNT_ANOM_TCP_BAD_FLAGS, len);
		if (p->anomalies & XS_ANOM_UDP_LEN_MISMATCH)
			xs_count(st, XS_CNT_ANOM_UDP_LEN_MISMATCH, len);
		if (p->anomalies & XS_ANOM_LAND)
			xs_count(st, XS_CNT_ANOM_LAND, len);
	}
}

#endif /* XS_TELEMETRY_H */
