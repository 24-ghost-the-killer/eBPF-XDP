// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * xdp_main.c - xdp-sentinel XDP dataplane entry point.
 *
 * Phase 1 pipeline (per frame):
 *
 *   1. one PERCPU_ARRAY lookup  -> per-CPU counter block
 *   2. one ARRAY lookup         -> runtime config (inlined by the verifier)
 *   3. bounded L2-L4 parse      -> struct xs_pkt on the stack
 *   4. counter updates          -> plain stores into the per-CPU block
 *   5. validity verdict         -> PASS unless an explicit drop flag is set
 *
 * No helper other than map lookups is called, nothing blocks, nothing
 * allocates. Later phases insert allowlist, policy, rate-limit and telemetry
 * stages between 4 and 5 (docs/architecture.md, "XDP pipeline").
 */
#include "compat.h"
#include "abi.h"
#include "parsers.h"
#include "maps.h"
#include "telemetry.h"
#include "telemetry_flow.h"
#include "policy.h"

/*
 * Deterministic validity mitigation. Everything is opt-in: the zero config
 * passes all traffic, because the kernel stack already discards malformed
 * frames and an overly strict parser must never become an outage.
 */
static __always_inline int xs_validity_verdict(int rc, const struct xs_pkt *p, __u32 flags)
{
	if (xs_rc_is_error(rc))
		return (flags & XS_CFG_DROP_MALFORMED) ? XDP_DROP : XDP_PASS;
	if (rc != XS_PARSE_OK)
		return XDP_PASS; /* NOT_IP and UNSUP_* are never dropped here */
	/*
	 * LAND (source address == destination): never legitimate on a forwarding
	 * path (RFC 1812 §5.3.7), so it is classed with malformed traffic. This
	 * check runs even for allowlist-exempt sources, so a LAND flood that spoofs
	 * an exempt address (e.g. the victim's own IP) is still dropped -- the
	 * per-source and aggregate rate limiters cannot, because they skip exempt
	 * sources. Gated on DROP_MALFORMED so the observe-only default is preserved.
	 */
	if ((p->anomalies & XS_ANOM_LAND) && (flags & XS_CFG_DROP_MALFORMED))
		return XDP_DROP;
	/*
	 * Impossible packets: bogon/martian source, TTL/hop-limit 0, or port 0.
	 * No conforming stack emits these, so they are never legitimate traffic --
	 * they are either crafted or the product of a spoofed flood. Dropped only
	 * when DROP_SPOOFED is set (observe-only default), and, like LAND, the
	 * check runs even for allowlist-exempt sources so a flood that forges an
	 * exempt address is still shed (the rate limiters skip exempt sources).
	 */
	if ((p->anomalies & (XS_ANOM_BOGON_SRC | XS_ANOM_TTL_ZERO | XS_ANOM_PORT_ZERO)) &&
	    (flags & XS_CFG_DROP_SPOOFED))
		return XDP_DROP;
	if (p->l4_proto == 17 && (flags & XS_CFG_DROP_UDP)) {
		/*
		 * Drop UDP aimed at a service port, but never the host's own return
		 * traffic. Inbound UDP to an ephemeral destination port is a reply to
		 * a flow this box opened (DNS/NTP, and QUIC tunnels like Twingate /
		 * WireGuard that carry remote management), so exempting it means a full
		 * UDP drop can no longer sever the box's own connectivity. A non-first
		 * fragment carries no L4 header (l4_parsed == 0): its port is unknown
		 * and it may be a piece of such a reply, so it is exempted too rather
		 * than risk breaking a fragmented response. Single-source floods that
		 * slip through on an ephemeral port are still caught by the rate
		 * limiter.
		 */
		if (p->l4_parsed && xs_ntohs_bounded(p->dport) < XS_EPHEMERAL_PORT_MIN)
			return XDP_DROP;
	}
	if (p->l4_proto == 17 && p->l4_parsed && p->dport == bpf_htons(53) &&
	    (flags & XS_CFG_DROP_UDP_DNS))
		return XDP_DROP;
	if ((p->anomalies & XS_ANOM_TCP_BAD_FLAGS) && (flags & XS_CFG_DROP_BAD_TCP_FLAGS))
		return XDP_DROP;
	if (p->frag != XS_FRAG_NONE && (flags & XS_CFG_DROP_FRAGMENTS))
		return XDP_DROP;
	if (p->n_ext > 0 && (flags & XS_CFG_DROP_IPV6_EXT))
		return XDP_DROP; /* IPv6 extension-header flood */
	/*
	 * Per-vector drops the risk engine turns on for the detected attack type.
	 * DROP_UDP_STRICT closes the ephemeral-port / fragment / reflection gaps of
	 * DROP_UDP: it drops every UDP packet (protocol known from the IP header, so
	 * non-first fragments too), no return-traffic exemption. Used only under a
	 * severe UDP/reflection flood and lifted when it ends.
	 */
	if (p->l4_proto == XS_IPPROTO_UDP && (flags & XS_CFG_DROP_UDP_STRICT))
		return XDP_DROP;
	if ((p->l4_proto == XS_IPPROTO_ICMP || p->l4_proto == XS_IPPROTO_ICMPV6) &&
	    (flags & XS_CFG_DROP_ICMP))
		return XDP_DROP;
	if (p->l4_parsed && p->l4_proto == XS_IPPROTO_TCP &&
	    (p->tcp_flags & XS_TCP_SYN) && !(p->tcp_flags & XS_TCP_ACK) &&
	    (flags & XS_CFG_DROP_SYN))
		return XDP_DROP; /* SYN flood (SYN without ACK) */
	if (p->l4_parsed && p->l4_proto == XS_IPPROTO_TCP &&
	    (p->tcp_flags & (XS_TCP_SYN | XS_TCP_FIN | XS_TCP_RST | XS_TCP_ACK)) == XS_TCP_ACK &&
	    (flags & XS_CFG_DROP_ACK))
		return XDP_DROP; /* ACK flood (pure ACK) */
	return XDP_PASS;
}

/*
 * Verification boundary. xs_parse() is a *global* (non-static, noinline)
 * BPF-to-BPF function, so the verifier checks it exactly once, independently
 * of its call site, and the caller sees the returned rc and *p as unknown
 * values. Without this boundary every distinct parser outcome (VLAN depth x
 * L3 x IPv6 extension chain x fragment state x L4 result) is carried as a
 * separate verifier state through all accounting and, in later phases, all
 * policy code: the Phase 1 program alone needed ~600k verified instructions
 * inlined versus a few thousand split. Runtime cost is one BPF call (a few
 * ns); the JIT emits a direct call.
 */
__noinline int xs_parse(struct xdp_md *ctx, struct xs_pkt *p)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (!p) /* global functions must handle a NULL pointer argument */
		return XS_PARSE_ERR_ETH_TRUNC;
	return xs_parse_packet(data, data_end, p);
}

/*
 * Aggregate (interface-wide) rate limiter. One shared GCRA word capping total
 * ingress regardless of source -- the only thing that stops a fully
 * source-spoofed flood. Returns 1 when the packet should be dropped.
 */
static __always_inline int xs_global_rl_drop(const struct xs_rl_params *grl, __u64 now)
{
	const __u32 z = 0;
	__u64 *gtat = bpf_map_lookup_elem(&xs_global_rl, &z);

	if (!gtat)
		return 0;
	return !xs_gcra(gtat, grl->interval_ns, grl->tolerance_ns, now);
}

/*
 * Always-on ARP storm cap. Normal ARP is a handful of frames per second (even
 * a full /24 ARP sweep is a few hundred); an L2 loop or broadcast storm is
 * 10^5/s and, being non-IP, slips past every IP mitigation. Cap ARP per
 * interface at XS_ARP_RL_PPS with a generous burst so resolution and sweeps
 * are never touched, while a storm is cut by ~99%. Returns 1 to drop.
 */
#define XS_ARP_RL_PPS   2000u
#define XS_ARP_RL_BURST 500u
static __always_inline int xs_arp_rl_drop(__u64 now)
{
	const __u32 z = 0;
	__u64 *tat = bpf_map_lookup_elem(&xs_arp_rl, &z);
	const __u32 interval = 1000000000u / XS_ARP_RL_PPS;

	if (!tat)
		return 0;
	return !xs_gcra(tat, interval, (__u64)interval * XS_ARP_RL_BURST, now);
}

/*
 * Service allowlist (positive security model). On a destination listed in
 * xs_protected_v4, only the {proto,dport} services present in xs_service_v4 are
 * permitted; anything else returns 1 (deny). A destination that is NOT protected
 * returns 0 (default allow), so the stage is transparent for unprotected hosts.
 * IPv4 only; dport is 0 for portless protocols and non-first fragments.
 */
static __always_inline int xs_service_denied(const struct xs_pkt *p)
{
	__be32 d = p->daddr.v4;

	if (!bpf_map_lookup_elem(&xs_protected_v4, &d))
		return 0; /* destination not protected -> default allow */

	/*
	 * Return traffic of the protected host's OWN outbound connections. The
	 * allowlist guards the services a host offers, not its replies: a reply
	 * lands on the ephemeral port the host chose, which no allowlist can list.
	 * Without this the box's Twingate connector died whenever it egressed via
	 * br0 (nightly, when the WiFi uplink drops): every relay reply to
	 * 192.168.1.193:<ephemeral> was service-denied. TCP must carry ACK, so a
	 * new inbound connection (bare SYN) to a high port is still denied; a raw
	 * ACK flood aimed at ephemeral ports falls through to conntrack and the
	 * rate limiters, exactly as DROP_UDP's same exemption does for UDP.
	 */
	if (p->l4_parsed && xs_ntohs_bounded(p->dport) >= XS_EPHEMERAL_PORT_MIN) {
		if (p->l4_proto == XS_IPPROTO_UDP)
			return 0;
		if (p->l4_proto == XS_IPPROTO_TCP && (p->tcp_flags & XS_TCP_ACK))
			return 0;
	}

	struct xs_service_key k = {
		.daddr = d,
		.dport = p->l4_parsed ? p->dport : 0,
		.proto = p->l4_proto,
		._pad  = 0,
	};
	return bpf_map_lookup_elem(&xs_service_v4, &k) ? 0 : 1;
}

/*
 * IPv6 twin of xs_service_denied: on a destination listed in xs_protected_v6,
 * only the services in xs_service_v6 pass. ICMPv6 is always allowed -- IPv6
 * cannot work without neighbour discovery and path-MTU messages -- and so is
 * return traffic of the host's own connections (ephemeral dport, as for IPv4).
 * Closes the gap where a protected host with a global IPv6 address was
 * reachable on every port over IPv6 while IPv4 was default-deny.
 */
static __always_inline int xs_service_denied6(const struct xs_pkt *p)
{
	struct xs_in6 d = {};

	__builtin_memcpy(d.a, p->daddr.v6, 16);
	if (!bpf_map_lookup_elem(&xs_protected_v6, &d))
		return 0; /* destination not protected -> default allow */
	if (p->l4_proto == XS_IPPROTO_ICMPV6)
		return 0;
	if (p->l4_parsed && xs_ntohs_bounded(p->dport) >= XS_EPHEMERAL_PORT_MIN) {
		if (p->l4_proto == XS_IPPROTO_UDP)
			return 0;
		if (p->l4_proto == XS_IPPROTO_TCP && (p->tcp_flags & XS_TCP_ACK))
			return 0;
	}

	struct xs_service_key6 k = {};

	__builtin_memcpy(k.daddr, p->daddr.v6, 16);
	k.dport = p->l4_parsed ? p->dport : 0;
	k.proto = p->l4_proto;
	return bpf_map_lookup_elem(&xs_service_v6, &k) ? 0 : 1;
}

/*
 * Scan detection (XS_CFG_SCAN_BLOCK). Called only for IPv4 packets to internal
 * destinations other than the box itself. Returns 1 to drop: the source is a
 * blocked scanner, or this probe just pushed it over the threshold.
 *
 * A "probe" is a new-connection attempt: TCP SYN without ACK, or UDP to a
 * service port (< 32768; replies to ephemeral ports are return traffic).
 * Distinct {destination, port} targets are counted in a 512-bit hashed set per
 * window, so a vertical scan (many ports, one host) and a horizontal one (one
 * port, many hosts) both count, while a client hammering one service does not.
 */
static __always_inline int xs_scan_drop(struct xs_stats *st, const struct xs_config *cfg,
					const struct xs_pkt *p, __u64 now, __u64 len)
{
	__be32 sa = p->saddr.v4;
	struct xs_scan *s = bpf_map_lookup_elem(&xs_scan_v4, &sa);

	if (s && now < s->blocked_until_ns)
		return 1;
	if (!p->l4_parsed)
		return 0;
	int probe = (p->l4_proto == XS_IPPROTO_TCP && (p->tcp_flags & XS_TCP_SYN) &&
		     !(p->tcp_flags & XS_TCP_ACK)) ||
		    (p->l4_proto == XS_IPPROTO_UDP && xs_ntohs_bounded(p->dport) < XS_EPHEMERAL_PORT_MIN);
	if (!probe || (bpf_ntohl(p->daddr.v4) & 0xff) == 0xff) /* .255: subnet broadcast */
		return 0;

	__u32 thr = cfg && cfg->scan_threshold ? cfg->scan_threshold : XS_SCAN_DEFAULT_THRESHOLD;
	__u64 window = (__u64)(cfg && cfg->scan_window_ms ? cfg->scan_window_ms : XS_SCAN_DEFAULT_WINDOW_MS) * 1000000ULL;
	__u64 block = (__u64)(cfg && cfg->scan_block_s ? cfg->scan_block_s : XS_SCAN_DEFAULT_BLOCK_S) * 1000000000ULL;
	__u32 h = (__u32)xs_mix64(((__u64)p->daddr.v4 << 16) ^ (__u64)p->dport ^ ((__u64)p->l4_proto << 48)) & 511;
	__u32 w = (h >> 6) & 7;
	__u64 bit = 1ULL << (h & 63);

	if (!s) {
		struct xs_scan n = {};

		n.window_ns = now;
		n.count = 1;
		n.bits[w] = bit;
		bpf_map_update_elem(&xs_scan_v4, &sa, &n, BPF_ANY);
		return 0;
	}
	if (now - s->window_ns > window) {
		s->window_ns = now;
		s->count = 0;
		s->blocked_until_ns = 0;
		for (int i = 0; i < 8; i++)
			s->bits[i] = 0;
	}
	if (!(s->bits[w] & bit)) {
		s->bits[w] |= bit;
		s->count++;
	}
	if (s->count >= thr) {
		s->blocked_until_ns = now + block;
		s->count = 0;
		xs_count(st, XS_CNT_SCAN_DETECTED, len);
		return 1;
	}
	return 0;
}

/*
 * SYN authentication (XS_CFG_SYN_AUTH). Called for a TCP SYN (no ACK) from a
 * non-exempt source. Returns 1 to drop. A verified source passes; otherwise the
 * first SYN of a connection is held back and its {5-tuple, ISN} remembered, and
 * the client's own retransmission of that exact SYN (0.2-30 s later) verifies
 * the source for 10 minutes. Spoofed SYN floods never retransmit.
 */
static __always_inline int xs_syn_auth_drop(struct xs_stats *st, const struct xs_pkt *p,
					    __u64 now, __u64 len)
{
	__u64 src = p->l3 == XS_L3_IPV4 ? ((__u64)p->saddr.v4 | (1ULL << 63)) : xs_addr_hi(&p->saddr);
	__u64 *ok = bpf_map_lookup_elem(&xs_synauth_ok, &src);

	if (ok && now < *ok)
		return 0;

	__u64 key = xs_mix64(xs_hash_flow(p) ^ ((__u64)p->tcp_seq << 13));
	__u64 *first = bpf_map_lookup_elem(&xs_synauth_pend, &key);

	if (first) {
		__u64 age = now - *first;

		if (age >= XS_SYNAUTH_MIN_NS && age <= XS_SYNAUTH_MAX_NS) {
			__u64 until = now + XS_SYNAUTH_TRUST_NS;

			bpf_map_update_elem(&xs_synauth_ok, &src, &until, BPF_ANY);
			bpf_map_delete_elem(&xs_synauth_pend, &key);
			xs_count(st, XS_CNT_SYNAUTH_PASS, len);
			return 0;
		}
		if (age > XS_SYNAUTH_MAX_NS)
			*first = now; /* stale: start over */
		return 1;
	}
	bpf_map_update_elem(&xs_synauth_pend, &key, &now, BPF_ANY);
	return 1;
}

/*
 * The xs_l2_trust entry when this frame's source MAC is a registered upstream
 * router (anti-spoofing for the allowlist, see policy.h), else NULL. One small
 * hash lookup, only made while the allowlist is armed.
 */
static __always_inline const struct xs_l2_trust *xs_upstream_router(void *data, void *data_end)
{
	struct xs_mac_key k = {};

	if (data + 12 > data_end)
		return NULL;
	__builtin_memcpy(k.addr, (__u8 *)data + 6, 6);
	return bpf_map_lookup_elem(&xs_untrusted_l2, &k);
}

/* ---- Honeypot addresses (struct xs_honeypot) ---- */

static __always_inline int xs_mac_eq(const __u8 *a, const __u8 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
	       a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static __always_inline struct xs_honeypot_hit *xs_honeypot_src_of(__be32 src, const __u8 *mac, __u64 now)
{
	struct xs_honeypot_hit *h = bpf_map_lookup_elem(&xs_honeypot_src, &src);

	if (!h) {
		struct xs_honeypot_hit n = {};

		n.first_ns = now;
		__builtin_memcpy(n.src_mac, mac, 6);
		bpf_map_update_elem(&xs_honeypot_src, &src, &n, BPF_ANY);
		h = bpf_map_lookup_elem(&xs_honeypot_src, &src);
	}
	return h;
}

/*
 * ARP for a honeypot address. Returns XDP_TX after turning a request into the
 * reply in place, XDP_PASS for an ARP the honeypot does not answer, or -1 when
 * the frame has nothing to do with a honeypot (normal processing continues).
 *
 * A real device that uses a honeypot address (its own request, reply or
 * gratuitous ARP with that sender address) stands the honeypot down at once,
 * so a device that got the address from DHCP keeps working. Address probes
 * (sender 0.0.0.0, RFC 5227) are never answered for the same reason.
 */
static __always_inline int xs_honeypot_arp(struct xs_stats *st, void *data, void *data_end,
					   const struct xs_pkt *p, __u64 now, __u64 len)
{
	__u8 *eth = data;
	__u8 *a = (__u8 *)data + 14 + 4 * (p->vlan_depth & 3);
	__be32 spa, tpa;

	if ((void *)(eth + 14) > data_end || (void *)(a + 28) > data_end)
		return -1;
	/* Ethernet/IPv4 ARP only: htype 1, ptype 0x0800, hlen 6, plen 4 */
	if (a[0] != 0 || a[1] != 1 || a[2] != 0x08 || a[3] != 0 || a[4] != 6 || a[5] != 4)
		return -1;
	__builtin_memcpy(&spa, a + 14, 4);
	__builtin_memcpy(&tpa, a + 24, 4);

	struct xs_honeypot *own = bpf_map_lookup_elem(&xs_honeypot_v4, &spa);

	if (own && !xs_mac_eq(a + 8, own->mac)) {
		if (!own->conflict_ns) {
			own->conflict_ns = now;
			xs_count(st, XS_CNT_HONEYPOT_CONFLICT, len);
		}
		return -1;
	}

	/* requests only (op 1), never probes or gratuitous ARP */
	if (a[6] != 0 || a[7] != 1 || spa == 0 || spa == tpa)
		return -1;
	struct xs_honeypot *hp = bpf_map_lookup_elem(&xs_honeypot_v4, &tpa);

	/* an interactive decoy is a real address of the box: its kernel answers */
	if (!hp || hp->conflict_ns || (hp->flags & XS_HP_INTERACT))
		return -1;

	struct xs_honeypot_hit *h = xs_honeypot_src_of(spa, a + 8, now);

	if (h) {
		h->arps++;
		h->last_ns = now;
		h->last_dst = tpa;
	}

	/* request -> reply, in place */
	__u8 req_mac[6];

	__builtin_memcpy(req_mac, a + 8, 6);
	__builtin_memcpy(eth, req_mac, 6);          /* eth dst = asker */
	__builtin_memcpy(eth + 6, hp->mac, 6);      /* eth src = honeypot */
	a[7] = 2;                                   /* op = reply */
	__builtin_memcpy(a + 8, hp->mac, 6);        /* sender = honeypot */
	__builtin_memcpy(a + 14, &tpa, 4);
	__builtin_memcpy(a + 18, req_mac, 6);       /* target = asker */
	__builtin_memcpy(a + 24, &spa, 4);
	xs_count(st, XS_CNT_HONEYPOT_ARP, len);
	return XDP_TX;
}

/*
 * An IPv4 packet to a honeypot address: record its source and drop it. When
 * the honeypot has XS_HP_BLOCK, a source that sends TCP or UDP to it is
 * scan-blocked from the internal network (enforced by XS_CFG_SCAN_BLOCK, which
 * never touches traffic to the box itself or to the internet). ICMP alone never
 * blocks: a router's DHCP "is this address free?" ping must not get it blocked,
 * and neither does a registered upstream router.
 */
static __always_inline int xs_honeypot_ip(struct xs_stats *st, void *data, void *data_end,
					  const struct xs_pkt *p, const struct xs_config *cfg, __u64 now, __u64 len)
{
	__be32 dst = p->daddr.v4;
	struct xs_honeypot *hp = bpf_map_lookup_elem(&xs_honeypot_v4, &dst);
	__u8 *eth = data;

	if (!hp || hp->conflict_ns || (void *)(eth + 14) > data_end)
		return -1;

	__be32 src = p->saddr.v4;
	struct xs_honeypot_hit *h = xs_honeypot_src_of(src, eth + 6, now);

	xs_count(st, XS_CNT_HONEYPOT_HIT, len);
	if (!h)
		return XDP_DROP;
	h->packets++;
	h->last_ns = now;
	h->last_dst = dst;
	h->last_proto = p->l4_proto;
	h->last_dport = p->l4_parsed && (p->l4_proto == XS_IPPROTO_TCP || p->l4_proto == XS_IPPROTO_UDP) ? p->dport : 0;

	if ((hp->flags & XS_HP_BLOCK) && h->last_dport && !h->blocked &&
	    !(cfg && cfg->lifeline_v4 && src == cfg->lifeline_v4) && !xs_upstream_router(data, data_end)) {
		__u64 block = (__u64)(cfg && cfg->scan_block_s ? cfg->scan_block_s : XS_SCAN_DEFAULT_BLOCK_S) * 1000000000ULL;
		struct xs_scan *s = bpf_map_lookup_elem(&xs_scan_v4, &src);

		if (s) {
			s->blocked_until_ns = now + block;
		} else {
			struct xs_scan n = {};

			n.window_ns = now;
			n.blocked_until_ns = now + block;
			bpf_map_update_elem(&xs_scan_v4, &src, &n, BPF_ANY);
		}
		h->blocked = 1;
		xs_count(st, XS_CNT_SCAN_DETECTED, len);
	}
	/* Interactive decoy: let the fake logins (SSH 22, telnet 23, web 80) and
	 * ping through to the box, which owns the address; drop everything else so
	 * the box's real services never show up behind the decoy. */
	if (hp->flags & XS_HP_INTERACT) {
		__u16 dp = xs_ntohs_bounded(p->dport);

		if (p->l4_proto == 1 /* ICMP */ ||
		    (p->l4_parsed && p->l4_proto == XS_IPPROTO_TCP && (dp == 22 || dp == 23 || dp == 80))) {
			xs_count(st, XS_CNT_HONEYPOT_PASS, len);
			return XDP_PASS;
		}
	}
	return XDP_DROP;
}

/* ---- LAN guard (struct xs_languard) ---- */

/*
 * ARP that claims a bound address (router, box, approved device) from a
 * different MAC: someone is trying to become the man in the middle. Recorded
 * per {address, MAC}; dropped when the binding has XS_BIND_DROP. Returns
 * XDP_DROP or -1 (carry on).
 */
static __always_inline int xs_arp_guard(struct xs_stats *st, void *data, void *data_end,
					const struct xs_pkt *p, __u64 now, __u64 len)
{
	__u8 *a = (__u8 *)data + 14 + 4 * (p->vlan_depth & 3);
	struct xs_spoof_key k = {};

	if ((void *)(a + 28) > data_end)
		return -1;
	if (a[0] != 0 || a[1] != 1 || a[2] != 0x08 || a[3] != 0 || a[4] != 6 || a[5] != 4)
		return -1;
	__builtin_memcpy(&k.ip, a + 14, 4);
	if (k.ip == 0)
		return -1; /* address probe (RFC 5227): claims nothing */

	struct xs_arp_bind *b = bpf_map_lookup_elem(&xs_arp_bind, &k.ip);

	if (!b || xs_mac_eq(a + 8, b->mac))
		return -1;
	__builtin_memcpy(k.mac, a + 8, 6);
	struct xs_spoof *sp = bpf_map_lookup_elem(&xs_arp_spoof, &k);

	if (sp) {
		sp->last_ns = now;
		sp->frames++;
	} else {
		struct xs_spoof n = { .first_ns = now, .last_ns = now, .frames = 1 };

		bpf_map_update_elem(&xs_arp_spoof, &k, &n, BPF_ANY);
		sp = bpf_map_lookup_elem(&xs_arp_spoof, &k);
	}
	xs_count(st, XS_CNT_ARP_SPOOF, len);
	if (b->flags & XS_BIND_DROP) {
		if (sp)
			sp->dropped++;
		return XDP_DROP;
	}
	return -1;
}

/*
 * New-device approval. An IP packet from a MAC that is not approved is
 * recorded (watch mode) and, in enforce mode, dropped -- except DHCP (so it can
 * get an address), ICMPv6 (neighbour discovery) and anything to the box itself.
 * Returns XDP_DROP or -1.
 */
static __always_inline int xs_nac(struct xs_stats *st, void *data, void *data_end,
				  const struct xs_pkt *p, const struct xs_languard *lg, __u64 now, __u64 len)
{
	struct xs_mac_key k = {};

	if ((void *)((__u8 *)data + 12) > data_end)
		return -1;
	__builtin_memcpy(k.addr, (__u8 *)data + 6, 6);
	if (bpf_map_lookup_elem(&xs_nac_mac, &k))
		return -1;

	struct xs_nac_seen *s = bpf_map_lookup_elem(&xs_nac_seen, &k);

	if (!s) {
		struct xs_nac_seen n = { .first_ns = now };

		bpf_map_update_elem(&xs_nac_seen, &k, &n, BPF_ANY);
		s = bpf_map_lookup_elem(&xs_nac_seen, &k);
	}
	if (s) {
		s->packets++;
		s->last_ns = now;
		if (p->l3 == XS_L3_IPV4 && p->saddr.v4)
			s->ip = p->saddr.v4;
	}
	if (lg->nac != XS_NAC_ENFORCE)
		return -1;
	if (p->l4_parsed && p->l4_proto == XS_IPPROTO_UDP &&
	    (xs_ntohs_bounded(p->dport) == 67 || xs_ntohs_bounded(p->dport) == 68))
		return -1;
	if (p->l3 == XS_L3_IPV6 && p->l4_proto == 58)
		return -1;
	if (p->l3 == XS_L3_IPV4 && lg->lifeline && p->daddr.v4 == lg->lifeline)
		return -1;
	if (s)
		s->dropped++;
	xs_count(st, XS_CNT_NAC_DROP, len);
	return XDP_DROP;
}

/* ---- Attack signatures (struct xs_sig_key / xs_sig_rule) ---- */

/* Count a dropped packet by its shape (called on the 1-in-16 drop sample). */
static __always_inline void xs_sig_note(const struct xs_pkt *p, __u64 len)
{
	struct xs_sig_key k = {};
	struct xs_sig_count *c;

	k.proto = p->l4_proto;
	k.ttl = p->ttl;
	k.len64 = len / 64 > 255 ? 255 : (__u8)(len / 64);
	if (p->l4_parsed && (p->l4_proto == XS_IPPROTO_TCP || p->l4_proto == XS_IPPROTO_UDP)) {
		k.dport = p->dport;
		k.sport = p->sport;
		if (p->l4_proto == XS_IPPROTO_TCP)
			k.tcp_flags = p->tcp_flags;
	} else if (p->l4_parsed) {
		/* ICMP / ICMPv6: type and code ride in dport */
		k.dport = bpf_htons(((__u16)p->icmp_type << 8) | p->icmp_code);
	}
	c = bpf_map_lookup_elem(&xs_sig_seen, &k);
	if (c) {
		__sync_fetch_and_add(&c->packets, 1);
		__sync_fetch_and_add(&c->bytes, len);
	} else {
		struct xs_sig_count n = { .packets = 1, .bytes = len };

		bpf_map_update_elem(&xs_sig_seen, &k, &n, BPF_ANY);
	}
}

/* True when an approved signature rule matches (and counts the hit). */
static __always_inline int xs_sig_match(const struct xs_pkt *p, __u64 len)
{
	const __u32 zero = 0;
	__u32 *on = bpf_map_lookup_elem(&xs_sig_on, &zero);

	if (!on || !*on)
		return 0;
	for (__u32 i = 0; i < XS_SIG_RULES; i++) {
		struct xs_sig_rule *r = bpf_map_lookup_elem(&xs_sig_rules, &i);

		if (!r || !r->on)
			continue;
		if ((r->match & XS_SIG_PROTO) && r->proto != p->l4_proto)
			continue;
		if ((r->match & XS_SIG_DPORT) && (!p->l4_parsed || r->dport != p->dport))
			continue;
		if ((r->match & XS_SIG_SPORT) && (!p->l4_parsed || r->sport != p->sport))
			continue;
		if ((r->match & XS_SIG_FLAGS) && (p->tcp_flags & r->flags_mask) != r->tcp_flags)
			continue;
		if ((r->match & XS_SIG_LEN) && (len < r->len_lo || len > r->len_hi))
			continue;
		if ((r->match & XS_SIG_TTL) && (p->ttl < r->ttl_lo || p->ttl > r->ttl_hi))
			continue;
		__sync_fetch_and_add(&r->hits, 1);
		return 1;
	}
	return 0;
}

/* True when the destination is under default-deny (listed in xs_protected_v4). */
static __always_inline int xs_is_protected(const struct xs_pkt *p)
{
	__be32 d = p->daddr.v4;

	return bpf_map_lookup_elem(&xs_protected_v4, &d) ? 1 : 0;
}

/*
 * True when an IPv4 destination is a private/internal address (RFC1918).
 * Lockdown uses this so it only ever drops traffic bound for the internal
 * network and NEVER a packet to a public destination. That is what keeps the
 * Twingate connector's link to its public relays (and any other egress to the
 * internet) alive while lockdown is armed, so the remote operator can never
 * lose their tunnel by turning lockdown on.
 */
static __always_inline int xs_dst_is_internal(const struct xs_pkt *p)
{
	__u32 d = bpf_ntohl(p->daddr.v4);
	__u8 a = (__u8)(d >> 24);
	__u8 b = (__u8)(d >> 16);

	if (a == 10)
		return 1;                        /* 10.0.0.0/8     */
	if (a == 172 && (b & 0xf0) == 16)
		return 1;                        /* 172.16.0.0/12  */
	if (a == 192 && b == 168)
		return 1;                        /* 192.168.0.0/16 */
	return 0;
}

SEC("xdp")
int xs_xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	const __u32 zero = 0;
	struct xs_pkt pkt = {};
	const struct xs_config *cfg;
	struct xs_stats *st;
	__u64 len = data_end - data;
	__u32 flags;
	int rc, verdict;

	st = bpf_map_lookup_elem(&xs_stats, &zero);
	if (!st)
		return XDP_PASS; /* cannot happen for index 0; required by the verifier */
	cfg = bpf_map_lookup_elem(&xs_config, &zero);
	flags = cfg ? cfg->flags : 0;
	__u32 hll_epoch = cfg ? cfg->hll_epoch : 0;
	__u32 sample_shift = cfg ? cfg->sample_shift : 0;
	struct xs_rl_params rl = cfg ? xs_rl_params_of(cfg->rl_interval_ns, cfg->rl_burst)
				     : xs_rl_params_of(0, 0);
	struct xs_rl_params grl = cfg ? xs_rl_params_of(cfg->global_rl_interval_ns, cfg->global_rl_burst)
				      : xs_rl_params_of(0, 0);
	/* One monotonic clock read per packet, shared by the policy stage,
	 * conntrack, the aggregate rate limiter and the sampler. Reading it once
	 * is cheaper on the armed hot path and keeps the stages time-consistent. */
	__u64 now = bpf_ktime_get_ns();

	xs_count(st, XS_CNT_RX, len);

	/*
	 * The verifier treats a global function's return value as an unknown
	 * scalar, but clang (21+) propagates xs_parse()'s real return range
	 * (0..XS_PARSE_RC_MAX-1) across the call and deletes the bounds check
	 * in xs_count() that the verifier needs for the rc-indexed counter
	 * slot ("R2 unbounded memory access" on Linux 7.0 / clang 21).
	 * Hiding rc from the optimiser keeps that check in the object.
	 */
	rc = xs_opaque(xs_parse(ctx, &pkt));
	xs_account_parse(st, &pkt, rc, len);

	/*
	 * Phase 2 policy stage. Only entered when the control plane has
	 * installed at least one allowlist or block entry (a CHECK_* bit set),
	 * so the clock read and map lookups are skipped otherwise. A trusted
	 * allowlist match or an active block decides the verdict here, ahead of
	 * the deterministic validity checks.
	 */
	int decision = XS_POL_CONTINUE;
	/* ARP storm cap (always on, see xs_arp_rl_drop). Decided first: ARP never
	 * reaches the IP-only stages below, so this is its only guard. */
	int arp_drop = rc == XS_PARSE_NOT_IP && pkt.eth_proto == bpf_htons(XS_ETH_P_ARP) &&
		       xs_arp_rl_drop(now);
	/* Honeypot addresses: decided ahead of the policy stage so even trusted
	 * sources are recorded (nothing legitimate ever talks to them). */
	int honey = -1;
	__u32 *hp_on = bpf_map_lookup_elem(&xs_honeypot_on, &zero);
	/* LAN guard: ARP spoofing and new-device approval, ahead of everything
	 * that trusts LAN addresses. */
	int guard = -1;
	const struct xs_languard *lg = bpf_map_lookup_elem(&xs_languard_cfg, &zero);

	if (lg && !arp_drop) {
		if (lg->bindings && rc == XS_PARSE_NOT_IP && pkt.eth_proto == bpf_htons(XS_ETH_P_ARP))
			guard = xs_arp_guard(st, data, data_end, &pkt, now, len);
		else if (lg->nac && rc == XS_PARSE_OK && (pkt.l3 == XS_L3_IPV4 || pkt.l3 == XS_L3_IPV6))
			guard = xs_nac(st, data, data_end, &pkt, lg, now, len);
	}

	if (hp_on && *hp_on && !arp_drop && guard < 0) {
		if (rc == XS_PARSE_NOT_IP && pkt.eth_proto == bpf_htons(XS_ETH_P_ARP))
			honey = xs_honeypot_arp(st, data, data_end, &pkt, now, len);
		else if (rc == XS_PARSE_OK && pkt.l3 == XS_L3_IPV4)
			honey = xs_honeypot_ip(st, data, data_end, &pkt, cfg, now, len);
	}

	if (!arp_drop && guard < 0 && honey < 0 && (flags & (XS_CFG_CHECK_ALLOW | XS_CFG_CHECK_POLICY | XS_CFG_RATELIMIT)))
		decision = xs_policy_stage(st, &pkt, flags, &rl, now, len,
					   (flags & XS_CFG_CHECK_ALLOW) ? xs_upstream_router(data, data_end) : NULL);

	/* Allowlisted (dynamic-exempt) sources are validity-checked but skip the
	 * aggregate cap and conntrack drop, so the operator's own box is never cut
	 * off by those blunt, under-attack mitigations. */
	int exempt = (decision == XS_POL_EXEMPT);

	if (arp_drop) {
		xs_count(st, XS_CNT_ARP_RATE_LIMITED, len);
		verdict = XDP_DROP;
	} else if (guard >= 0) {
		verdict = guard;
	} else if (honey >= 0) {
		verdict = honey;
	} else if (decision == XS_POL_PASS)
		verdict = XDP_PASS;
	else if (decision == XS_POL_DROP)
		verdict = XDP_DROP;
	else if (!exempt && (flags & XS_CFG_SERVICE_ALLOW) && rc == XS_PARSE_OK &&
		 ((pkt.l3 == XS_L3_IPV4 && xs_service_denied(&pkt)) ||
		  (pkt.l3 == XS_L3_IPV6 && xs_service_denied6(&pkt)))) {
		/*
		 * Positive security model: on a protected destination only the
		 * explicitly allowed {proto,dport} services pass; everything else is
		 * dropped and attributed as service_deny. Checked ahead of the
		 * per-vector drops so off-service floods are cut at the door.
		 */
		xs_count(st, XS_CNT_SERVICE_DENY, len);
		verdict = XDP_DROP;
	} else if (!exempt && (flags & (XS_CFG_LOCKDOWN | XS_CFG_AUTO_LOCKDOWN)) && rc == XS_PARSE_OK &&
		   pkt.l3 == XS_L3_IPV4 && xs_dst_is_internal(&pkt) && !xs_is_protected(&pkt)) {
		/*
		 * Lockdown kill-switch: inside the internal network only protected
		 * destinations are reachable; every other IPv4 packet to an internal
		 * (RFC1918) address is dropped (attributed as service_deny). Packets to
		 * PUBLIC destinations always fall through, so the Twingate connector's
		 * link to its relays survives and arming lockdown can never sever the
		 * operator's own tunnel. Protected hosts still obey their service
		 * allowlist (handled just above). ARP / IPv6 are untouched so the
		 * bridge never isolates itself.
		 */
		xs_count(st, XS_CNT_SERVICE_DENY, len);
		verdict = XDP_DROP;
	} else {
		/*
		 * Precise, per-vector validity drops run FIRST, ahead of the aggregate
		 * rate limiter. A malformed / UDP / ICMP / fragment / bad-flags /
		 * IPv6-ext flood is then dropped and attributed as exactly that vector
		 * instead of being masked as a generic "rate_limited" drop (the limiter
		 * used to run first and swallow ~96% of drops). It also stops clearly-bad
		 * traffic from consuming the limiter's GCRA budget, so the aggregate cap
		 * is spent only on the ambiguous volumetric remainder.
		 */
		verdict = xs_validity_verdict(rc, &pkt, flags);
		/*
		 * Attack signatures the operator approved (from an earlier attack's
		 * dominant packet shape): matching traffic from outside is dropped at
		 * once, before the risk ladder has to climb. Exempt sources never.
		 */
		if (verdict != XDP_DROP && !exempt && rc == XS_PARSE_OK && xs_sig_match(&pkt, len)) {
			xs_count(st, XS_CNT_SIG_DROP, len);
			verdict = XDP_DROP;
		}
		/*
		 * Scan detection: a source probing many internal targets is cut off from
		 * the internal network for a while. Runs for allowlist-exempt LAN sources
		 * too (FULL trust never gets here), but never touches traffic aimed at
		 * the box itself (lifeline_v4) or bound for the internet.
		 */
		if (verdict != XDP_DROP && (flags & XS_CFG_SCAN_BLOCK) && rc == XS_PARSE_OK &&
		    pkt.l3 == XS_L3_IPV4 && xs_dst_is_internal(&pkt) &&
		    !(cfg && cfg->lifeline_v4 && pkt.daddr.v4 == cfg->lifeline_v4) &&
		    xs_scan_drop(st, cfg, &pkt, now, len)) {
			xs_count(st, XS_CNT_SCAN_DROP, len);
			verdict = XDP_DROP;
		}
		/*
		 * SYN authentication under a SYN flood: hold back the first SYN of an
		 * unverified source until it retransmits (exempt sources skip it).
		 */
		if (verdict != XDP_DROP && !exempt && (flags & XS_CFG_SYN_AUTH) && rc == XS_PARSE_OK &&
		    pkt.l4_parsed && pkt.l4_proto == XS_IPPROTO_TCP &&
		    (pkt.tcp_flags & XS_TCP_SYN) && !(pkt.tcp_flags & XS_TCP_ACK) &&
		    xs_syn_auth_drop(st, &pkt, now, len)) {
			xs_count(st, XS_CNT_SYNAUTH_DROP, len);
			verdict = XDP_DROP;
		}
		/*
		 * Connection tracking: for TCP that validity passed, count packets
		 * matching no tracked flow (ACK/RST flood) and, only when
		 * DROP_UNTRACKED is set, drop them. SYN/SYN-ACK create the flow inside
		 * xs_conntrack_untracked, so legitimate handshakes are always tracked.
		 */
		if (!exempt && verdict != XDP_DROP && (flags & XS_CFG_CONNTRACK) && rc == XS_PARSE_OK &&
		    pkt.l4_parsed && pkt.l4_proto == XS_IPPROTO_TCP &&
		    xs_conntrack_untracked(&pkt, now)) {
			xs_count(st, XS_CNT_CT_UNTRACKED, len);
			if (flags & XS_CFG_DROP_UNTRACKED)
				verdict = XDP_DROP;
		}
		/*
		 * Aggregate (interface-wide) rate limiter LAST: only packets that
		 * survived the precise drops above are metered, so it caps whatever
		 * volumetric remainder the per-vector rules cannot name -- notably a
		 * spoofed-source TCP/SYN flood, which per-source limiting can't catch.
		 * Still counted as a rate-limiter drop.
		 */
		if (verdict != XDP_DROP && !exempt && (flags & XS_CFG_GLOBAL_RL) && grl.interval_ns &&
		    rc == XS_PARSE_OK && xs_global_rl_drop(&grl, now)) {
			xs_count(st, XS_CNT_RATE_LIMITED, len);
			verdict = XDP_DROP;
		}
	}

	xs_count(st, verdict == XDP_DROP ? XS_CNT_VERDICT_DROP :
		     verdict == XDP_TX ? XS_CNT_VERDICT_TX : XS_CNT_VERDICT_PASS, len);
	if (verdict == XDP_TX)
		return XDP_TX; /* a honeypot ARP reply: nothing more to account */

	/*
	 * Per-destination victim accounting. Only on a drop (so an un-attacked
	 * box never touches this map), credit the targeted IPv4 destination so
	 * the control plane can name which host the flood was aimed at. IPv6 is
	 * a later addition.
	 */
	/*
	 * Sample the per-IP attribution maps: credit victim/attacker on ~1/16 of
	 * drops instead of every one, so a fully source-spoofed flood no longer
	 * does an LRU insert+evict per packet on the drop fast path. The exact
	 * per-CPU drop/byte totals above are untouched; top-talker ranking is
	 * statistical and unaffected by 16x downsampling. (The VERDICT_DROP counter
	 * was just incremented, so its low nibble cycles 0..15 across drops.)
	 */
	if (verdict == XDP_DROP && (st->c[XS_CNT_VERDICT_DROP].packets & 0xF) == 0) {
		if (rc == XS_PARSE_OK && (pkt.l3 == XS_L3_IPV4 || pkt.l3 == XS_L3_IPV6))
			xs_sig_note(&pkt, len);
		if (pkt.l3 == XS_L3_IPV4) {
			__be32 dkey = pkt.daddr.v4;
			struct xs_victim *v = bpf_map_lookup_elem(&xs_victim_v4, &dkey);
			__be32 skey = pkt.saddr.v4;
			struct xs_victim *a = bpf_map_lookup_elem(&xs_attacker_v4, &skey);

			if (v) {
				__sync_fetch_and_add(&v->packets, 1);
				__sync_fetch_and_add(&v->bytes, len);
			} else {
				struct xs_victim nv = { .packets = 1, .bytes = len };

				bpf_map_update_elem(&xs_victim_v4, &dkey, &nv, BPF_ANY);
			}
			if (a) {
				__sync_fetch_and_add(&a->packets, 1);
				__sync_fetch_and_add(&a->bytes, len);
			} else {
				struct xs_victim na = { .packets = 1, .bytes = len };

				bpf_map_update_elem(&xs_attacker_v4, &skey, &na, BPF_ANY);
			}
		} else if (pkt.l3 == XS_L3_IPV6) {
			/* Victim: the full /128 destination. */
			struct xs_in6 dkey = {};
			struct xs_in6 skey = {};
			struct xs_victim *v, *a;

			__builtin_memcpy(dkey.a, &pkt.daddr, 16);
			/* Attacker: the source /64 (zero the low 64 bits). */
			__builtin_memcpy(skey.a, &pkt.saddr, 8);

			v = bpf_map_lookup_elem(&xs_victim_v6, &dkey);
			a = bpf_map_lookup_elem(&xs_attacker_v6, &skey);
			if (v) {
				__sync_fetch_and_add(&v->packets, 1);
				__sync_fetch_and_add(&v->bytes, len);
			} else {
				struct xs_victim nv = { .packets = 1, .bytes = len };

				bpf_map_update_elem(&xs_victim_v6, &dkey, &nv, BPF_ANY);
			}
			if (a) {
				__sync_fetch_and_add(&a->packets, 1);
				__sync_fetch_and_add(&a->bytes, len);
			} else {
				struct xs_victim na = { .packets = 1, .bytes = len };

				bpf_map_update_elem(&xs_attacker_v6, &skey, &na, BPF_ANY);
			}
		}
	}

	/*
	 * Phase 5 flow aggregation. Only for fully parsed IP packets, and only
	 * for the stages the collector has switched on, so an idle system pays
	 * nothing. The clock is read once, lazily, and only when sampling.
	 */
	if (rc == XS_PARSE_OK && (flags & (XS_CFG_SAMPLING | XS_CFG_HLL | XS_CFG_DPORT_HIST))) {
		if (flags & XS_CFG_HLL)
			xs_hll_update(&pkt, hll_epoch);
		if (flags & XS_CFG_DPORT_HIST)
			xs_dport_bump(&pkt);
		if (flags & XS_CFG_SAMPLING)
			xs_maybe_sample(&pkt, sample_shift, now, verdict, rc, len);
	}
	return verdict;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
