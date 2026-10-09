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

	if (flags & (XS_CFG_CHECK_ALLOW | XS_CFG_CHECK_POLICY | XS_CFG_RATELIMIT))
		decision = xs_policy_stage(st, &pkt, flags, &rl, bpf_ktime_get_ns(), len);

	/* Allowlisted (dynamic-exempt) sources are validity-checked but skip the
	 * aggregate cap and conntrack drop, so the operator's own box is never cut
	 * off by those blunt, under-attack mitigations. */
	int exempt = (decision == XS_POL_EXEMPT);

	if (decision == XS_POL_PASS)
		verdict = XDP_PASS;
	else if (decision == XS_POL_DROP)
		verdict = XDP_DROP;
	else if (!exempt && (flags & XS_CFG_GLOBAL_RL) && grl.interval_ns && rc == XS_PARSE_OK &&
		 xs_global_rl_drop(&grl, bpf_ktime_get_ns())) {
		/* aggregate cap hit: drops spoofed-source floods per-source can't.
		 * Counted as a rate-limiter drop. */
		xs_count(st, XS_CNT_RATE_LIMITED, len);
		verdict = XDP_DROP;
	} else {
		verdict = xs_validity_verdict(rc, &pkt, flags);
		/*
		 * Connection tracking: for TCP that validity passed, count packets
		 * matching no tracked flow (ACK/RST flood) and, only when
		 * DROP_UNTRACKED is set, drop them. SYN/SYN-ACK create the flow inside
		 * xs_conntrack_untracked, so legitimate handshakes are always tracked.
		 */
		if (!exempt && verdict != XDP_DROP && (flags & XS_CFG_CONNTRACK) && rc == XS_PARSE_OK &&
		    pkt.l4_parsed && pkt.l4_proto == XS_IPPROTO_TCP &&
		    xs_conntrack_untracked(&pkt, bpf_ktime_get_ns())) {
			xs_count(st, XS_CNT_CT_UNTRACKED, len);
			if (flags & XS_CFG_DROP_UNTRACKED)
				verdict = XDP_DROP;
		}
	}

	xs_count(st, verdict == XDP_DROP ? XS_CNT_VERDICT_DROP : XS_CNT_VERDICT_PASS, len);

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
			xs_maybe_sample(&pkt, sample_shift, bpf_ktime_get_ns(), verdict, rc, len);
	}
	return verdict;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
