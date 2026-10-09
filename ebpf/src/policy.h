/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * policy.h - Phase 2 per-source policy and allowlist stage.
 *
 * Runs after parsing/accounting and before the deterministic validity
 * verdict. Precedence, highest first:
 *
 *   1. allowlist, FULL trust      -> PASS immediately, skip everything
 *   2. allowlist, DYNAMIC_EXEMPT  -> skip the block table, still validity-checked
 *   3. per-source block policy    -> DROP (or explicit PASS), if not expired
 *   4. (caller continues to the validity verdict)
 *
 * Expiry is enforced here with the deadline the control plane wrote
 * (CLOCK_MONOTONIC, matching bpf_ktime_get_ns): an entry whose expires_ns
 * has passed is ignored, so a temporary block lifts itself even if the agent
 * that created it has died. Userspace still garbage-collects expired entries
 * to free capacity, but correctness does not depend on it.
 *
 * Everything is gated by config bits (XS_CFG_CHECK_ALLOW / _POLICY) that
 * userspace sets only while the maps are non-empty, so an appliance with no
 * policies pays nothing.
 */
#ifndef XS_POLICY_H
#define XS_POLICY_H

#include "compat.h"
#include "abi.h"
#include "maps.h"
#include "parsers.h"
#include "telemetry.h"
#include "rate_limit.h"

/* Result of the policy stage. */
enum xs_policy_result {
	XS_POL_CONTINUE = 0, /* no decision; fall through to the validity verdict */
	XS_POL_PASS     = 1, /* pass now (trusted or explicit pass) */
	XS_POL_DROP     = 2, /* drop now (active block) */
	XS_POL_EXEMPT   = 3, /* allowlisted (dynamic-exempt): validity-check only,
			      * skip the aggregate cap and conntrack drop too */
};

static __always_inline int xs_policy_active(const struct xs_policy *pol, __u64 now)
{
	return pol->expires_ns == 0 || now < pol->expires_ns;
}

static __always_inline int xs_allow_active(const struct xs_allow *a, __u64 now)
{
	return a->expires_ns == 0 || now < a->expires_ns;
}

/*
 * Apply a found block policy. Only DROP and explicit PASS are actioned in
 * Phase 2; RATE_LIMIT is reserved and, until Phase 3 implements it, is
 * treated as "no decision" (fail open) rather than silently dropping.
 */
static __always_inline int xs_apply_policy(struct xs_stats *st, const struct xs_policy *pol,
					   __u64 now, __u64 len)
{
	if (!xs_policy_active(pol, now)) {
		xs_count(st, XS_CNT_POLICY_EXPIRED, len);
		return XS_POL_CONTINUE;
	}
	if (pol->action == XS_ACTION_DROP) {
		xs_count(st, XS_CNT_POLICY_DROP, len);
		return XS_POL_DROP;
	}
	if (pol->action == XS_ACTION_PASS)
		return XS_POL_PASS;
	return XS_POL_CONTINUE; /* unknown/reserved action: fail open */
}

/*
 * Automatic per-source rate limiting. Runs only for sources that were not
 * allowlisted (exempt) or already blocked. On the first packet from a source
 * the GCRA state is seeded (that packet conforms); afterwards each packet is
 * charged against the shared TAT and dropped when it does not conform.
 */
static __always_inline int xs_autorl_v4(struct xs_stats *st, __be32 sa,
					const struct xs_rl_params *rl, __u64 now, __u64 len)
{
	__u64 *tat = bpf_map_lookup_elem(&xs_rl_v4, &sa);

	xs_count(st, XS_CNT_RATE_TRACKED, len);
	if (!tat) {
		__u64 seed = now + rl->interval_ns;

		bpf_map_update_elem(&xs_rl_v4, &sa, &seed, BPF_ANY);
		return XS_POL_CONTINUE;
	}
	if (xs_gcra(tat, rl->interval_ns, rl->tolerance_ns, now))
		return XS_POL_CONTINUE;
	xs_count(st, XS_CNT_RATE_LIMITED, len);
	return XS_POL_DROP;
}

static __always_inline int xs_autorl_v6(struct xs_stats *st, __u64 prefix,
					const struct xs_rl_params *rl, __u64 now, __u64 len)
{
	__u64 *tat = bpf_map_lookup_elem(&xs_rl_v6, &prefix);

	xs_count(st, XS_CNT_RATE_TRACKED, len);
	if (!tat) {
		__u64 seed = now + rl->interval_ns;

		bpf_map_update_elem(&xs_rl_v6, &prefix, &seed, BPF_ANY);
		return XS_POL_CONTINUE;
	}
	if (xs_gcra(tat, rl->interval_ns, rl->tolerance_ns, now))
		return XS_POL_CONTINUE;
	xs_count(st, XS_CNT_RATE_LIMITED, len);
	return XS_POL_DROP;
}

/* IPv4 path. */
static __always_inline int xs_policy_lookup_v4(struct xs_stats *st, const struct xs_pkt *p,
					__u32 flags, const struct xs_rl_params *rl, __u64 now, __u64 len)
{
	int exempt = 0;

	if (flags & XS_CFG_CHECK_ALLOW) {
		struct xs_lpm_v4 k = { .prefixlen = 32 };
		struct xs_allow *a;

		__builtin_memcpy(k.addr, &p->saddr.v4, 4);
		a = bpf_map_lookup_elem(&xs_allow_v4, &k);
		if (a && xs_allow_active(a, now)) {
			if (a->trust == XS_TRUST_FULL) {
				xs_count(st, XS_CNT_ALLOW_PASS, len);
				return XS_POL_PASS;
			}
			exempt = 1; /* DYNAMIC_EXEMPT: skip block + rate limit below */
		}
	}
	if ((flags & XS_CFG_CHECK_POLICY) && !exempt) {
		struct xs_policy *pol = bpf_map_lookup_elem(&xs_policy_v4, &p->saddr.v4);

		if (pol) {
			int r = xs_apply_policy(st, pol, now, len);

			if (r != XS_POL_CONTINUE)
				return r;
		}
	}
	if ((flags & XS_CFG_RATELIMIT) && !exempt)
		return xs_autorl_v4(st, p->saddr.v4, rl, now, len);
	return exempt ? XS_POL_EXEMPT : XS_POL_CONTINUE;
}

/* IPv6 path: key the policy/rate tables on the /64 prefix (first 8 address bytes). */
static __always_inline int xs_policy_lookup_v6(struct xs_stats *st, const struct xs_pkt *p,
					__u32 flags, const struct xs_rl_params *rl, __u64 now, __u64 len)
{
	int exempt = 0;
	__u64 prefix;

	__builtin_memcpy(&prefix, p->saddr.v6, 8);

	if (flags & XS_CFG_CHECK_ALLOW) {
		struct xs_lpm_v6 k = { .prefixlen = 128 };
		struct xs_allow *a;

		__builtin_memcpy(k.addr, p->saddr.v6, 16);
		a = bpf_map_lookup_elem(&xs_allow_v6, &k);
		if (a && xs_allow_active(a, now)) {
			if (a->trust == XS_TRUST_FULL) {
				xs_count(st, XS_CNT_ALLOW_PASS, len);
				return XS_POL_PASS;
			}
			exempt = 1;
		}
	}
	if ((flags & XS_CFG_CHECK_POLICY) && !exempt) {
		struct xs_policy *pol = bpf_map_lookup_elem(&xs_policy_v6, &prefix);

		if (pol) {
			int r = xs_apply_policy(st, pol, now, len);

			if (r != XS_POL_CONTINUE)
				return r;
		}
	}
	if ((flags & XS_CFG_RATELIMIT) && !exempt)
		return xs_autorl_v6(st, prefix, rl, now, len);
	return exempt ? XS_POL_EXEMPT : XS_POL_CONTINUE;
}

/*
 * Policy stage entry point. Returns an enum xs_policy_result. `now` is read
 * once by the caller (only when a CHECK or RATELIMIT bit is set) to avoid a
 * bpf_ktime_get_ns() call on the no-policy fast path.
 */
static __always_inline int xs_policy_stage(struct xs_stats *st, const struct xs_pkt *p,
					   __u32 flags, const struct xs_rl_params *rl,
					   __u64 now, __u64 len)
{
	if (p->l3 == XS_L3_IPV4)
		return xs_policy_lookup_v4(st, p, flags, rl, now, len);
	if (p->l3 == XS_L3_IPV6)
		return xs_policy_lookup_v6(st, p, flags, rl, now, len);
	return XS_POL_CONTINUE; /* non-IP: no per-source policy applies */
}

#endif /* XS_POLICY_H */
