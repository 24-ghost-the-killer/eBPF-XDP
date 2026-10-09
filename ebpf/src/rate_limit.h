/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * rate_limit.h - Phase 3 per-source rate limiting (GCRA).
 *
 * GCRA (Generic Cell Rate Algorithm) is the virtual-scheduling form of the
 * leaky bucket. Its entire state is one timestamp, the Theoretical Arrival
 * Time (TAT), so it fits in a single 64-bit map value and is updated with one
 * compare-and-swap - no lock, no per-CPU split, correct when a source's
 * packets are spread across RX cores by RSS.
 *
 *   interval_ns  = 1e9 / rate       (ns of "virtual time" one packet consumes)
 *   tolerance_ns = interval_ns * burst   (how far ahead of "now" the TAT may
 *                                         run, i.e. the bucket depth)
 *
 * A packet conforms iff max(TAT, now) - now <= tolerance; on conformance the
 * TAT advances by interval_ns. An idle source (TAT far in the past) resets to
 * now, so a burst is allowed again after a quiet period.
 *
 * The CAS is retried once; sustained contention (a source hammering many
 * cores at once) failing the retry is reported as nonconforming, which is the
 * safe direction: that contention is itself evidence of a flood.
 */
#ifndef XS_RATE_LIMIT_H
#define XS_RATE_LIMIT_H

#include "compat.h"

/*
 * Run GCRA against a shared TAT word. Returns 1 (conforming) or 0
 * (nonconforming). `tat_ns` points into a map value.
 */
static __always_inline int xs_gcra(__u64 *tat_ns, __u32 interval_ns, __u64 tolerance_ns, __u64 now)
{
#pragma unroll
	for (int i = 0; i < 2; i++) {
		__u64 tat = *tat_ns;
		__u64 base = tat > now ? tat : now;

		if (base - now > tolerance_ns)
			return 0; /* arrived too early: nonconforming */
		if (__sync_bool_compare_and_swap(tat_ns, tat, base + interval_ns))
			return 1; /* reserved this packet's slot */
	}
	return 0; /* lost the race twice under contention: treat as nonconforming */
}

/* Rate-limiter parameters, derived once per packet from xs_config. */
struct xs_rl_params {
	__u32 interval_ns; /* 0 => limiter disabled */
	__u64 tolerance_ns;
};

static __always_inline struct xs_rl_params xs_rl_params_of(__u32 interval_ns, __u32 burst)
{
	struct xs_rl_params rl = {
		.interval_ns = interval_ns,
		.tolerance_ns = (__u64)interval_ns * (burst ? burst : 1),
	};
	return rl;
}

/*
 * Apply the limiter to one source. `tat` is the source's map value, or NULL
 * on the first packet from a source (the caller seeds it). Returns 1 to allow
 * (conforming / first packet), 0 to drop.
 */
static __always_inline int xs_rl_conforms(__u64 *tat, const struct xs_rl_params *rl, __u64 now)
{
	if (tat)
		return xs_gcra(tat, rl->interval_ns, rl->tolerance_ns, now);
	return 1; /* first packet from a new source always conforms */
}

#endif /* XS_RATE_LIMIT_H */
