// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Benchmark rung 0: the cheapest possible XDP program. Its cost is the
 * floor that every other measurement is compared against. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xs_baseline_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
