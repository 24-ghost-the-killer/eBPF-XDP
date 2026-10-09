// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Phase 2 in-kernel policy tests. Loads the compiled object, populates the
 * allowlist and per-source policy maps, and runs crafted frames through the
 * program with BPF_PROG_TEST_RUN to verify:
 *
 *   - precedence: allowlist(FULL) > block > validity > pass;
 *   - DYNAMIC_EXEMPT skips the block table but still gets validity checks;
 *   - TTL expiry: a policy whose expires_ns has passed is ignored, and the
 *     POLICY_EXPIRED counter is bumped;
 *   - the block/allow CHECK_* gating (nothing happens with the bits clear);
 *   - the verdict invariant still holds (pass + drop == rx).
 *
 * Expiry deadlines are set relative to CLOCK_MONOTONIC, which is the clock
 * bpf_ktime_get_ns() reads, so "past" and "future" are meaningful during the
 * test run.
 *
 * Requires root.  test_policy [path/to/xdp_main.bpf.o]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cases.h"

#define XDP_DROP_RC 1
#define XDP_PASS_RC 2

static int failures;
static int nr_cpus;

/* Source addresses used by the tests (network order via htonl at use). */
#define IP_BLOCKED   0x0A000001u /* 10.0.0.1  - blocked */
#define IP_ALLOWED   0x0A000002u /* 10.0.0.2  - allowlisted FULL */
#define IP_EXEMPT    0x0A000003u /* 10.0.0.3  - allowlisted DYNAMIC_EXEMPT + blocked */
#define IP_EXPIRED   0x0A000004u /* 10.0.0.4  - blocked but expired */
#define IP_NORMAL    0x0A000005u /* 10.0.0.5  - no policy */

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

/* A plain valid TCP SYN from src -> dst:80. */
static void build_syn(struct pb *b, __u32 saddr)
{
	pb_init(b);
	pb_eth(b, XS_ETH_P_IPV4);
	pb_ipv4(b, 6, saddr, DST4, 0, 0);
	pb_tcp(b, 40000, 80, SYN, 5);
	pb_finalize(b);
}

/* A NULL-flags TCP packet (bad flags) from src -> dst:80. */
static void build_nullflags(struct pb *b, __u32 saddr)
{
	pb_init(b);
	pb_eth(b, XS_ETH_P_IPV4);
	pb_ipv4(b, 6, saddr, DST4, 0, 0);
	pb_tcp(b, 40000, 80, 0, 5);
	pb_finalize(b);
}

static int run_frame(int prog_fd, const struct pb *b, __u32 *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = b->buf, .data_size_in = b->len, .repeat = 1);
	int err = bpf_prog_test_run_opts(prog_fd, &opts);

	*retval = opts.retval;
	return err;
}

static __u64 counter(int stats_fd, unsigned slot)
{
	struct xs_stats *pc = calloc(nr_cpus, sizeof(*pc));
	__u32 key = 0;
	__u64 sum = 0;

	if (bpf_map_lookup_elem(stats_fd, &key, pc) == 0)
		for (int c = 0; c < nr_cpus; c++)
			sum += pc[c].c[slot].packets;
	free(pc);
	return sum;
}

static void set_config(int cfg_fd, __u32 flags)
{
	struct xs_config cfg = { .abi_version = XS_ABI_VERSION, .flags = flags };
	__u32 key = 0;

	if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY))
		exit(2);
}

static void put_policy(int fd, __u32 saddr_h, __u8 action, __u64 expires)
{
	__be32 key = htonl(saddr_h);
	struct xs_policy pol = { .expires_ns = expires, .action = action,
				 .reason = XS_REASON_MANUAL, .policy_id = 1 };

	if (bpf_map_update_elem(fd, &key, &pol, BPF_ANY)) {
		perror("policy update");
		exit(2);
	}
}

static void put_allow(int fd, __u32 saddr_h, __u8 trust)
{
	struct xs_lpm_v4 key = { .prefixlen = 32 };
	struct xs_allow val = { .trust = trust };
	__be32 a = htonl(saddr_h);

	memcpy(key.addr, &a, 4);
	if (bpf_map_update_elem(fd, &key, &val, BPF_ANY)) {
		perror("allow update");
		exit(2);
	}
}

#define EXPECT(name, cond)                                                     \
	do {                                                                  \
		if (!(cond)) {                                                 \
			fprintf(stderr, "FAIL %s\n", name);                   \
			failures++;                                           \
		} else {                                                      \
			printf("ok   - %s\n", name);                          \
		}                                                             \
	} while (0)

/* Run one frame and return its retval, asserting the test_run call worked. */
static __u32 verdict(int prog_fd, const struct pb *b)
{
	__u32 rv;

	if (run_frame(prog_fd, b, &rv)) {
		fprintf(stderr, "test_run failed: %s\n", strerror(errno));
		exit(2);
	}
	return rv;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "ebpf/build/xdp_main.bpf.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prog_fd, stats_fd, cfg_fd, pol4_fd, allow4_fd;
	struct pb b;
	__u64 c0;

	nr_cpus = libbpf_num_possible_cpus();
	obj = bpf_object__open_file(path, NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "load %s failed: %s\n", path, strerror(errno));
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "xs_xdp_main");
	prog_fd = bpf_program__fd(prog);
	stats_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xs_stats"));
	cfg_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xs_config"));
	pol4_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xs_policy_v4"));
	allow4_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xs_allow_v4"));
	if (!prog || stats_fd < 0 || cfg_fd < 0 || pol4_fd < 0 || allow4_fd < 0) {
		fprintf(stderr, "object missing a Phase 2 map/program\n");
		return 2;
	}

	/* Populate maps. */
	put_policy(pol4_fd, IP_BLOCKED, XS_ACTION_DROP, 0);              /* never expires */
	put_policy(pol4_fd, IP_EXEMPT, XS_ACTION_DROP, 0);
	put_policy(pol4_fd, IP_EXPIRED, XS_ACTION_DROP, now_ns() - 1000000000ull); /* 1s ago */
	put_allow(allow4_fd, IP_ALLOWED, XS_TRUST_FULL);
	put_allow(allow4_fd, IP_EXEMPT, XS_TRUST_DYNAMIC_EXEMPT);

	/* 1. With CHECK_* bits clear, policies are ignored entirely. */
	set_config(cfg_fd, 0);
	build_syn(&b, IP_BLOCKED);
	EXPECT("blocked IP passes when CHECK_POLICY is off", verdict(prog_fd, &b) == XDP_PASS_RC);

	/* 2. Enable both checks. */
	set_config(cfg_fd, XS_CFG_CHECK_ALLOW | XS_CFG_CHECK_POLICY);

	c0 = counter(stats_fd, XS_CNT_POLICY_DROP);
	build_syn(&b, IP_BLOCKED);
	EXPECT("blocked IP is dropped", verdict(prog_fd, &b) == XDP_DROP_RC);
	EXPECT("POLICY_DROP counter incremented", counter(stats_fd, XS_CNT_POLICY_DROP) == c0 + 1);

	c0 = counter(stats_fd, XS_CNT_ALLOW_PASS);
	build_syn(&b, IP_ALLOWED);
	EXPECT("allowlisted IP passes", verdict(prog_fd, &b) == XDP_PASS_RC);
	EXPECT("ALLOW_PASS counter incremented", counter(stats_fd, XS_CNT_ALLOW_PASS) == c0 + 1);

	/* 3. FULL trust beats even a validity drop: bad flags from an allowlisted
	 *    IP still pass when DROP_BAD_TCP_FLAGS is set. */
	set_config(cfg_fd, XS_CFG_CHECK_ALLOW | XS_CFG_CHECK_POLICY | XS_CFG_DROP_BAD_TCP_FLAGS);
	build_nullflags(&b, IP_ALLOWED);
	EXPECT("FULL-trust allow overrides validity drop", verdict(prog_fd, &b) == XDP_PASS_RC);
	/* ...but a non-allowlisted bad-flags packet is still dropped by validity. */
	build_nullflags(&b, IP_NORMAL);
	EXPECT("normal bad-flags packet dropped by validity", verdict(prog_fd, &b) == XDP_DROP_RC);

	/* 4. DYNAMIC_EXEMPT: skips the block table (would be dropped) but is still
	 *    validity-checked. A clean SYN from the exempt+blocked IP passes. */
	set_config(cfg_fd, XS_CFG_CHECK_ALLOW | XS_CFG_CHECK_POLICY);
	build_syn(&b, IP_EXEMPT);
	EXPECT("DYNAMIC_EXEMPT skips its own block", verdict(prog_fd, &b) == XDP_PASS_RC);

	/* 5. Expired block is ignored and counted as expired. */
	c0 = counter(stats_fd, XS_CNT_POLICY_EXPIRED);
	build_syn(&b, IP_EXPIRED);
	EXPECT("expired block no longer drops", verdict(prog_fd, &b) == XDP_PASS_RC);
	EXPECT("POLICY_EXPIRED counter incremented", counter(stats_fd, XS_CNT_POLICY_EXPIRED) == c0 + 1);

	/* 6. Unlisted IP just passes. */
	build_syn(&b, IP_NORMAL);
	EXPECT("normal IP passes", verdict(prog_fd, &b) == XDP_PASS_RC);

	/* 7. Verdict invariant. */
	{
		__u64 rx = counter(stats_fd, XS_CNT_RX);
		__u64 pass = counter(stats_fd, XS_CNT_VERDICT_PASS);
		__u64 drop = counter(stats_fd, XS_CNT_VERDICT_DROP);

		EXPECT("rx == pass + drop", rx == pass + drop);
	}

	bpf_object__close(obj);
	if (failures) {
		printf("policy tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("policy tests: OK\n");
	return 0;
}
