// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Phase 3 rate-limiter tests. Drives the compiled program with
 * BPF_PROG_TEST_RUN and verifies the automatic per-source GCRA limiter:
 *
 *   - conformance: at a limit of R pps with burst B, a source may send up to
 *     ~B packets instantly, then is capped near R over time;
 *   - a source under the limit is never dropped;
 *   - two sources are limited independently (per-source state);
 *   - allowlisted sources are exempt from the limiter;
 *   - the idle-reset property: after a quiet period the burst is available
 *     again;
 *   - the verdict invariant (pass + drop == rx).
 *
 * BPF_PROG_TEST_RUN executes the program back-to-back with no real time
 * between calls, so a tight loop of N runs models "N packets arriving at
 * effectively the same instant" - exactly the burst case a rate limiter must
 * bound. Wall-clock spacing is exercised by sleeping between bursts.
 *
 * Requires root.  test_ratelimit [path/to/xdp_main.bpf.o]
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
static int prog_fd, stats_fd, cfg_fd, rl4_fd, allow4_fd;

#define IP_A     0x0A000001u
#define IP_B     0x0A000002u
#define IP_TRUST 0x0A000003u

static __u64 counter(unsigned slot)
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

/* Enable the rate limiter at `pps` with burst `burst`. */
static void set_ratelimit(__u32 pps, __u32 burst)
{
	struct xs_config cfg = {
		.abi_version = XS_ABI_VERSION,
		.flags = pps ? XS_CFG_RATELIMIT : 0,
		.rl_interval_ns = pps ? 1000000000u / pps : 0,
		.rl_burst = burst,
	};
	__u32 key = 0;

	if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY))
		exit(2);
}

static void enable_allow(void)
{
	struct xs_config cfg = {
		.abi_version = XS_ABI_VERSION,
		.flags = XS_CFG_RATELIMIT | XS_CFG_CHECK_ALLOW,
		.rl_interval_ns = 1000000000u / 100, /* 100 pps */
		.rl_burst = 1,
	};
	__u32 key = 0;
	struct xs_lpm_v4 k = { .prefixlen = 32 };
	struct xs_allow val = { .trust = XS_TRUST_FULL };
	__be32 a = htonl(IP_TRUST);

	if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY))
		exit(2);
	memcpy(k.addr, &a, 4);
	if (bpf_map_update_elem(allow4_fd, &k, &val, BPF_ANY))
		exit(2);
}

static void clear_rl_state(void)
{
	/* Wipe per-source GCRA state so tests do not interfere. */
	__be32 key = 0, next;

	while (bpf_map_get_next_key(rl4_fd, &key, &next) == 0) {
		bpf_map_delete_elem(rl4_fd, &next);
		key = next;
	}
}

static __u32 send_one(__u32 saddr)
{
	struct pb b;
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	pb_init(&b);
	pb_eth(&b, XS_ETH_P_IPV4);
	pb_ipv4(&b, 6, saddr, DST4, 0, 0);
	pb_tcp(&b, 40000, 80, SYN, 5);
	pb_finalize(&b);
	opts.data_in = b.buf;
	opts.data_size_in = b.len;
	opts.repeat = 1;
	if (bpf_prog_test_run_opts(prog_fd, &opts)) {
		perror("test_run");
		exit(2);
	}
	return opts.retval;
}

/* Send `n` packets from `saddr` back-to-back; return how many passed. */
static int burst(__u32 saddr, int n)
{
	int passed = 0;

	for (int i = 0; i < n; i++)
		if (send_one(saddr) == XDP_PASS_RC)
			passed++;
	return passed;
}

#define EXPECT(name, cond)                                                    \
	do {                                                                  \
		if (!(cond)) {                                                 \
			fprintf(stderr, "FAIL %s\n", name);                   \
			failures++;                                           \
		} else {                                                      \
			printf("ok   - %s\n", name);                          \
		}                                                             \
	} while (0)

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "ebpf/build/xdp_main.bpf.o";
	struct bpf_object *obj;
	struct bpf_program *prog;

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
	rl4_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xs_rl_v4"));
	allow4_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xs_allow_v4"));
	if (rl4_fd < 0 || cfg_fd < 0) {
		fprintf(stderr, "object missing Phase 3 maps\n");
		return 2;
	}

	/* 1. Limiter off: a huge burst all passes. */
	set_ratelimit(0, 0);
	EXPECT("limiter off: 1000-packet burst all passes", burst(IP_A, 1000) == 1000);

	/* 2. Limit 100 pps, burst 20. A back-to-back burst (~same instant) is
	 *    capped near the bucket depth, not unlimited. */
	clear_rl_state();
	set_ratelimit(100, 20);
	int passed = burst(IP_A, 1000);
	EXPECT("burst is bounded by the bucket (<= 25 of 1000 pass)", passed <= 25);
	EXPECT("burst allows roughly the bucket depth (>= 15 pass)", passed >= 15);

	/* 3. A second source has its own budget. */
	int passed_b = burst(IP_B, 1000);
	EXPECT("second source limited independently (15..25)", passed_b >= 15 && passed_b <= 25);

	/* 4. Idle reset: after the bucket has drained (sleep > burst*interval),
	 *    the source may burst again. 20 packets at 100pps = 200ms of credit. */
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 300000000 }; /* 300 ms */
	nanosleep(&ts, NULL);
	EXPECT("burst available again after idle", burst(IP_A, 10) >= 5);

	/* 5. A source sending under the limit is never dropped: 10 packets each
	 *    spaced > interval (10ms) at 100pps all pass. */
	clear_rl_state();
	set_ratelimit(100, 4);
	int under = 0;
	for (int i = 0; i < 10; i++) {
		if (send_one(IP_B) == XDP_PASS_RC)
			under++;
		nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 12000000 }, NULL); /* 12 ms */
	}
	EXPECT("under-limit source never dropped", under == 10);

	/* 6. Allowlisted source is exempt from the limiter. */
	clear_rl_state();
	enable_allow();
	EXPECT("allowlisted source exempt from rate limit", burst(IP_TRUST, 500) == 500);

	/* 7. Verdict invariant. */
	EXPECT("rx == pass + drop",
	       counter(XS_CNT_RX) == counter(XS_CNT_VERDICT_PASS) + counter(XS_CNT_VERDICT_DROP));

	bpf_object__close(obj);
	if (failures) {
		printf("ratelimit tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("ratelimit tests: OK\n");
	return 0;
}
