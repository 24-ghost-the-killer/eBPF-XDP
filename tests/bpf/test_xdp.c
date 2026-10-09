// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * In-kernel dataplane tests. Loads the compiled XDP object through the real
 * verifier and executes it with BPF_PROG_TEST_RUN on every corpus frame:
 *
 *   1. verifier: the object must load; verifier statistics are printed so
 *      regressions in verification cost are visible in CI logs;
 *   2. default config (all zero): every frame must return XDP_PASS;
 *   3. strict config (all drop flags): the verdict must match the corpus;
 *   4. counters: RX, the parse-outcome slot, the verdict slot and the
 *      case-specific slots must increase by exactly one packet and by the
 *      frame length in bytes;
 *   5. invariants over the whole run: sum(parse outcomes) == RX and
 *      PASS + DROP == RX.
 *
 * Requires root (CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN).
 *
 *   test_xdp [path/to/xdp_main.bpf.o]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cases.h"

#define XDP_DROP_RC 1
#define XDP_PASS_RC 2

static int failures;
static int nr_cpus;

struct totals {
	struct xs_counter c[XS_CNT_SLOTS];
};

static int read_totals(int map_fd, struct totals *t)
{
	struct xs_stats *percpu = calloc(nr_cpus, sizeof(*percpu));
	__u32 key = 0;
	int err;

	if (!percpu)
		return -ENOMEM;
	err = bpf_map_lookup_elem(map_fd, &key, percpu);
	if (!err) {
		memset(t, 0, sizeof(*t));
		for (int cpu = 0; cpu < nr_cpus; cpu++)
			for (int i = 0; i < XS_CNT_SLOTS; i++) {
				t->c[i].packets += percpu[cpu].c[i].packets;
				t->c[i].bytes += percpu[cpu].c[i].bytes;
			}
	}
	free(percpu);
	return err;
}

static int set_flags(int map_fd, __u32 flags)
{
	struct xs_config cfg = { .abi_version = XS_ABI_VERSION, .flags = flags };
	__u32 key = 0;

	return bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
}

static int run_frame(int prog_fd, const struct pb *b, __u32 *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = b->buf,
		.data_size_in = b->len,
		.repeat = 1,
	);
	int err = bpf_prog_test_run_opts(prog_fd, &opts);

	*retval = opts.retval;
	return err;
}

static void expect_delta(const char *name, const char *what, const struct totals *before,
			 const struct totals *after, unsigned id, __u64 bytes)
{
	__u64 dp = after->c[id].packets - before->c[id].packets;
	__u64 db = after->c[id].bytes - before->c[id].bytes;

	if (dp != 1 || db != bytes) {
		fprintf(stderr, "FAIL %-18s counter %s[%u]: +%llu pkts +%llu bytes, want +1/+%llu\n",
			name, what, id, (unsigned long long)dp, (unsigned long long)db,
			(unsigned long long)bytes);
		failures++;
	}
}

static void run_corpus(int prog_fd, int stats_fd, int cfg_fd, int strict)
{
	/* The corpus is all-valid traffic; "strict" exercises the base validity
	 * drops. The per-vector drops (ICMP/SYN/ACK/UDP_STRICT) drop valid packets
	 * and are attack-only, so they are not part of this deterministic set. */
	__u32 flags = strict ? XS_CFG_VALIDITY_FLAGS : 0;
	int skipped = 0;

	if (set_flags(cfg_fd, flags)) {
		perror("config update");
		exit(2);
	}

	for (size_t i = 0; i < XS_N_CASES; i++) {
		const struct xs_case *c = &xs_cases[i];
		struct totals before, after;
		struct pb b;
		__u32 retval, want;
		int err;

		pb_init(&b);
		c->build(&b);
		if (read_totals(stats_fd, &before))
			exit(2);
		err = run_frame(prog_fd, &b, &retval);
		if (err) {
			/* The kernel refuses test frames shorter than an Ethernet
			 * header (-EINVAL); such frames are covered by the host
			 * parser tests. */
			if (b.len < 14) {
				skipped++;
				continue;
			}
			fprintf(stderr, "FAIL %-18s test_run: %s\n", c->name, strerror(-err));
			failures++;
			continue;
		}
		if (read_totals(stats_fd, &after))
			exit(2);

		want = (strict && c->strict == 'D') ? XDP_DROP_RC : XDP_PASS_RC;
		if (retval != want) {
			fprintf(stderr, "FAIL %-18s %s verdict %u want %u\n", c->name,
				strict ? "strict" : "default", retval, want);
			failures++;
		}

		expect_delta(c->name, "RX", &before, &after, XS_CNT_RX, b.len);
		expect_delta(c->name, "PARSE", &before, &after, XS_CNT_PARSE_BASE + c->rc, b.len);
		expect_delta(c->name, "VERDICT", &before, &after,
			     want == XDP_DROP_RC ? XS_CNT_VERDICT_DROP : XS_CNT_VERDICT_PASS, b.len);
		for (int k = 0; k < 4 && c->counters[k]; k++)
			expect_delta(c->name, "CLASS", &before, &after, c->counters[k], b.len);
	}
	printf("%-8s config: %zu frames run, %d skipped (shorter than ETH_HLEN)\n",
	       strict ? "strict" : "default", XS_N_CASES - skipped, skipped);
}

static void check_invariants(int stats_fd)
{
	struct totals t;
	__u64 parse = 0, verdicts;

	if (read_totals(stats_fd, &t))
		exit(2);
	for (int i = 0; i < XS_PARSE_RC_MAX; i++)
		parse += t.c[XS_CNT_PARSE_BASE + i].packets;
	verdicts = t.c[XS_CNT_VERDICT_PASS].packets + t.c[XS_CNT_VERDICT_DROP].packets +
		   t.c[XS_CNT_VERDICT_TX].packets + t.c[XS_CNT_VERDICT_REDIRECT].packets;
	if (parse != t.c[XS_CNT_RX].packets || verdicts != t.c[XS_CNT_RX].packets) {
		fprintf(stderr, "FAIL invariants: rx=%llu parse_sum=%llu verdict_sum=%llu\n",
			(unsigned long long)t.c[XS_CNT_RX].packets, (unsigned long long)parse,
			(unsigned long long)verdicts);
		failures++;
	} else {
		printf("invariants: rx=%llu == sum(parse outcomes) == sum(verdicts)\n",
		       (unsigned long long)t.c[XS_CNT_RX].packets);
	}
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "ebpf/build/xdp_main.bpf.o";
	static char vlog[64 * 1024];
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *stats, *cfg;
	int err;

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus <= 0) {
		fprintf(stderr, "cannot determine possible CPUs\n");
		return 2;
	}

	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 2;
	}
	prog = bpf_object__find_program_by_name(obj, "xs_xdp_main");
	stats = bpf_object__find_map_by_name(obj, "xs_stats");
	cfg = bpf_object__find_map_by_name(obj, "xs_config");
	if (!prog || !stats || !cfg) {
		fprintf(stderr, "object is missing xs_xdp_main/xs_stats/xs_config\n");
		return 2;
	}

	/* log level 4 = BPF_LOG_STATS: only the summary lines */
	bpf_program__set_log_level(prog, 4);
	bpf_program__set_log_buf(prog, vlog, sizeof(vlog));
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "verifier rejected %s: %s\n%s\n", path, strerror(-err), vlog);
		return 1;
	}
	printf("verifier: accepted, %u BPF insns\n%s", (unsigned)bpf_program__insn_cnt(prog), vlog);

	run_corpus(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg), 0);
	run_corpus(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg), 1);
	check_invariants(bpf_map__fd(stats));

	bpf_object__close(obj);
	if (failures) {
		printf("xdp tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("xdp tests: OK\n");
	return 0;
}
