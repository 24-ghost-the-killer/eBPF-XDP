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
#include <arpa/inet.h>
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

/*
 * ARP storm cap: replay one ARP frame back-to-back (a storm compressed into a
 * few ms). The always-on cap must pass the burst allowance (~500) and drop the
 * rest, attributing every drop to ARP_RATE_LIMITED. Runs LAST: it drains the
 * shared ARP budget, which would make the corpus's own ARP cases drop.
 */
static void run_arp_storm(int prog_fd, int stats_fd, int cfg_fd)
{
	const __u32 n = 5000;
	struct totals before, after;
	struct pb b;
	int err;

	if (set_flags(cfg_fd, 0)) {
		perror("config update");
		exit(2);
	}
	pb_init(&b);
	pb_eth(&b, XS_ETH_P_ARP);
	pb_payload(&b, 28);
	if (read_totals(stats_fd, &before))
		exit(2);
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = b.buf,
		.data_size_in = b.len,
		.repeat = n,
	);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err) {
		fprintf(stderr, "FAIL arp_storm test_run: %s\n", strerror(-err));
		failures++;
		return;
	}
	if (read_totals(stats_fd, &after))
		exit(2);

	__u64 rl = after.c[XS_CNT_ARP_RATE_LIMITED].packets - before.c[XS_CNT_ARP_RATE_LIMITED].packets;
	__u64 drop = after.c[XS_CNT_VERDICT_DROP].packets - before.c[XS_CNT_VERDICT_DROP].packets;
	__u64 pass = after.c[XS_CNT_VERDICT_PASS].packets - before.c[XS_CNT_VERDICT_PASS].packets;

	/* burst 500 (+1 for the conforming first slot, + a few for elapsed time) */
	if (rl != drop || pass < 400 || pass > 1000 || drop + pass != n) {
		fprintf(stderr, "FAIL arp_storm: %u frames -> pass %llu drop %llu arp_rl %llu\n", n,
			(unsigned long long)pass, (unsigned long long)drop, (unsigned long long)rl);
		failures++;
	} else {
		printf("arp storm: %u frames -> %llu passed (burst), %llu capped\n", n,
		       (unsigned long long)pass, (unsigned long long)drop);
	}
}

/* ---- shared helpers for the feature tests below ---- */

static __u32 ip4(int a, int b, int c, int d)
{
	return ((__u32)a << 24) | ((__u32)b << 16) | ((__u32)c << 8) | (__u32)d;
}

/* An IPv4 TCP frame with the given flags and sequence number. */
static void tcp4(struct pb *b, __u32 src, __u32 dst, __u16 sport, __u16 dport, __u8 flags, __u32 seq)
{
	pb_init(b);
	pb_eth(b, XS_ETH_P_IPV4);
	pb_ipv4(b, 6, src, dst, 0, 0);
	__u32 th = b->len;
	pb_tcp(b, sport, dport, flags, 5);
	pb_put32(b->buf + th + 4, seq);
	pb_finalize(b);
}

static __u32 verdict_of(int prog_fd, const struct pb *b)
{
	__u32 rv = 0;

	if (run_frame(prog_fd, b, &rv)) {
		fprintf(stderr, "test_run failed\n");
		exit(2);
	}
	return rv;
}

static __u64 delta(const struct totals *a, const struct totals *b, int slot)
{
	return b->c[slot].packets - a->c[slot].packets;
}

#define CHECK(cond, ...) do { if (!(cond)) { fprintf(stderr, "FAIL " __VA_ARGS__); fprintf(stderr, "\n"); failures++; } } while (0)

/*
 * Scan detection: a LAN source SYN-probing distinct ports on an internal host
 * is blocked when it reaches the threshold, and stays blocked for internal
 * destinations -- but its traffic to the box itself (lifeline) and to the
 * internet still passes.
 */
static void run_scan(int prog_fd, int stats_fd, int cfg_fd)
{
	struct xs_config cfg = { .abi_version = XS_ABI_VERSION, .flags = XS_CFG_SCAN_BLOCK,
				 .scan_threshold = 20, .scan_window_ms = 10000, .scan_block_s = 600,
				 .lifeline_v4 = htonl(ip4(192, 168, 1, 193)) };
	__u32 key = 0, scanner = ip4(192, 168, 1, 105), victim = ip4(192, 168, 1, 173);
	struct totals before, after;
	struct pb b;
	int passed = 0, first_drop = -1;

	if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY) || read_totals(stats_fd, &before))
		exit(2);
	for (int port = 1; port <= 30; port++) {
		tcp4(&b, scanner, victim, 50000, (__u16)port, 0x02, 1000 + port);
		if (verdict_of(prog_fd, &b) == XDP_PASS_RC)
			passed++;
		else if (first_drop < 0)
			first_drop = port;
	}
	/* a normal connection to the box itself must still pass */
	tcp4(&b, scanner, ip4(192, 168, 1, 193), 50001, 22, 0x02, 7);
	__u32 lifeline = verdict_of(prog_fd, &b);
	/* ... and so must internet-bound traffic */
	tcp4(&b, scanner, ip4(8, 8, 8, 8), 50002, 443, 0x02, 8);
	__u32 internet = verdict_of(prog_fd, &b);
	/* while an innocent LAN host probing a few ports is untouched */
	int other_ok = 1;
	for (int port = 1; port <= 5; port++) {
		tcp4(&b, ip4(192, 168, 1, 50), victim, 51000, (__u16)port, 0x02, 9);
		other_ok &= verdict_of(prog_fd, &b) == XDP_PASS_RC;
	}
	if (read_totals(stats_fd, &after))
		exit(2);

	/* distinct targets are counted in a 512-bit hashed set, so a hash collision
	 * can delay the block by a probe or two; never earlier than the threshold */
	CHECK(first_drop >= 20 && first_drop <= 25 && passed == first_drop - 1,
	      "scan: %d probes passed, first drop at port %d (want 19, 20 .. 24, 25)", passed, first_drop);
	CHECK(delta(&before, &after, XS_CNT_SCAN_DETECTED) == 1, "scan: detected %llu times (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_SCAN_DETECTED));
	CHECK(delta(&before, &after, XS_CNT_SCAN_DROP) == (__u64)(30 - first_drop + 1), "scan: %llu scan drops (want %d)",
	      (unsigned long long)delta(&before, &after, XS_CNT_SCAN_DROP), 30 - first_drop + 1);
	CHECK(lifeline == XDP_PASS_RC, "scan: traffic to the box itself was dropped");
	CHECK(internet == XDP_PASS_RC, "scan: internet-bound traffic was dropped");
	CHECK(other_ok, "scan: an innocent host was blocked");
	printf("scan detection: blocked at probe %d, box + internet still reachable\n", first_drop);
}

/*
 * SYN authentication: the first SYN of an unverified source is held back; the
 * same SYN retransmitted later verifies the source, whose next connections pass
 * at once. A different (spoofed) source is still held.
 */
static void run_synauth(int prog_fd, int stats_fd, int cfg_fd)
{
	__u32 client = ip4(203, 0, 113, 7), server = ip4(192, 168, 1, 173);
	struct totals before, after;
	struct pb b;

	if (set_flags(cfg_fd, XS_CFG_SYN_AUTH) || read_totals(stats_fd, &before))
		exit(2);
	tcp4(&b, client, server, 40000, 22, 0x02, 0x11223344);
	__u32 first = verdict_of(prog_fd, &b);
	__u32 too_soon = verdict_of(prog_fd, &b); /* immediate duplicate: not a real retransmit */
	usleep(300000);
	__u32 retrans = verdict_of(prog_fd, &b);
	tcp4(&b, client, server, 40001, 443, 0x02, 0x55667788);
	__u32 next_conn = verdict_of(prog_fd, &b);
	tcp4(&b, ip4(198, 51, 100, 9), server, 40002, 22, 0x02, 0x1);
	__u32 spoofed = verdict_of(prog_fd, &b);
	/* established traffic (ACK) is never touched by it */
	tcp4(&b, ip4(198, 51, 100, 10), server, 40003, 22, 0x10, 0x2);
	__u32 ack = verdict_of(prog_fd, &b);
	if (read_totals(stats_fd, &after))
		exit(2);

	CHECK(first == XDP_DROP_RC && too_soon == XDP_DROP_RC, "synauth: first SYN %u / immediate dup %u (want drop)", first, too_soon);
	CHECK(retrans == XDP_PASS_RC, "synauth: retransmitted SYN was not let through");
	CHECK(next_conn == XDP_PASS_RC, "synauth: verified source's next connection was held");
	CHECK(spoofed == XDP_DROP_RC, "synauth: unverified source passed");
	CHECK(ack == XDP_PASS_RC, "synauth: a plain ACK was dropped");
	CHECK(delta(&before, &after, XS_CNT_SYNAUTH_PASS) == 1, "synauth: %llu verified (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_SYNAUTH_PASS));
	printf("syn authentication: held first SYN, verified on retransmit, spoofed source stays out\n");
}

/*
 * IPv6 service allowlist: on a protected IPv6 destination only listed services
 * pass; ICMPv6 and return traffic to ephemeral ports always pass.
 */
static void run_service6(int prog_fd, int stats_fd, int cfg_fd, int prot_fd, int svc_fd)
{
	__u8 dst[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 };
	struct xs_service_key6 k = { .proto = 6 };
	__u8 one = 1;
	struct totals before, after;
	struct pb b;
	__u32 v[5];

	memcpy(k.daddr, dst, 16);
	k.dport = htons(22);
	if (bpf_map_update_elem(prot_fd, dst, &one, BPF_ANY) || bpf_map_update_elem(svc_fd, &k, &one, BPF_ANY) ||
	    set_flags(cfg_fd, XS_CFG_SERVICE_ALLOW) || read_totals(stats_fd, &before))
		exit(2);
	const struct { __u8 proto; __u16 dport; __u8 flags; } cases[5] = {
		{ 6, 22, 0x02 },     /* allowed service */
		{ 6, 80, 0x02 },     /* not listed */
		{ 58, 0, 0 },        /* ICMPv6 */
		{ 6, 40000, 0x10 },  /* return traffic (ACK to an ephemeral port) */
		{ 17, 53, 0 },       /* UDP, not listed */
	};
	for (int i = 0; i < 5; i++) {
		pb_init(&b);
		pb_eth(&b, XS_ETH_P_IPV6);
		pb_ipv6(&b, cases[i].proto, 0x99, 0x42);
		if (cases[i].proto == 6)
			pb_tcp(&b, 50000, cases[i].dport, cases[i].flags, 5);
		else if (cases[i].proto == 17)
			pb_udp(&b, 50000, cases[i].dport);
		else
			pb_icmp(&b, 128, 0);
		pb_finalize(&b);
		v[i] = verdict_of(prog_fd, &b);
	}
	if (read_totals(stats_fd, &after))
		exit(2);
	CHECK(v[0] == XDP_PASS_RC, "service6: allowed tcp/22 dropped");
	CHECK(v[1] == XDP_DROP_RC, "service6: unlisted tcp/80 passed");
	CHECK(v[2] == XDP_PASS_RC, "service6: ICMPv6 dropped (breaks IPv6)");
	CHECK(v[3] == XDP_PASS_RC, "service6: return traffic dropped");
	CHECK(v[4] == XDP_DROP_RC, "service6: unlisted udp/53 passed");
	CHECK(delta(&before, &after, XS_CNT_SERVICE_DENY) == 2, "service6: %llu service denies (want 2)",
	      (unsigned long long)delta(&before, &after, XS_CNT_SERVICE_DENY));
	bpf_map_delete_elem(prot_fd, dst);
	printf("ipv6 service allowlist: listed port passes, others dropped, ICMPv6 + replies pass\n");
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
	run_scan(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg));
	run_synauth(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg));
	{
		struct bpf_map *p6 = bpf_object__find_map_by_name(obj, "xs_protected_v6");
		struct bpf_map *s6 = bpf_object__find_map_by_name(obj, "xs_service_v6");

		if (!p6 || !s6) {
			fprintf(stderr, "FAIL object has no xs_protected_v6/xs_service_v6 maps\n");
			failures++;
		} else {
			run_service6(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg),
				     bpf_map__fd(p6), bpf_map__fd(s6));
		}
	}
	run_arp_storm(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg));
	check_invariants(bpf_map__fd(stats));

	bpf_object__close(obj);
	if (failures) {
		printf("xdp tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("xdp tests: OK\n");
	return 0;
}
