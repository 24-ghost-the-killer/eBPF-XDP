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

/*
 * Honeypot addresses: an ARP request for one is answered in place (XDP_TX) with
 * a correct reply; TCP to it is dropped, recorded and (with XS_HP_BLOCK) gets
 * the source scan-blocked from the LAN but not from the box; a ping to it never
 * blocks; a real device using the address stands the honeypot down.
 */
static void arp4(struct pb *b, __u16 op, const __u8 *sha, __u32 spa, __u32 tpa)
{
	pb_init(b);
	pb_eth(b, XS_ETH_P_ARP);
	__u8 *a = pb_put(b, 28);

	memset(a, 0, 28);
	a[1] = 1; a[2] = 0x08; a[4] = 6; a[5] = 4; a[7] = (__u8)op;
	memcpy(a + 8, sha, 6);
	pb_put32(a + 14, spa);
	pb_put32(a + 24, tpa);
}

static void run_honeypot(int prog_fd, int stats_fd, int cfg_fd, int on_fd, int hp_fd, int src_fd, int scan_fd)
{
	const __u8 hp_mac[6] = { 0x02, 0x58, 0x53, 0x48, 0x50, 0xc8 };
	const __u8 asker[6] = { 0x02, 0, 0, 0, 0, 0x01 }; /* pb_eth's source MAC */
	const __u8 squatter[6] = { 0x02, 0, 0, 0, 0, 0x77 };
	__u32 hp_ip = ip4(192, 168, 1, 200), hp2_ip = ip4(192, 168, 1, 201);
	__u32 scanner = ip4(192, 168, 1, 50), pinger = ip4(192, 168, 1, 51);
	__u32 lifeline = ip4(192, 168, 1, 193), other = ip4(192, 168, 1, 173);
	struct xs_config cfg = { .abi_version = XS_ABI_VERSION, .flags = XS_CFG_SCAN_BLOCK,
				 .lifeline_v4 = htonl(lifeline) };
	struct xs_honeypot hp = { .flags = XS_HP_BLOCK };
	struct totals before, after;
	__u32 key = 0, n = 2, rv;
	__be32 k;
	struct pb b;
	__u8 out[256];

	memcpy(hp.mac, hp_mac, 6);
	if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY) || bpf_map_update_elem(on_fd, &key, &n, BPF_ANY))
		exit(2);
	k = htonl(hp_ip);
	bpf_map_update_elem(hp_fd, &k, &hp, BPF_ANY);
	k = htonl(hp2_ip);
	bpf_map_update_elem(hp_fd, &k, &hp, BPF_ANY);
	if (read_totals(stats_fd, &before))
		exit(2);

	/* 1. ARP request "who has .200?" -> a reply from the honeypot MAC */
	arp4(&b, 1, asker, scanner, hp_ip);
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = b.buf, .data_size_in = b.len,
		    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
	if (bpf_prog_test_run_opts(prog_fd, &opts))
		exit(2);
	__u8 *a = out + 14;
	int reply_ok = opts.retval == 3 /* XDP_TX */ && opts.data_size_out == b.len &&
		       !memcmp(out, asker, 6) && !memcmp(out + 6, hp_mac, 6) && a[7] == 2 &&
		       !memcmp(a + 8, hp_mac, 6) && !memcmp(a + 18, asker, 6) &&
		       a[14] == 192 && a[17] == 200 && a[24] == 192 && a[27] == 50;
	CHECK(reply_ok, "honeypot: ARP for a honeypot got no correct reply (retval %u)", opts.retval);

	/* 2. ARP for a normal address and an address probe: not answered */
	arp4(&b, 1, asker, scanner, other);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_PASS_RC, "honeypot: ARP for a real address was not passed (%u)", rv);
	arp4(&b, 1, asker, 0, hp_ip);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_PASS_RC, "honeypot: an address probe (sender 0.0.0.0) was answered (%u)", rv);

	/* 3. a ping to the honeypot: dropped and recorded, never blocks */
	pb_init(&b); pb_eth(&b, XS_ETH_P_IPV4); pb_ipv4(&b, 1, pinger, hp_ip, 0, 0); pb_icmp(&b, 8, 0); pb_finalize(&b);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_DROP_RC, "honeypot: ping to it was not dropped (%u)", rv);
	tcp4(&b, pinger, other, 40000, 80, XS_TCP_SYN, 1);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_PASS_RC, "honeypot: a pinger was blocked (%u)", rv);

	/* 4. a TCP probe to the honeypot: dropped, recorded, source blocked from the LAN */
	tcp4(&b, scanner, hp_ip, 40001, 22, XS_TCP_SYN, 1);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_DROP_RC, "honeypot: TCP probe was not dropped (%u)", rv);
	tcp4(&b, scanner, other, 40002, 80, XS_TCP_SYN, 2);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_DROP_RC, "honeypot: probing source was not blocked from the LAN (%u)", rv);
	tcp4(&b, scanner, lifeline, 40003, 443, XS_TCP_SYN, 3);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_PASS_RC, "honeypot: blocked source lost the box itself (%u)", rv);

	struct xs_honeypot_hit h = {};

	k = htonl(scanner);
	CHECK(!bpf_map_lookup_elem(src_fd, &k, &h) && h.arps == 1 && h.packets == 1 && h.blocked == 1 &&
	      ntohs(h.last_dport) == 22 && h.last_proto == 6 && h.last_dst == htonl(hp_ip),
	      "honeypot: scanner record wrong (arps %u pkts %llu blocked %u port %u)", h.arps,
	      (unsigned long long)h.packets, h.blocked, ntohs(h.last_dport));
	memset(&h, 0, sizeof(h));
	k = htonl(pinger);
	CHECK(!bpf_map_lookup_elem(src_fd, &k, &h) && h.packets == 1 && !h.blocked,
	      "honeypot: pinger record wrong (pkts %llu blocked %u)", (unsigned long long)h.packets, h.blocked);

	/* 5. a real device announces .201 as its own: that honeypot stands down */
	arp4(&b, 1, squatter, hp2_ip, other);
	verdict_of(prog_fd, &b);
	arp4(&b, 1, asker, scanner, hp2_ip);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_PASS_RC, "honeypot: kept answering for an address a real device uses (%u)", rv);
	tcp4(&b, pinger, hp2_ip, 40004, 80, XS_TCP_SYN, 4);
	rv = verdict_of(prog_fd, &b);
	CHECK(rv == XDP_PASS_RC, "honeypot: traffic to the real device was dropped (%u)", rv);

	if (read_totals(stats_fd, &after))
		exit(2);
	CHECK(delta(&before, &after, XS_CNT_HONEYPOT_ARP) == 1, "honeypot: %llu ARP replies (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_HONEYPOT_ARP));
	CHECK(delta(&before, &after, XS_CNT_HONEYPOT_HIT) == 2, "honeypot: %llu hits (want 2)",
	      (unsigned long long)delta(&before, &after, XS_CNT_HONEYPOT_HIT));
	CHECK(delta(&before, &after, XS_CNT_HONEYPOT_CONFLICT) == 1, "honeypot: %llu conflicts (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_HONEYPOT_CONFLICT));
	CHECK(delta(&before, &after, XS_CNT_VERDICT_TX) == 1, "honeypot: %llu TX verdicts (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_VERDICT_TX));

	/* leave the feature off for the tests that follow */
	n = 0;
	bpf_map_update_elem(on_fd, &key, &n, BPF_ANY);
	k = htonl(scanner);
	bpf_map_delete_elem(scan_fd, &k);
	set_flags(cfg_fd, 0);
	if (!failures)
		printf("honeypot: ARP answered, probes recorded, prober blocked from LAN (not the box), pings never block, conflict stands down\n");
}

/*
 * LAN guard: an ARP frame claiming the router's address from another MAC is
 * recorded and (XS_BIND_DROP) dropped, the real router's ARP passes. New-device
 * approval: watch mode records an unapproved MAC but passes it; enforce mode
 * drops it except DHCP and traffic to the box; approved MACs always pass.
 */
static void run_languard(int prog_fd, int stats_fd, int lg_fd, int bind_fd, int spoof_fd, int nacm_fd, int nacs_fd)
{
	const __u8 router[6] = { 0x5c, 0xa6, 0xe6, 0x3a, 0x1d, 0xc3 };
	const __u8 evil[6] = { 0x02, 0, 0, 0, 0, 0x01 }; /* pb_eth's source MAC */
	__u32 gw = ip4(192, 168, 1, 1), box = ip4(192, 168, 1, 193), dev = ip4(192, 168, 1, 60), other = ip4(192, 168, 1, 173);
	struct xs_languard lg = { .bindings = 1, .nac = XS_NAC_WATCH, .lifeline = htonl(box) };
	struct xs_arp_bind b = { .flags = XS_BIND_DROP };
	struct totals before, after;
	__u32 key = 0, rv;
	__be32 k = htonl(gw);
	struct pb pk;

	memcpy(b.mac, router, 6);
	if (bpf_map_update_elem(lg_fd, &key, &lg, BPF_ANY) || bpf_map_update_elem(bind_fd, &k, &b, BPF_ANY))
		exit(2);
	if (read_totals(stats_fd, &before))
		exit(2);

	/* 1. "I am 192.168.1.1" from a foreign MAC: dropped and recorded */
	arp4(&pk, 2, evil, gw, dev);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_DROP_RC, "languard: router impersonation passed (%u)", rv);
	arp4(&pk, 2, router, gw, dev);
	memcpy(pk.buf + 6, router, 6);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "languard: the real router's ARP was dropped (%u)", rv);
	struct xs_spoof_key sk = { .ip = htonl(gw) };
	struct xs_spoof sp = {};

	memcpy(sk.mac, evil, 6);
	CHECK(!bpf_map_lookup_elem(spoof_fd, &sk, &sp) && sp.frames == 1 && sp.dropped == 1,
	      "languard: spoof record wrong (frames %u dropped %u)", sp.frames, sp.dropped);

	/* 2. watch mode: unapproved device recorded, passed */
	tcp4(&pk, dev, other, 40000, 80, XS_TCP_SYN, 1);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "nac: watch mode dropped an unapproved device (%u)", rv);
	struct xs_mac_key mk = {};
	struct xs_nac_seen ns = {};

	memcpy(mk.addr, evil, 6);
	CHECK(!bpf_map_lookup_elem(nacs_fd, &mk, &ns) && ns.packets == 1 && ns.ip == htonl(dev),
	      "nac: unapproved device not recorded (pkts %llu)", (unsigned long long)ns.packets);

	/* 3. enforce mode: dropped, but DHCP and the box still pass */
	lg.nac = XS_NAC_ENFORCE;
	bpf_map_update_elem(lg_fd, &key, &lg, BPF_ANY);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_DROP_RC, "nac: enforce mode passed an unapproved device (%u)", rv);
	tcp4(&pk, dev, box, 40001, 443, XS_TCP_SYN, 2);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "nac: unapproved device lost the box itself (%u)", rv);
	pb_init(&pk); pb_eth(&pk, XS_ETH_P_IPV4); pb_ipv4(&pk, 17, 0, 0xffffffff, 0, 0); pb_udp(&pk, 68, 67); pb_payload(&pk, 240); pb_finalize(&pk);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "nac: DHCP from an unapproved device was dropped (%u)", rv);

	/* 4. approve it: passes */
	__u32 one = 1;
	bpf_map_update_elem(nacm_fd, &mk, &one, BPF_ANY);
	tcp4(&pk, dev, other, 40002, 80, XS_TCP_SYN, 3);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "nac: an approved device was dropped (%u)", rv);

	if (read_totals(stats_fd, &after))
		exit(2);
	CHECK(delta(&before, &after, XS_CNT_ARP_SPOOF) == 1, "languard: %llu spoof counts (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_ARP_SPOOF));
	CHECK(delta(&before, &after, XS_CNT_NAC_DROP) == 1, "nac: %llu drops (want 1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_NAC_DROP));

	struct xs_languard off = {};

	bpf_map_update_elem(lg_fd, &key, &off, BPF_ANY);
	bpf_map_delete_elem(nacm_fd, &mk);
	if (!failures)
		printf("languard: router impersonation dropped, real router passes; new devices watched, enforced (DHCP + box allowed), approved pass\n");
}

/*
 * Attack signatures: dropped packets are counted by shape; an approved rule
 * drops matching traffic from outside at once, never from an exempt source,
 * and counts its hits.
 */
static void run_signature(int prog_fd, int stats_fd, int cfg_fd, int seen_fd, int rules_fd, int on_fd)
{
	__u32 attacker = ip4(203, 0, 113, 9), victim = ip4(192, 168, 1, 173);
	struct xs_sig_rule r = { .on = 1, .proto = 17, .dport = htons(11211), .len_lo = 60, .len_hi = 1500,
				 .match = XS_SIG_PROTO | XS_SIG_DPORT | XS_SIG_LEN };
	struct totals before, after;
	__u32 key = 0, n = 1, rv;
	struct pb pk;

	set_flags(cfg_fd, XS_CFG_DROP_UDP);
	/* 64 dropped UDP packets -> some land in the 1-in-16 shape counter */
	pb_init(&pk); pb_eth(&pk, XS_ETH_P_IPV4); pb_ipv4(&pk, 17, attacker, victim, 0, 0); pb_udp(&pk, 4444, 11211); pb_payload(&pk, 100); pb_finalize(&pk);
	for (int i = 0; i < 64; i++)
		verdict_of(prog_fd, &pk);
	struct xs_sig_key sk = { .proto = 17, .ttl = pk.buf[14 + 8], .len64 = (__u8)(pk.len / 64), .dport = htons(11211), .sport = htons(4444) };
	struct xs_sig_count c = {};

	CHECK(!bpf_map_lookup_elem(seen_fd, &sk, &c) && c.packets >= 1, "signature: dropped packet shape not counted");

	/* approved rule: dropped even with no drop flag armed */
	set_flags(cfg_fd, 0);
	bpf_map_update_elem(rules_fd, &key, &r, BPF_ANY);
	bpf_map_update_elem(on_fd, &key, &n, BPF_ANY);
	if (read_totals(stats_fd, &before))
		exit(2);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_DROP_RC, "signature: matching packet passed (%u)", rv);
	pb_init(&pk); pb_eth(&pk, XS_ETH_P_IPV4); pb_ipv4(&pk, 17, attacker, victim, 0, 0); pb_udp(&pk, 4444, 53); pb_payload(&pk, 100); pb_finalize(&pk);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "signature: a non-matching packet was dropped (%u)", rv);
	if (read_totals(stats_fd, &after))
		exit(2);
	struct xs_sig_rule got = {};

	bpf_map_lookup_elem(rules_fd, &key, &got);
	CHECK(delta(&before, &after, XS_CNT_SIG_DROP) == 1 && got.hits == 1, "signature: %llu drops, %llu hits (want 1/1)",
	      (unsigned long long)delta(&before, &after, XS_CNT_SIG_DROP), (unsigned long long)got.hits);

	struct xs_sig_rule none = {};

	n = 0;
	bpf_map_update_elem(rules_fd, &key, &none, BPF_ANY);
	bpf_map_update_elem(on_fd, &key, &n, BPF_ANY);
	if (!failures)
		printf("signature: drop shapes counted; approved rule drops its match at once, nothing else\n");
}

/* Interactive decoy: the fake-login ports and ping pass to the box, other ports drop, no ARP answer. */
static void run_honeypot_interact(int prog_fd, int on_fd, int hp_fd)
{
	__u32 hp_ip = ip4(192, 168, 1, 210), scanner = ip4(192, 168, 1, 52);
	const __u8 asker[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	struct xs_honeypot hp = { .mac = { 0x02, 0x58, 0x53, 0x48, 0x50, 0xd2 }, .flags = XS_HP_INTERACT };
	__u32 key = 0, n = 1, rv;
	__be32 k = htonl(hp_ip);
	struct pb pk;

	bpf_map_update_elem(hp_fd, &k, &hp, BPF_ANY);
	bpf_map_update_elem(on_fd, &key, &n, BPF_ANY);
	tcp4(&pk, scanner, hp_ip, 40000, 22, XS_TCP_SYN, 1);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "interactive decoy: SSH to it was dropped (%u)", rv);
	tcp4(&pk, scanner, hp_ip, 40001, 3000, XS_TCP_SYN, 2);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_DROP_RC, "interactive decoy: a real box port showed through (%u)", rv);
	arp4(&pk, 1, asker, scanner, hp_ip);
	rv = verdict_of(prog_fd, &pk);
	CHECK(rv == XDP_PASS_RC, "interactive decoy: XDP answered ARP the kernel should answer (%u)", rv);
	n = 0;
	bpf_map_update_elem(on_fd, &key, &n, BPF_ANY);
	bpf_map_delete_elem(hp_fd, &k);
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
	{
		struct bpf_map *on = bpf_object__find_map_by_name(obj, "xs_honeypot_on");
		struct bpf_map *hp = bpf_object__find_map_by_name(obj, "xs_honeypot_v4");
		struct bpf_map *hs = bpf_object__find_map_by_name(obj, "xs_honeypot_src");
		struct bpf_map *sc = bpf_object__find_map_by_name(obj, "xs_scan_v4");

		if (!on || !hp || !hs || !sc) {
			fprintf(stderr, "FAIL object has no honeypot maps\n");
			failures++;
		} else {
			run_honeypot(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg), bpf_map__fd(on),
				     bpf_map__fd(hp), bpf_map__fd(hs), bpf_map__fd(sc));
			run_honeypot_interact(bpf_program__fd(prog), bpf_map__fd(on), bpf_map__fd(hp));
		}
	}
	{
		const char *names[] = { "xs_languard_cfg", "xs_arp_bind", "xs_arp_spoof", "xs_nac_mac", "xs_nac_seen",
					"xs_sig_seen", "xs_sig_rules", "xs_sig_on" };
		int fd[8];
		int ok = 1;

		for (int i = 0; i < 8; i++) {
			struct bpf_map *m = bpf_object__find_map_by_name(obj, names[i]);

			fd[i] = m ? bpf_map__fd(m) : -1;
			if (fd[i] < 0) {
				fprintf(stderr, "FAIL object has no map %s\n", names[i]);
				failures++;
				ok = 0;
			}
		}
		if (ok) {
			run_languard(bpf_program__fd(prog), bpf_map__fd(stats), fd[0], fd[1], fd[2], fd[3], fd[4]);
			run_signature(bpf_program__fd(prog), bpf_map__fd(stats), bpf_map__fd(cfg), fd[5], fd[6], fd[7]);
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
