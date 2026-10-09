// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * CPU-cost microbenchmark of the XDP program using BPF_PROG_TEST_RUN.
 *
 * What it measures: nanoseconds per invocation of the BPF program on one
 * CPU, averaged over `repeat` runs of the same frame, as reported by the
 * kernel (bpf_test_run timing). The frame stays hot in L1, so this is the
 * best case for the program itself.
 *
 * What it does NOT measure: NIC/driver RX cost, DMA, cache misses from
 * real traffic, map contention between CPUs, or line rate. It is a
 * regression gate for per-packet program cost, not a throughput claim.
 * Line-rate methodology is in docs/performance.md.
 *
 *   bench_prog_run <xdp_main.bpf.o> <baseline.bpf.o> [repeat]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cases.h"

struct frame {
	const char *name;
	void (*build)(struct pb *b, uint32_t size);
};

/* Pad a frame with payload to `size` bytes on the wire including the 4-byte
 * FCS, i.e. size - 4 bytes as seen by XDP. */
static void pad_to(struct pb *b, uint32_t size)
{
	uint32_t want = size - 4;

	if (b->len < want)
		pb_payload(b, want - b->len);
	pb_finalize(b);
}

static void f_v4_tcp_syn(struct pb *b, uint32_t size)
{
	pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 5);
	pad_to(b, size);
}

static void f_v4_udp(struct pb *b, uint32_t size)
{
	pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 40000, 53);
	pad_to(b, size);
}

static void f_v6_ext3_tcp(struct pb *b, uint32_t size)
{
	pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 60, 0);
	pb_ipv6_ext(b, 43, 1); pb_ipv6_ext(b, 6, 0); pb_tcp(b, 40000, 443, SYN, 5);
	pad_to(b, size);
}

static void f_qinq_v4_udp(struct pb *b, uint32_t size)
{
	pb_eth(b, XS_ETH_P_8021AD); pb_vlan(b, 200, XS_ETH_P_8021Q); pb_vlan(b, 100, XS_ETH_P_IPV4);
	pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 1, 2);
	pad_to(b, size);
}

static const struct frame frames[] = {
	{ "ipv4_tcp_syn", f_v4_tcp_syn },
	{ "ipv4_udp", f_v4_udp },
	{ "qinq_ipv4_udp", f_qinq_v4_udp },
	{ "ipv6_ext3_tcp", f_v6_ext3_tcp },
};

static const uint32_t sizes[] = { 64, 128, 256, 512, 1024, 1500 };

static int load(const char *path, const char *prog_name, struct bpf_object **obj)
{
	struct bpf_program *prog;

	*obj = bpf_object__open_file(path, NULL);
	if (!*obj || bpf_object__load(*obj)) {
		fprintf(stderr, "cannot load %s: %s\n", path, strerror(errno));
		exit(2);
	}
	prog = bpf_object__find_program_by_name(*obj, prog_name);
	if (!prog) {
		fprintf(stderr, "%s: no program %s\n", path, prog_name);
		exit(2);
	}
	return bpf_program__fd(prog);
}

static double ns_per_run(int prog_fd, const struct pb *b, __u32 repeat)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = b->buf,
		.data_size_in = b->len,
		.repeat = repeat,
	);
	/* best of 5 to suppress scheduler noise */
	double best = 1e18;

	for (int i = 0; i < 5; i++) {
		if (bpf_prog_test_run_opts(prog_fd, &opts)) {
			perror("test_run");
			exit(2);
		}
		if (opts.duration < best)
			best = opts.duration;
	}
	return best;
}

int main(int argc, char **argv)
{
	struct bpf_object *main_obj, *base_obj;
	int main_fd, base_fd;
	__u32 repeat;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <xdp_main.bpf.o> <baseline.bpf.o> [repeat]\n", argv[0]);
		return 2;
	}
	repeat = argc > 3 ? (__u32)strtoul(argv[3], NULL, 0) : 1000000;
	main_fd = load(argv[1], "xs_xdp_main", &main_obj);
	base_fd = load(argv[2], "xs_baseline_pass", &base_obj);

	printf("# BPF_PROG_TEST_RUN, 1 CPU, repeat=%u, best of 5. Program CPU cost only:\n", repeat);
	printf("# excludes NIC/driver/DMA cost; not a line-rate measurement.\n");
	printf("%-16s %6s %12s %12s %12s\n", "frame", "size", "base_ns", "xdp_main_ns", "delta_ns");
	for (size_t f = 0; f < sizeof(frames) / sizeof(frames[0]); f++) {
		for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
			struct pb b;
			double base, full;

			pb_init(&b);
			frames[f].build(&b, sizes[s]);
			base = ns_per_run(base_fd, &b, repeat);
			full = ns_per_run(main_fd, &b, repeat);
			printf("%-16s %6u %12.1f %12.1f %12.1f\n", frames[f].name, sizes[s], base,
			       full, full - base);
		}
	}
	bpf_object__close(main_obj);
	bpf_object__close(base_obj);
	return 0;
}
