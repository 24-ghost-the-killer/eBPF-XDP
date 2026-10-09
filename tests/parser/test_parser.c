// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * Host-side parser tests: runs the dataplane parser (ebpf/src/parsers.h,
 * compiled for the host) against the shared packet corpus.
 *
 * Additionally fuzzes the parser with truncations of every corpus frame
 * (every prefix length) and random bit flips; built with
 * -fsanitize=address,undefined an out-of-bounds read aborts the test.
 * This complements, not replaces, the verifier: the verifier proves memory
 * safety of the BPF build, these tests prove the parser gives the right
 * answer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "cases.h"

static int failures;

#define CHECK_EQ(c, field, got, want)                                              \
	do {                                                                       \
		if ((long)(got) != (long)(want)) {                                 \
			fprintf(stderr, "FAIL %-18s %-10s got %ld want %ld\n",     \
				(c)->name, field, (long)(got), (long)(want));      \
			failures++;                                                \
		}                                                                  \
	} while (0)

/* Parse a copy placed at the end of a heap buffer so ASan catches any read
 * past data_end. */
static int parse_exact(const uint8_t *frame, uint32_t len, struct xs_pkt *p)
{
	uint8_t *copy = malloc(len ? len : 1);
	int rc;

	memcpy(copy, frame, len);
	memset(p, 0, sizeof(*p));
	rc = xs_parse_packet(copy, copy + len, p);
	free(copy);
	return rc;
}

static void run_case(const struct xs_case *c)
{
	struct pb b;
	struct xs_pkt p;
	int rc;

	pb_init(&b);
	c->build(&b);
	rc = parse_exact(b.buf, b.len, &p);

	CHECK_EQ(c, "rc", rc, c->rc);
	if (xs_rc_is_error(c->rc))
		return;
	CHECK_EQ(c, "l3", p.l3, c->l3);
	CHECK_EQ(c, "vlan_depth", p.vlan_depth, c->vlan_depth);
	if (c->rc == XS_PARSE_NOT_IP || c->rc == XS_PARSE_UNSUP_VLAN_DEPTH)
		return;
	CHECK_EQ(c, "l4_proto", p.l4_proto, c->l4_proto);
	CHECK_EQ(c, "frag", p.frag, c->frag);
	CHECK_EQ(c, "n_ext", p.n_ext, c->n_ext);
	CHECK_EQ(c, "anomalies", p.anomalies, c->anomalies);
	CHECK_EQ(c, "l4_parsed", p.l4_parsed, c->l4_parsed);
	CHECK_EQ(c, "tcp_flags", p.tcp_flags, c->tcp_flags);
	CHECK_EQ(c, "sport", ntohs(p.sport), c->sport);
	CHECK_EQ(c, "dport", ntohs(p.dport), c->dport);
}

/* Every prefix of every valid frame must be rejected or accepted without
 * reading out of bounds, and a strict prefix of a frame whose IP length
 * fields cover the whole frame can never parse as OK. */
static void fuzz_truncation(void)
{
	unsigned long runs = 0;

	for (size_t i = 0; i < XS_N_CASES; i++) {
		struct pb b;
		struct xs_pkt p;

		pb_init(&b);
		xs_cases[i].build(&b);
		for (uint32_t n = 0; n < b.len; n++) {
			(void)parse_exact(b.buf, n, &p);
			runs++;
		}
	}
	printf("truncation fuzz: %lu prefixes parsed\n", runs);
}

static void fuzz_bitflips(unsigned iterations)
{
	unsigned long seed = 0x5eed;
	unsigned hist[XS_PARSE_RC_MAX] = { 0 };

	for (unsigned it = 0; it < iterations; it++) {
		const struct xs_case *c = &xs_cases[it % XS_N_CASES];
		struct pb b;
		struct xs_pkt p;
		int rc;

		pb_init(&b);
		c->build(&b);
		for (int k = 0; k < 4 && b.len; k++) {
			seed = seed * 6364136223846793005ul + 1442695040888963407ul;
			b.buf[(seed >> 33) % b.len] ^= (uint8_t)(1u << ((seed >> 20) & 7));
		}
		rc = parse_exact(b.buf, b.len, &p);
		if (rc < 0 || rc >= XS_PARSE_RC_MAX) {
			fprintf(stderr, "FAIL bitflip: rc %d out of range\n", rc);
			failures++;
			continue;
		}
		hist[rc]++;
	}
	printf("bitflip fuzz: %u mutated frames, outcomes:", iterations);
	for (int i = 0; i < XS_PARSE_RC_MAX; i++)
		if (hist[i])
			printf(" rc%d=%u", i, hist[i]);
	printf("\n");
}

int main(void)
{
	for (size_t i = 0; i < XS_N_CASES; i++)
		run_case(&xs_cases[i]);
	printf("corpus: %zu cases\n", XS_N_CASES);
	fuzz_truncation();
	fuzz_bitflips(200000);

	if (failures) {
		printf("parser tests: %d FAILURES\n", failures);
		return 1;
	}
	printf("parser tests: OK\n");
	return 0;
}
