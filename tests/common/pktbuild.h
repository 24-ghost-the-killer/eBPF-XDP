/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * pktbuild.h - minimal frame builder for dataplane tests.
 *
 * Builds frames byte by byte so tests can express exactly the malformed
 * shapes they need. Length fields (IPv4 tot_len, IPv6 payload_len, UDP len)
 * are filled by pb_finalize() from the recorded header offsets; a test that
 * wants a broken length overwrites it afterwards with pb_put16().
 *
 * Header-only and dependency-free so both the host parser tests and the
 * libbpf harness can use it.
 */
#ifndef XS_TEST_PKTBUILD_H
#define XS_TEST_PKTBUILD_H

#include <stdint.h>
#include <string.h>
#include <assert.h>

#define PB_MAX 4096

struct pb {
	uint8_t  buf[PB_MAX];
	uint32_t len;
	int32_t  ip4_off;  /* offset of the (last) IPv4 header, -1 if none */
	int32_t  ip6_off;  /* offset of the (last) IPv6 header, -1 if none */
	int32_t  udp_off;  /* offset of the UDP header, -1 if none */
};

static inline void pb_init(struct pb *b)
{
	memset(b, 0, sizeof(*b));
	b->ip4_off = b->ip6_off = b->udp_off = -1;
}

static inline uint8_t *pb_put(struct pb *b, uint32_t n)
{
	uint8_t *p;

	assert(b->len + n <= PB_MAX);
	p = b->buf + b->len;
	memset(p, 0, n);
	b->len += n;
	return p;
}

static inline void pb_put16(struct pb *b, uint32_t off, uint16_t v)
{
	b->buf[off] = v >> 8;
	b->buf[off + 1] = v & 0xFF;
}

static inline void pb_put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

/* Ethernet header; `proto` is the ethertype or the outer VLAN TPID. */
static inline void pb_eth(struct pb *b, uint16_t proto)
{
	static const uint8_t dst[6] = { 0x02, 0, 0, 0, 0, 0x02 };
	static const uint8_t src[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	uint8_t *p = pb_put(b, 14);

	memcpy(p, dst, 6);
	memcpy(p + 6, src, 6);
	p[12] = proto >> 8;
	p[13] = proto & 0xFF;
}

/* One VLAN tag: TCI (PCP 0) + the next ethertype/TPID. */
static inline void pb_vlan(struct pb *b, uint16_t vid, uint16_t next)
{
	uint8_t *p = pb_put(b, 4);

	p[0] = (vid >> 8) & 0x0F;
	p[1] = vid & 0xFF;
	p[2] = next >> 8;
	p[3] = next & 0xFF;
}

/* IPv4 header with `opt_words` 32-bit option words (NOP-filled). */
static inline void pb_ipv4(struct pb *b, uint8_t proto, uint32_t saddr, uint32_t daddr,
			   uint8_t opt_words, uint16_t frag_off)
{
	uint32_t hlen = 20 + 4u * opt_words;
	uint8_t *p;

	b->ip4_off = b->len;
	p = pb_put(b, hlen);
	p[0] = 0x40 | (uint8_t)(hlen / 4);
	p[6] = frag_off >> 8;
	p[7] = frag_off & 0xFF;
	p[8] = 64;
	p[9] = proto;
	pb_put32(p + 12, saddr);
	pb_put32(p + 16, daddr);
	memset(p + 20, 0x01, hlen - 20); /* IPOPT_NOP */
}

/* IPv6 header; addresses are ::<lo> style (low 32 bits given). */
static inline void pb_ipv6(struct pb *b, uint8_t nexthdr, uint32_t saddr_lo, uint32_t daddr_lo)
{
	uint8_t *p;

	b->ip6_off = b->len;
	p = pb_put(b, 40);
	p[0] = 0x60;
	p[6] = nexthdr;
	p[7] = 64;
	p[8] = 0x20; p[9] = 0x01; p[10] = 0x0d; p[11] = 0xb8; /* 2001:db8:: */
	pb_put32(p + 20, saddr_lo);
	p[24] = 0x20; p[25] = 0x01; p[26] = 0x0d; p[27] = 0xb8;
	pb_put32(p + 36, daddr_lo);
}

/* Generic extension header (HBH / routing / dst opts): (units+1)*8 bytes. */
static inline void pb_ipv6_ext(struct pb *b, uint8_t nexthdr, uint8_t units)
{
	uint8_t *p = pb_put(b, (units + 1u) * 8);

	p[0] = nexthdr;
	p[1] = units;
	p[2] = 0x01; /* PadN option, keeps HBH/DST syntactically plausible */
	p[3] = (uint8_t)((units + 1u) * 8 - 4);
}

/* Authentication header: (units+2)*4 bytes. */
static inline void pb_ipv6_ah(struct pb *b, uint8_t nexthdr, uint8_t units)
{
	uint8_t *p = pb_put(b, (units + 2u) * 4);

	p[0] = nexthdr;
	p[1] = units;
}

/* Fragment header; offset in 8-octet units. */
static inline void pb_ipv6_frag(struct pb *b, uint8_t nexthdr, uint16_t offset, int more)
{
	uint8_t *p = pb_put(b, 8);
	uint16_t fo = (uint16_t)(offset << 3) | (more ? 1 : 0);

	p[0] = nexthdr;
	p[2] = fo >> 8;
	p[3] = fo & 0xFF;
	pb_put32(p + 4, 0x12345678);
}

static inline void pb_tcp(struct pb *b, uint16_t sport, uint16_t dport, uint8_t flags,
			  uint8_t doff_words)
{
	uint32_t hlen = doff_words >= 5 ? doff_words * 4u : 20;
	uint8_t *p = pb_put(b, hlen);

	p[0] = sport >> 8; p[1] = sport & 0xFF;
	p[2] = dport >> 8; p[3] = dport & 0xFF;
	p[12] = (uint8_t)(doff_words << 4);
	p[13] = flags;
	p[14] = 0xFF; p[15] = 0xFF; /* window */
}

static inline void pb_udp(struct pb *b, uint16_t sport, uint16_t dport)
{
	uint8_t *p;

	b->udp_off = b->len;
	p = pb_put(b, 8);
	p[0] = sport >> 8; p[1] = sport & 0xFF;
	p[2] = dport >> 8; p[3] = dport & 0xFF;
}

static inline void pb_icmp(struct pb *b, uint8_t type, uint8_t code)
{
	uint8_t *p = pb_put(b, 8);

	p[0] = type;
	p[1] = code;
}

static inline void pb_payload(struct pb *b, uint32_t n)
{
	uint8_t *p = pb_put(b, n);

	for (uint32_t i = 0; i < n; i++)
		p[i] = (uint8_t)i;
}

/* Fill IPv4 tot_len, IPv6 payload_len and UDP len from the current length. */
static inline void pb_finalize(struct pb *b)
{
	if (b->ip4_off >= 0)
		pb_put16(b, b->ip4_off + 2, (uint16_t)(b->len - b->ip4_off));
	if (b->ip6_off >= 0)
		pb_put16(b, b->ip6_off + 4, (uint16_t)(b->len - b->ip6_off - 40));
	if (b->udp_off >= 0)
		pb_put16(b, b->udp_off + 4, (uint16_t)(b->len - b->udp_off));
}

#endif /* XS_TEST_PKTBUILD_H */
