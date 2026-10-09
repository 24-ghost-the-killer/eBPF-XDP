/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * cases.h - the dataplane packet corpus.
 *
 * One table drives two test suites:
 *   tests/parser/test_parser.c  runs xs_parse_packet() on the host and checks
 *                               the parse result and every extracted field;
 *   tests/bpf/test_xdp.c        runs the compiled XDP program in the kernel
 *                               via BPF_PROG_TEST_RUN and checks verdicts
 *                               and counter deltas.
 *
 * Expectation fields other than rc/strict/counters are only compared for
 * non-error outcomes (OK, NOT_IP, UNSUP_*); for malformed frames the exact
 * error code is the contract.
 *
 * `strict` is the verdict with every drop flag enabled. With the default
 * (zero) config every frame must PASS.
 */
#ifndef XS_TEST_CASES_H
#define XS_TEST_CASES_H

#include "compat.h"
#include "abi.h"
#include "parsers.h"
#include "pktbuild.h"

#define SRC4 0xC6336401u /* 198.51.100.1 */
#define DST4 0xCB00710Au /* 203.0.113.10 */

#define FIN XS_TCP_FIN
#define SYN XS_TCP_SYN
#define RST XS_TCP_RST
#define PSH XS_TCP_PSH
#define ACK XS_TCP_ACK
#define URG XS_TCP_URG

#define P 'P'
#define D 'D'

struct xs_case {
	const char *name;
	void (*build)(struct pb *b);
	int rc;
	char strict;
	/* additional counters expected to increase by exactly one packet */
	uint16_t counters[4];
	/* parsed fields (non-error outcomes only) */
	uint8_t l3, l4_proto, frag, vlan_depth, n_ext, anomalies, tcp_flags, l4_parsed;
	uint16_t sport, dport; /* host byte order */
};

#define B(fn) static void fn(struct pb *b)

/* ---------------- L2 ---------------- */
B(eth_trunc)        { pb_put(b, 10); }
B(eth_only_ipv4)    { pb_eth(b, XS_ETH_P_IPV4); }
B(arp)              { pb_eth(b, XS_ETH_P_ARP); pb_payload(b, 28); }
B(llc_8023)         { pb_eth(b, 0x0026); pb_payload(b, 46); }

/* ---------------- IPv4 valid ---------------- */
B(v4_tcp_syn)       { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v4_tcp_syn_opts)  { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 10); pb_finalize(b); }
B(v4_tcp_synack)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, DST4, SRC4, 0, 0); pb_tcp(b, 443, 40000, SYN | ACK, 5); pb_finalize(b); }
B(v4_tcp_ack_data)  { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, ACK | PSH, 5); pb_payload(b, 100); pb_finalize(b); }
B(v4_tcp_fin_ack)   { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, FIN | ACK, 5); pb_finalize(b); }
B(v4_tcp_rst)       { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, RST, 5); pb_finalize(b); }
B(v4_udp)           { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 5353, 53); pb_payload(b, 32); pb_finalize(b); }
/* UDP reply to an ephemeral port: the box's own return traffic (DNS/QUIC), so
 * DROP_UDP must NOT drop it even under the strict all-flags config. */
B(v4_udp_ephem)     { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 443, 40000); pb_payload(b, 64); pb_finalize(b); }
B(v4_icmp_echo)     { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 1, SRC4, DST4, 0, 0); pb_icmp(b, 8, 0); pb_payload(b, 56); pb_finalize(b); }
B(v4_gre)           { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 47, SRC4, DST4, 0, 0); pb_payload(b, 24); pb_finalize(b); }
B(v4_options)       { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 2, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v4_eth_padding)   { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 1, SRC4, DST4, 0, 0); pb_icmp(b, 8, 0); pb_finalize(b); pb_put(b, 18); }
B(v4_land)          { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, SRC4, 0, 0); pb_tcp(b, 139, 139, SYN, 5); pb_finalize(b); }

/* ---------------- IPv4 fragments ---------------- */
B(v4_frag_first)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0x2000); pb_udp(b, 5000, 6000); pb_payload(b, 200); pb_finalize(b);
		      pb_put16(b, b->udp_off + 4, 3000); /* datagram length > fragment: legal */ }
B(v4_frag_later)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 185); pb_payload(b, 100); pb_finalize(b); }
B(v4_frag_tiny)     { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0x2000); pb_payload(b, 8); pb_finalize(b); }

/* ---------------- IPv4 malformed ---------------- */
B(v4_trunc)         { pb_eth(b, XS_ETH_P_IPV4); pb_put(b, 10)[0] = 0x45; }
B(v4_bad_version)   { v4_tcp_syn(b); b->buf[14] = 0x55; }
B(v4_ihl_lt5)       { v4_tcp_syn(b); b->buf[14] = 0x44; }
B(v4_ihl_beyond)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_payload(b, 4); pb_finalize(b); b->buf[14] = 0x4F; }
B(v4_totlen_big)    { v4_udp(b); pb_put16(b, 14 + 2, (uint16_t)(b->len - 14 + 100)); }
B(v4_totlen_lt_ihl) { v4_udp(b); pb_put16(b, 14 + 2, 16); }

/* ---------------- TCP/UDP/ICMP malformed / anomalous ---------------- */
B(v4_tcp_trunc)     { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_payload(b, 10); pb_finalize(b); }
B(v4_tcp_doff_lt5)  { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 1, 2, SYN, 4); pb_finalize(b); }
B(v4_tcp_doff_big)  { v4_tcp_syn(b); b->buf[14 + 20 + 12] = 0xF0; /* 60-byte header in a 20-byte segment */ }
B(v4_tcp_null)      { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, 0, 5); pb_finalize(b); }
B(v4_tcp_xmas)      { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, FIN | PSH | URG, 5); pb_finalize(b); }
B(v4_tcp_synfin)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, SYN | FIN, 5); pb_finalize(b); }
B(v4_tcp_synrst)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, SYN | RST, 5); pb_finalize(b); }
B(v4_tcp_fin_only)  { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 22, FIN, 5); pb_finalize(b); }
B(v4_udp_trunc)     { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_payload(b, 4); pb_finalize(b); }
B(v4_udp_len_lt8)   { v4_udp(b); pb_put16(b, b->udp_off + 4, 4); }
B(v4_udp_len_big)   { v4_udp(b); pb_put16(b, b->udp_off + 4, (uint16_t)(b->len - b->udp_off + 10)); }
B(v4_udp_len_small) { v4_udp(b); pb_put16(b, b->udp_off + 4, 8); }
B(v4_icmp_trunc)    { pb_eth(b, XS_ETH_P_IPV4); pb_ipv4(b, 1, SRC4, DST4, 0, 0); pb_payload(b, 4); pb_finalize(b); }

/* ---------------- VLAN ---------------- */
B(vlan1_v4_tcp)     { pb_eth(b, XS_ETH_P_8021Q); pb_vlan(b, 100, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(qinq_v4_udp)      { pb_eth(b, XS_ETH_P_8021AD); pb_vlan(b, 200, XS_ETH_P_8021Q); pb_vlan(b, 100, XS_ETH_P_IPV4); pb_ipv4(b, 17, SRC4, DST4, 0, 0); pb_udp(b, 1, 2); pb_finalize(b); }
B(qinq9100_v6_udp)  { pb_eth(b, XS_ETH_P_QINQ_9100); pb_vlan(b, 7, XS_ETH_P_8021Q); pb_vlan(b, 8, XS_ETH_P_IPV6); pb_ipv6(b, 17, 1, 2); pb_udp(b, 1, 2); pb_finalize(b); }
B(vlan3_unsup)      { pb_eth(b, XS_ETH_P_8021AD); pb_vlan(b, 1, XS_ETH_P_8021Q); pb_vlan(b, 2, XS_ETH_P_8021Q); pb_vlan(b, 3, XS_ETH_P_IPV4); pb_ipv4(b, 6, SRC4, DST4, 0, 0); pb_tcp(b, 1, 2, SYN, 5); pb_finalize(b); }
B(vlan_trunc)       { pb_eth(b, XS_ETH_P_8021Q); pb_put(b, 2); }
B(vlan_arp)         { pb_eth(b, XS_ETH_P_8021Q); pb_vlan(b, 5, XS_ETH_P_ARP); pb_payload(b, 28); }

/* ---------------- IPv6 valid ---------------- */
B(v6_tcp_syn)       { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 6, 1, 2); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_udp)           { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 17, 1, 2); pb_udp(b, 5353, 53); pb_payload(b, 32); pb_finalize(b); }
B(v6_icmpv6_echo)   { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 58, 1, 2); pb_icmp(b, 128, 0); pb_payload(b, 56); pb_finalize(b); }
B(v6_padding)       { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 58, 1, 2); pb_icmp(b, 128, 0); pb_finalize(b); pb_put(b, 10); }
B(v6_land)          { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 6, 1, 1); pb_tcp(b, 80, 80, SYN, 5); pb_finalize(b); }
B(v6_esp)           { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 50, 1, 2); pb_payload(b, 40); pb_finalize(b); }
B(v6_no_next)       { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 59, 1, 2); pb_payload(b, 8); pb_finalize(b); }
B(v6_icmp4_in_v6)   { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 1, 1, 2); pb_icmp(b, 8, 0); pb_finalize(b); }

/* ---------------- IPv6 extension headers / fragments ---------------- */
B(v6_hbh_tcp)       { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 6, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_chain3_tcp)    { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 60, 0); pb_ipv6_ext(b, 43, 1); pb_ipv6_ext(b, 6, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_ah_udp)        { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 51, 1, 2); pb_ipv6_ah(b, 17, 4); pb_udp(b, 500, 500); pb_finalize(b); }
B(v6_frag_first)    { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 17, 0, 1); pb_udp(b, 5000, 6000); pb_payload(b, 64); pb_finalize(b); }
B(v6_frag_later)    { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 17, 100, 0); pb_payload(b, 64); pb_finalize(b); }
B(v6_atomic_frag)   { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 6, 0, 0); pb_tcp(b, 40000, 443, SYN, 5); pb_finalize(b); }
B(v6_frag_tiny)     { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 44, 1, 2); pb_ipv6_frag(b, 6, 0, 1); pb_payload(b, 8); pb_finalize(b); }
B(v6_ext6_udp)      { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 60, 1, 2); for (int i = 0; i < 5; i++) pb_ipv6_ext(b, 60, 0); pb_ipv6_ext(b, 17, 0); pb_udp(b, 1, 2); pb_finalize(b); }
B(v6_ext7_unsup)    { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 60, 1, 2); for (int i = 0; i < 6; i++) pb_ipv6_ext(b, 60, 0); pb_ipv6_ext(b, 17, 0); pb_udp(b, 1, 2); pb_finalize(b); }
B(v6_ext_hdr_trunc) { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_put(b, 4)[0] = 6; pb_finalize(b); }
B(v6_ext_len_frame) { uint8_t *p; pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); p = pb_put(b, 16); p[0] = 6; p[1] = 10; pb_finalize(b); }
B(v6_ext_len_plen)  { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 0, 1, 2); pb_ipv6_ext(b, 17, 1); pb_udp(b, 1, 2); pb_finalize(b); pb_put16(b, b->ip6_off + 4, 8); }

/* ---------------- IPv6 malformed ---------------- */
B(v6_trunc)         { pb_eth(b, XS_ETH_P_IPV6); pb_put(b, 20)[0] = 0x60; }
B(v6_bad_version)   { v6_udp(b); b->buf[14] = 0x40; }
B(v6_plen_big)      { v6_udp(b); pb_put16(b, b->ip6_off + 4, (uint16_t)(b->len - b->ip6_off - 40 + 100)); }
B(v6_plen_zero)     { v6_udp(b); pb_put16(b, b->ip6_off + 4, 0); }
B(v6_tcp_trunc)     { pb_eth(b, XS_ETH_P_IPV6); pb_ipv6(b, 6, 1, 2); pb_payload(b, 10); pb_finalize(b); }
B(v6_udp_len_big)   { v6_udp(b); pb_put16(b, b->udp_off + 4, 200); }

#undef B

#define V4 XS_L3_IPV4
#define V6 XS_L3_IPV6

static const struct xs_case xs_cases[] = {
	/* L2 */
	{ "eth_trunc",        eth_trunc,        XS_PARSE_ERR_ETH_TRUNC,  D },
	{ "eth_only_ipv4",    eth_only_ipv4,    XS_PARSE_ERR_IPV4_TRUNC, D },
	{ "arp",              arp,              XS_PARSE_NOT_IP, P, { XS_CNT_L3_ARP } },
	{ "llc_8023",         llc_8023,         XS_PARSE_NOT_IP, P, { XS_CNT_L3_OTHER } },

	/* IPv4 valid */
	{ "v4_tcp_syn",       v4_tcp_syn,       XS_PARSE_OK, P, { XS_CNT_L3_IPV4, XS_CNT_L4_TCP, XS_CNT_TCP_SYN },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_syn_opts",  v4_tcp_syn_opts,  XS_PARSE_OK, P, { XS_CNT_TCP_SYN },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_synack",    v4_tcp_synack,    XS_PARSE_OK, P, { XS_CNT_TCP_SYNACK },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN | ACK, .l4_parsed = 1, .sport = 443, .dport = 40000 },
	{ "v4_tcp_ack_data",  v4_tcp_ack_data,  XS_PARSE_OK, P, { XS_CNT_TCP_ACK },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = ACK | PSH, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_fin_ack",   v4_tcp_fin_ack,   XS_PARSE_OK, P, { XS_CNT_TCP_FIN },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = FIN | ACK, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_tcp_rst",       v4_tcp_rst,       XS_PARSE_OK, P, { XS_CNT_TCP_RST },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = RST, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v4_udp",           v4_udp,           XS_PARSE_OK, D, { XS_CNT_L3_IPV4, XS_CNT_L4_UDP },
	  .l3 = V4, .l4_proto = 17, .l4_parsed = 1, .sport = 5353, .dport = 53 },
	{ "v4_udp_ephem",     v4_udp_ephem,     XS_PARSE_OK, P, { XS_CNT_L3_IPV4, XS_CNT_L4_UDP },
	  .l3 = V4, .l4_proto = 17, .l4_parsed = 1, .sport = 443, .dport = 40000 },
	{ "v4_icmp_echo",     v4_icmp_echo,     XS_PARSE_OK, P, { XS_CNT_L4_ICMP },
	  .l3 = V4, .l4_proto = 1, .l4_parsed = 1 },
	{ "v4_gre",           v4_gre,           XS_PARSE_OK, P, { XS_CNT_L4_OTHER },
	  .l3 = V4, .l4_proto = 47 },
	{ "v4_options",       v4_options,       XS_PARSE_OK, P, { XS_CNT_ANOM_IPV4_OPTIONS },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443,
	  .anomalies = XS_ANOM_IPV4_OPTIONS },
	{ "v4_eth_padding",   v4_eth_padding,   XS_PARSE_OK, P, { XS_CNT_L4_ICMP },
	  .l3 = V4, .l4_proto = 1, .l4_parsed = 1 },
	{ "v4_land",          v4_land,          XS_PARSE_OK, P, { XS_CNT_ANOM_LAND },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 139, .dport = 139,
	  .anomalies = XS_ANOM_LAND },

	/* IPv4 fragments */
	{ "v4_frag_first",    v4_frag_first,    XS_PARSE_OK, D, { XS_CNT_FRAG_FIRST, XS_CNT_L4_UDP },
	  .l3 = V4, .l4_proto = 17, .frag = XS_FRAG_FIRST, .l4_parsed = 1, .sport = 5000, .dport = 6000 },
	{ "v4_frag_later",    v4_frag_later,    XS_PARSE_OK, D, { XS_CNT_FRAG_LATER, XS_CNT_L4_UDP },
	  .l3 = V4, .l4_proto = 17, .frag = XS_FRAG_LATER },
	{ "v4_frag_tiny",     v4_frag_tiny,     XS_PARSE_ERR_FRAG_TINY, D },

	/* IPv4 malformed */
	{ "v4_trunc",         v4_trunc,         XS_PARSE_ERR_IPV4_TRUNC,   D },
	{ "v4_bad_version",   v4_bad_version,   XS_PARSE_ERR_IPV4_VERSION, D },
	{ "v4_ihl_lt5",       v4_ihl_lt5,       XS_PARSE_ERR_IPV4_IHL,     D },
	{ "v4_ihl_beyond",    v4_ihl_beyond,    XS_PARSE_ERR_IPV4_TRUNC,   D },
	{ "v4_totlen_big",    v4_totlen_big,    XS_PARSE_ERR_IPV4_TOTLEN,  D },
	{ "v4_totlen_lt_ihl", v4_totlen_lt_ihl, XS_PARSE_ERR_IPV4_TOTLEN,  D },

	/* L4 malformed / anomalous */
	{ "v4_tcp_trunc",     v4_tcp_trunc,     XS_PARSE_ERR_TCP_TRUNC, D, { XS_CNT_L3_IPV4 } },
	{ "v4_tcp_doff_lt5",  v4_tcp_doff_lt5,  XS_PARSE_ERR_TCP_DOFF,  D },
	{ "v4_tcp_doff_big",  v4_tcp_doff_big,  XS_PARSE_ERR_TCP_DOFF,  D },
	{ "v4_tcp_null",      v4_tcp_null,      XS_PARSE_OK, D, { XS_CNT_ANOM_TCP_BAD_FLAGS },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = 0, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = XS_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_xmas",      v4_tcp_xmas,      XS_PARSE_OK, D, { XS_CNT_ANOM_TCP_BAD_FLAGS },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = FIN | PSH | URG, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = XS_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_synfin",    v4_tcp_synfin,    XS_PARSE_OK, D, { XS_CNT_ANOM_TCP_BAD_FLAGS },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN | FIN, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = XS_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_synrst",    v4_tcp_synrst,    XS_PARSE_OK, D, { XS_CNT_ANOM_TCP_BAD_FLAGS },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = SYN | RST, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = XS_ANOM_TCP_BAD_FLAGS },
	{ "v4_tcp_fin_only",  v4_tcp_fin_only,  XS_PARSE_OK, D, { XS_CNT_ANOM_TCP_BAD_FLAGS },
	  .l3 = V4, .l4_proto = 6, .tcp_flags = FIN, .l4_parsed = 1, .sport = 40000, .dport = 22,
	  .anomalies = XS_ANOM_TCP_BAD_FLAGS },
	{ "v4_udp_trunc",     v4_udp_trunc,     XS_PARSE_ERR_UDP_TRUNC, D },
	{ "v4_udp_len_lt8",   v4_udp_len_lt8,   XS_PARSE_ERR_UDP_LEN,   D },
	{ "v4_udp_len_big",   v4_udp_len_big,   XS_PARSE_ERR_UDP_LEN,   D },
	{ "v4_udp_len_small", v4_udp_len_small, XS_PARSE_OK, D, { XS_CNT_ANOM_UDP_LEN_MISMATCH },
	  .l3 = V4, .l4_proto = 17, .l4_parsed = 1, .sport = 5353, .dport = 53,
	  .anomalies = XS_ANOM_UDP_LEN_MISMATCH },
	{ "v4_icmp_trunc",    v4_icmp_trunc,    XS_PARSE_ERR_ICMP_TRUNC, D },

	/* VLAN */
	{ "vlan1_v4_tcp",     vlan1_v4_tcp,     XS_PARSE_OK, P, { XS_CNT_L2_VLAN1, XS_CNT_TCP_SYN },
	  .l3 = V4, .l4_proto = 6, .vlan_depth = 1, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "qinq_v4_udp",      qinq_v4_udp,      XS_PARSE_OK, D, { XS_CNT_L2_VLAN2, XS_CNT_L4_UDP },
	  .l3 = V4, .l4_proto = 17, .vlan_depth = 2, .l4_parsed = 1, .sport = 1, .dport = 2 },
	{ "qinq9100_v6_udp",  qinq9100_v6_udp,  XS_PARSE_OK, D, { XS_CNT_L2_VLAN2, XS_CNT_L3_IPV6 },
	  .l3 = V6, .l4_proto = 17, .vlan_depth = 2, .l4_parsed = 1, .sport = 1, .dport = 2 },
	{ "vlan3_unsup",      vlan3_unsup,      XS_PARSE_UNSUP_VLAN_DEPTH, P, { XS_CNT_L2_VLAN2 },
	  .vlan_depth = 2 },
	{ "vlan_trunc",       vlan_trunc,       XS_PARSE_ERR_VLAN_TRUNC, D },
	{ "vlan_arp",         vlan_arp,         XS_PARSE_NOT_IP, P, { XS_CNT_L2_VLAN1, XS_CNT_L3_ARP },
	  .vlan_depth = 1 },

	/* IPv6 valid */
	{ "v6_tcp_syn",       v6_tcp_syn,       XS_PARSE_OK, P, { XS_CNT_L3_IPV6, XS_CNT_L4_TCP, XS_CNT_TCP_SYN },
	  .l3 = V6, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_udp",           v6_udp,           XS_PARSE_OK, D, { XS_CNT_L4_UDP },
	  .l3 = V6, .l4_proto = 17, .l4_parsed = 1, .sport = 5353, .dport = 53 },
	{ "v6_icmpv6_echo",   v6_icmpv6_echo,   XS_PARSE_OK, P, { XS_CNT_L4_ICMPV6 },
	  .l3 = V6, .l4_proto = 58, .l4_parsed = 1 },
	{ "v6_padding",       v6_padding,       XS_PARSE_OK, P, { XS_CNT_L4_ICMPV6 },
	  .l3 = V6, .l4_proto = 58, .l4_parsed = 1 },
	{ "v6_land",          v6_land,          XS_PARSE_OK, P, { XS_CNT_ANOM_LAND },
	  .l3 = V6, .l4_proto = 6, .tcp_flags = SYN, .l4_parsed = 1, .sport = 80, .dport = 80,
	  .anomalies = XS_ANOM_LAND },
	{ "v6_esp",           v6_esp,           XS_PARSE_OK, P, { XS_CNT_L4_OTHER },
	  .l3 = V6, .l4_proto = 50 },
	{ "v6_no_next",       v6_no_next,       XS_PARSE_OK, P, { XS_CNT_L4_OTHER },
	  .l3 = V6, .l4_proto = 59 },
	{ "v6_icmp4_in_v6",   v6_icmp4_in_v6,   XS_PARSE_OK, P, { XS_CNT_L4_OTHER },
	  .l3 = V6, .l4_proto = 1 },

	/* IPv6 extension headers / fragments */
	{ "v6_hbh_tcp",       v6_hbh_tcp,       XS_PARSE_OK, P, { XS_CNT_IPV6_EXT, XS_CNT_TCP_SYN },
	  .l3 = V6, .l4_proto = 6, .n_ext = 1, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_chain3_tcp",    v6_chain3_tcp,    XS_PARSE_OK, P, { XS_CNT_IPV6_EXT },
	  .l3 = V6, .l4_proto = 6, .n_ext = 3, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_ah_udp",        v6_ah_udp,        XS_PARSE_OK, D, { XS_CNT_IPV6_EXT, XS_CNT_L4_UDP },
	  .l3 = V6, .l4_proto = 17, .n_ext = 1, .l4_parsed = 1, .sport = 500, .dport = 500 },
	{ "v6_frag_first",    v6_frag_first,    XS_PARSE_OK, D, { XS_CNT_FRAG_FIRST },
	  .l3 = V6, .l4_proto = 17, .n_ext = 1, .frag = XS_FRAG_FIRST, .l4_parsed = 1, .sport = 5000, .dport = 6000 },
	{ "v6_frag_later",    v6_frag_later,    XS_PARSE_OK, D, { XS_CNT_FRAG_LATER, XS_CNT_L4_UDP },
	  .l3 = V6, .l4_proto = 17, .n_ext = 1, .frag = XS_FRAG_LATER },
	{ "v6_atomic_frag",   v6_atomic_frag,   XS_PARSE_OK, P, { XS_CNT_IPV6_EXT },
	  .l3 = V6, .l4_proto = 6, .n_ext = 1, .tcp_flags = SYN, .l4_parsed = 1, .sport = 40000, .dport = 443 },
	{ "v6_frag_tiny",     v6_frag_tiny,     XS_PARSE_ERR_FRAG_TINY, D },
	{ "v6_ext6_udp",      v6_ext6_udp,      XS_PARSE_OK, D, { XS_CNT_IPV6_EXT },
	  .l3 = V6, .l4_proto = 17, .n_ext = 6, .l4_parsed = 1, .sport = 1, .dport = 2 },
	{ "v6_ext7_unsup",    v6_ext7_unsup,    XS_PARSE_UNSUP_IPV6_EXT_DEPTH, P, { XS_CNT_L3_IPV6 },
	  .l3 = V6, .l4_proto = 60, .n_ext = 6 },
	{ "v6_ext_hdr_trunc", v6_ext_hdr_trunc, XS_PARSE_ERR_IPV6_EXT_TRUNC, D },
	{ "v6_ext_len_frame", v6_ext_len_frame, XS_PARSE_ERR_IPV6_EXT_TRUNC, D },
	{ "v6_ext_len_plen",  v6_ext_len_plen,  XS_PARSE_ERR_IPV6_EXT_TRUNC, D },

	/* IPv6 malformed */
	{ "v6_trunc",         v6_trunc,         XS_PARSE_ERR_IPV6_TRUNC,   D },
	{ "v6_bad_version",   v6_bad_version,   XS_PARSE_ERR_IPV6_VERSION, D },
	{ "v6_plen_big",      v6_plen_big,      XS_PARSE_ERR_IPV6_PLEN,    D },
	{ "v6_plen_zero",     v6_plen_zero,     XS_PARSE_ERR_IPV6_PLEN,    D },
	{ "v6_tcp_trunc",     v6_tcp_trunc,     XS_PARSE_ERR_TCP_TRUNC,    D, { XS_CNT_L3_IPV6 } },
	{ "v6_udp_len_big",   v6_udp_len_big,   XS_PARSE_ERR_UDP_LEN,      D },
};

#define XS_N_CASES (sizeof(xs_cases) / sizeof(xs_cases[0]))

#undef V4
#undef V6
#undef P
#undef D

#endif /* XS_TEST_CASES_H */
