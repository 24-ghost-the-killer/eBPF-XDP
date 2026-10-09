/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * compat.h - build-environment shim.
 *
 * The dataplane headers (abi.h, parsers.h) are compiled in two environments:
 *
 *   1. clang -target bpf   (__bpf__ defined): the real XDP object. Kernel types
 *      come from the BTF-generated vmlinux.h, helpers from libbpf.
 *   2. a normal host C compiler: parser unit tests (tests/parser) and the
 *      libbpf test harness (tests/bpf). This lets the exact same parser code be
 *      exercised with malformed input on any developer machine, without root.
 *
 * Nothing in parsers.h may depend on BPF helpers; it only uses fixed-width
 * types and byte-order conversion.
 */
#ifndef XS_COMPAT_H
#define XS_COMPAT_H

#if defined(__bpf__)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#else /* host build */

#include <stdint.h>
#include <stddef.h>

#if defined(__linux__)
#include <linux/types.h>
#else
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint16_t __sum16;
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "host test build assumes a little-endian host"
#endif
#define bpf_htons(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) ((__be32)__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))

#endif /* __bpf__ */

/*
 * Hide a value from the optimiser. Used to force clang to emit range masks
 * that are no-ops at runtime but that the verifier needs; without the
 * barrier clang proves the mask redundant and deletes it.
 */
#define xs_opaque(x) ({						\
	__typeof__(x) ___v = (x);				\
	asm volatile("" : "+r"(___v));				\
	___v;							\
})

/*
 * Byte-swap a 16-bit wire value and re-establish its [0, 0xFFFF] bound.
 * The verifier (at least through 6.12) does not propagate value ranges
 * through the BPF_END (bswap) instruction: the result of bpf_ntohs() is an
 * unbounded scalar, and adding it to a packet pointer is rejected
 * ("makes pkt pointer be out of bounds").
 */
#define xs_ntohs_bounded(x) (xs_opaque((__u32)bpf_ntohs(x)) & 0xFFFF)

#endif /* XS_COMPAT_H */
