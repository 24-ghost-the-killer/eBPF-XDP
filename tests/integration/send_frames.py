#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Send crafted Ethernet frames through an AF_PACKET socket.

Used by veth_smoke.sh to put malformed / anomalous frames on the wire that
no normal socket API would emit.

    send_frames.py <iface> <dst_mac> <kind> <count>

kinds: xmas, tcp_trunc, syn, udp53, udp_len_bad, ipv6_frag_later
"""
import socket
import struct
import sys

SRC = bytes([10, 99, 0, 2])
DST = bytes([10, 99, 0, 1])


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(proto: int, payload: bytes, tot_len: int | None = None) -> bytes:
    tl = tot_len if tot_len is not None else 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tl, 0x1234, 0, 64, proto, 0, SRC, DST)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(flags: int) -> bytes:
    return struct.pack("!HHIIBBHHH", 40000, 22, 1, 0, 5 << 4, flags, 65535, 0, 0)


def frame(dst_mac: bytes, src_mac: bytes, ethertype: int, l3: bytes) -> bytes:
    f = dst_mac + src_mac + struct.pack("!H", ethertype) + l3
    return f + b"\0" * max(0, 60 - len(f))  # Ethernet minimum size


def build(kind: str, dst_mac: bytes, src_mac: bytes) -> bytes:
    if kind == "xmas":
        return frame(dst_mac, src_mac, 0x0800, ipv4(6, tcp(0x29)))
    if kind == "syn":
        return frame(dst_mac, src_mac, 0x0800, ipv4(6, tcp(0x02)))
    if kind == "udp53":
        udp = struct.pack("!HHHH", 5353, 53, 16, 0) + b"dns-test"
        return frame(dst_mac, src_mac, 0x0800, ipv4(17, udp))
    if kind == "tcp_trunc":  # IP payload of 10 bytes cannot hold a TCP header
        return frame(dst_mac, src_mac, 0x0800, ipv4(6, b"\x9c\x40\x00\x16" + b"\0" * 6))
    if kind == "udp_len_bad":  # UDP length claims more than the IP payload
        udp = struct.pack("!HHHH", 5353, 53, 200, 0) + b"x" * 12
        return frame(dst_mac, src_mac, 0x0800, ipv4(17, udp))
    if kind == "ipv6_frag_later":
        fh = struct.pack("!BBHI", 17, 0, (100 << 3), 0xABCD)
        payload = fh + b"y" * 32
        ip6 = struct.pack("!IHBB16s16s", 6 << 28, len(payload), 44, 64,
                          bytes.fromhex("fd00" + "00" * 13 + "02"),
                          bytes.fromhex("fd00" + "00" * 13 + "01"))
        return frame(dst_mac, src_mac, 0x86DD, ip6 + payload)
    raise SystemExit(f"unknown kind {kind}")


def main() -> None:
    iface, dst, kind, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    dst_mac = bytes.fromhex(dst.replace(":", ""))
    with open(f"/sys/class/net/{iface}/address") as f:
        src_mac = bytes.fromhex(f.read().strip().replace(":", ""))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    pkt = build(kind, dst_mac, src_mac)
    for _ in range(count):
        s.send(pkt)
    s.close()


if __name__ == "__main__":
    main()
