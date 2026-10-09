#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Multi-process traffic generator for stress-testing the xdp-sentinel
dataplane from a client machine.

Throughput techniques:
  * multiple worker processes (sidesteps Python's GIL);
  * connected UDP sockets with send() (no per-packet address resolution);
  * maxed SO_SNDBUF so the kernel queue rarely stalls the sender;
  * multi-port spray - each worker fans out over several destination ports,
    exercising more of the parser and any per-port logic at once;
  * on Linux, sendmmsg() batching - one syscall transmits a whole batch of
    packets, which is what lets a decent wired Linux host reach millions of
    pps. On macOS/other, falls back to a tight send() loop.

SUPER HAMMER MODE (--super, or `hammer.sh --super`): auto-tunes everything to
its most aggressive setting to oversend as much data as the source and path
will carry - workers = 4x CPUs, batch = 4096, ~near-MTU payloads, and a spray
across the common service ports. Pass --size 65507 to send giant fragmented
datagrams (max bandwidth per syscall; also hammers the fragment path).

Reality check: you only hit millions of pps / many Gbit/s from a Linux box on
a real wired NIC on the same LAN as the target. A Mac over Wi-Fi/Twingate is
capped far below that by the OS and the tunnel, and (for THIS server) traffic
to 10.55.12.50 over Twingate is decapsulated locally and never crosses wlo1's
XDP hook - run the flood from a host on the 10.55.12.0/24 LAN, or use pktgen
(benchmarks/xdp/pktgen_tx.sh) / TRex on wired Linux for line rate.

  ./flood.py udp 10.55.12.50 -p 80 -d 10 -w 8            # UDP flood
  ./flood.py udp 10.55.12.50 --ports 80,443,53 -d 10     # multi-port spray
  ./flood.py super 10.55.12.50 -d 15                      # SUPER HAMMER
  ./flood.py super 10.55.12.50 -d 15 --size 65507         # max-bandwidth mode
  ./flood.py tcp-connect 10.55.12.50 -p 80 -d 10 -w 16    # SYN-path flood
"""
import argparse
import ctypes
import ctypes.util
import errno
import multiprocessing as mp
import os
import socket
import sys
import time

# ---- sendmmsg() via ctypes (Linux) ---------------------------------------

_libc = None
if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    except OSError:
        _libc = None


class _iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class _msghdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint),
        ("msg_iov", ctypes.POINTER(_iovec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int),
    ]


class _mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", _msghdr), ("msg_len", ctypes.c_uint)]


def _sendmmsg_batch(fd, payload, batch):
    """Prepare a reusable batch of `batch` messages all sending `payload` on a
    connected socket, and return a closure that fires it once."""
    buf = ctypes.create_string_buffer(payload, len(payload))
    iov = _iovec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    msgs = (_mmsghdr * batch)()
    for i in range(batch):
        msgs[i].msg_hdr.msg_iov = ctypes.pointer(iov)
        msgs[i].msg_hdr.msg_iovlen = 1
    sendmmsg = _libc.sendmmsg

    def fire():
        return sendmmsg(fd, msgs, batch, 0)

    return fire


def _max_sndbuf(s):
    """Push SO_SNDBUF as high as the kernel allows, so a full send queue stalls
    the flood as little as possible. The kernel silently caps it."""
    for want in (256 << 20, 128 << 20, 64 << 20, 32 << 20, 16 << 20, 8 << 20):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, want)
            return
        except OSError:
            continue


# A full UDP send queue reports these; on macOS/BSD they fire even on a
# blocking socket (the kernel refuses to park a datagram sender), so they are
# normal backpressure - "the path is saturated" - not errors. We back off
# briefly instead of spinning the CPU on millions of instant retries.
_BACKPRESSURE = {errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK}


def udp_worker(args, stop_at, q):
    payload = os.urandom(max(1, args.size))
    plen = len(payload)
    # One connected socket per destination port; each fires round-robin so a
    # single worker sprays every port in `args.ports`.
    fires, socks = [], []
    for port in args.ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _max_sndbuf(s)
        s.connect((args.target, port))
        socks.append(s)
        fires.append(_sendmmsg_batch(s.fileno(), payload, args.batch)
                     if (_libc is not None and args.batch > 1) else None)

    # Keep the time.time() overhead negligible without wildly overrunning the
    # requested duration: fewer inner reps when the per-fire cost is larger.
    reps = max(1, 64 // len(args.ports))
    sleep = time.sleep
    sent = errs = byts = full = 0
    toobig = False
    while time.time() < stop_at and not toobig:
        for _ in range(reps):
            for i, fire in enumerate(fires):
                if fire is not None:
                    n = fire()
                    if n >= 0:
                        sent += n
                        byts += n * plen
                        continue
                    e = ctypes.get_errno()
                else:
                    try:
                        socks[i].send(payload)
                        sent += 1
                        byts += plen
                        continue
                    except OSError as ex:
                        e = ex.errno
                if e == errno.EMSGSIZE:
                    toobig = True
                    break
                if e in _BACKPRESSURE:
                    full += 1
                    sleep(0.0005)  # let the queue drain; this is the pacing
                else:
                    errs += 1
            if toobig:
                break
    q.put((sent, errs, byts, toobig, full))


def tcp_connect_worker(args, stop_at, q):
    sent = errs = 0
    ports = args.ports
    i = 0
    while time.time() < stop_at:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout)
        try:
            s.connect((args.target, ports[i % len(ports)]))
        except OSError:
            errs += 1
        i += 1
        sent += 1
        s.close()
    q.put((sent, errs, 0, False, 0))


# Common service ports the super/spray modes fan out over by default.
SUPER_PORTS = "80,443,8080,8443,53,123,3001,22"
MAX_UDP_PAYLOAD = 65507  # largest single UDP datagram (gets IP-fragmented)


def _parse_ports(spec):
    ports = []
    for tok in spec.split(","):
        tok = tok.strip()
        if tok:
            ports.append(int(tok))
    if not ports:
        raise SystemExit("no valid ports in --ports")
    return ports


def main():
    p = argparse.ArgumentParser(description="multi-process stress generator")
    p.add_argument("vector", choices=["udp", "tcp-connect", "super"],
                   help="super = max-aggression UDP preset (see --super)")
    p.add_argument("target")
    p.add_argument("-p", "--port", type=int, default=80,
                   help="single destination port (ignored if --ports is given)")
    p.add_argument("--ports", help="comma list of destination ports to spray")
    p.add_argument("-d", "--duration", type=float, default=10.0)
    p.add_argument("-w", "--workers", type=int, default=None)
    p.add_argument("--size", type=int, default=64,
                   help=f"UDP payload bytes (max {MAX_UDP_PAYLOAD}; >1472 fragments)")
    p.add_argument("--batch", type=int, default=1024,
                   help="sendmmsg batch size on Linux (1 = plain send loop)")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--super", action="store_true",
                   help="auto-tune for maximum volume (implied by the 'super' vector)")
    args = p.parse_args()

    given = lambda flag: any(a == flag or a.startswith(flag + "=") for a in sys.argv)
    cpus = os.cpu_count() or 4
    super_mode = args.super or args.vector == "super"
    if super_mode:
        # Aggressive defaults, only where the user did not override them.
        if args.vector == "super":
            args.vector = "udp"
        if args.workers is None:
            args.workers = cpus * 4
        if not given("--batch"):
            args.batch = 4096
        if not given("--size"):
            args.size = 1472  # fill a 1500-byte MTU without fragmenting
        if not args.ports:
            args.ports = SUPER_PORTS
    if args.workers is None:
        args.workers = cpus

    args.size = max(1, min(args.size, MAX_UDP_PAYLOAD))
    args.ports = _parse_ports(args.ports) if args.ports else [args.port]

    worker = udp_worker if args.vector == "udp" else tcp_connect_worker
    accel = ("sendmmsg x%d" % args.batch
             if (_libc and args.vector == "udp" and args.batch > 1) else "send() loop")
    frag = "  [FRAGMENTED datagrams]" if args.size > 1472 else ""
    q = mp.Queue()
    stop_at = time.time() + args.duration
    procs = [mp.Process(target=worker, args=(args, stop_at, q)) for _ in range(args.workers)]

    tag = "SUPER HAMMER" if super_mode else args.vector
    print(f"stress: {tag} -> {args.target} ports {args.ports}, {args.workers} workers, "
          f"{args.duration:g}s, {args.size}B payload, {accel}{frag}", file=sys.stderr)
    t0 = time.time()
    for pr in procs:
        pr.start()
    totals = [q.get() for _ in procs]
    for pr in procs:
        pr.join()
    dt = time.time() - t0

    sent = sum(t[0] for t in totals)
    errs = sum(t[1] for t in totals)
    byts = sum(t[2] for t in totals)
    toobig = any(t[3] for t in totals)
    full = sum(t[4] for t in totals)
    # Approximate wire bytes: payload + 8 (UDP) + 20 (IP) + 14 (Eth), fragmented
    # datagrams add another 20-byte IP header per ~1480-byte fragment.
    frags = max(1, -(-args.size // 1480)) if args.vector == "udp" else 1
    wire = byts + sent * (8 + 20 * frags + 14) if args.vector == "udp" else sent * 60
    print(f"sent      : {sent:,} packets")
    print(f"errors    : {errs:,}")
    if full:
        print(f"backpress.: {full:,} (queue full - normal; path is saturated)")
    print(f"appdata   : {byts / 1e6:,.1f} MB payload")
    print(f"duration  : {dt:.2f}s")
    print(f"rate      : {sent / dt:,.0f} pps")
    print(f"throughput: {wire * 8 / dt / 1e9:,.2f} Gbit/s  ({wire / 1e6 / dt:,.0f} MB/s on the wire, approx)")
    if toobig:
        cur = "unknown"
        try:
            import subprocess
            cur = subprocess.check_output(["sysctl", "-n", "net.inet.udp.maxdgram"],
                                          text=True).strip()
        except Exception:
            pass
        print(f"\nNOTE: --size {args.size} exceeds this OS's max UDP datagram "
              f"(net.inet.udp.maxdgram = {cur}); those sends failed with EMSGSIZE.\n"
              f"      Raise it (root):  sudo sysctl -w net.inet.udp.maxdgram={args.size}\n"
              f"      or just drop --size (super mode's 1472B default maxes pps).")
    elif full > sent:
        print(f"\nNOTE: the send queue was full most of the time - {sent/dt:,.0f} pps "
              f"is about all this path (Wi-Fi/tunnel) will carry. Flood from a wired\n"
              f"      host on the target's LAN, or use pktgen, to push real volume.")


if __name__ == "__main__":
    main()
