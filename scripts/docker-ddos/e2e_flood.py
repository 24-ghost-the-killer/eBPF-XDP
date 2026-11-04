#!/usr/bin/env python3
"""Blast ONE attack vector at max rate for N seconds out an iface (raw AF_PACKET),
so the risk engine detects a real flood and escalates (arming global_rl/ratelimit).

    e2e_flood.py <out_iface> [family=udp_flood] [seconds=14]
"""
import os, sys, socket, time, random

PENTEST = os.environ.get("XS_PENTEST_DIR") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pentest"))
_saved = sys.argv
sys.argv = [sys.argv[0]]
sys.path.insert(0, PENTEST)
import xdp_pentest as xp          # noqa: E402
sys.argv = _saved

IFACE = sys.argv[1] if len(sys.argv) > 1 else "veth-xs1"
FAM = sys.argv[2] if len(sys.argv) > 2 else "udp_flood"
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 14.0
VICTIM = xp.VICTIM

def rand_src():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((IFACE, 0))
    # Pre-build a ring of frames with varied spoofed sources (a random-source flood)
    # so the aggregate cap -- not per-source limiting -- is what must shed it.
    ring = [xp._build(FAM, rand_src(), VICTIM) for _ in range(512)]
    end = time.time() + DUR
    sent = 0; i = 0
    while time.time() < end:
        try:
            s.send(ring[i & 511]); sent += 1; i += 1
        except BlockingIOError:
            pass
    s.close()
    print(f"flood {FAM}: sent {sent} frames in {DUR:.0f}s (~{int(sent/DUR)} pps) out {IFACE}")

if __name__ == "__main__":
    main()
