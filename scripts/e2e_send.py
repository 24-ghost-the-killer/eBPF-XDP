#!/usr/bin/env python3
"""Transmit REAL attack frames out a veth so the XDP program on the peer RX-processes
them. Reuses the pentest's own packet builders. Run as root on the appliance.

    e2e_send.py <out_iface> [pkts_per_vector]
"""
import os, sys, socket, time

PENTEST = os.environ.get("XS_PENTEST_DIR") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pentest"))
sys.argv_backup = sys.argv[:]
sys.path.insert(0, PENTEST)
_saved = sys.argv
sys.argv = [sys.argv[0]]          # keep the pentest module's argparse quiet on import
import xdp_pentest as xp          # noqa: E402
sys.argv = _saved

IFACE = sys.argv[1] if len(sys.argv) > 1 else "veth-xs1"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 40

# A mix chosen so the capture clearly shows SELECTIVE dropping under the armed flags
# (drop_udp, drop_bad_tcp_flags, drop_fragments, drop_spoofed, drop_malformed):
#   expect DROP : udp_flood, tcp_bad_flags, null_flood, xmas_flood, frag_flood, land_attack
#   expect PASS : benign_tcp (ACK), syn_flood (no drop_syn armed), ack_flood
PLAN = [
    ("udp_flood",     "DROP  (drop_udp)"),
    ("syn_flood",     "PASS  (no drop_syn)"),
    ("benign_tcp",    "PASS  (plain ACK)"),
    ("ack_flood",     "PASS  (no drop_ack)"),
    ("tcp_bad_flags", "DROP  (drop_bad_tcp_flags)"),
    ("null_flood",    "DROP  (drop_bad_tcp_flags)"),
    ("xmas_flood",    "DROP  (drop_bad_tcp_flags)"),
    ("frag_flood",    "DROP  (drop_fragments)"),
    ("land_attack",   "DROP  (drop_spoofed: src==dst)"),
]

VICTIM = xp.VICTIM

def rand_src():
    import random
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((IFACE, 0))
    print(f"sending {N} frames/vector out {IFACE} -> peer (XDP under test)")
    totals = {}
    for fam, expect in PLAN:
        sent = 0
        for _ in range(N):
            src = VICTIM if fam == "land_attack" else rand_src()
            try:
                frame = xp._build(fam, src, VICTIM)
            except Exception as e:                       # noqa: BLE001
                print(f"  {fam}: build error {e}"); break
            s.send(frame)
            sent += 1
            time.sleep(0.001)                            # ~1 kpps, easy on tcpdump
        totals[fam] = sent
        print(f"  {fam:14s} x{sent:<4d} expect {expect}")
    s.close()
    print(f"TOTAL sent: {sum(totals.values())}")

if __name__ == "__main__":
    main()
