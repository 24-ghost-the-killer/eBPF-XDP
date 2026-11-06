#!/usr/bin/env python3
"""Verify the allowlist anti-spoofing (spoofed-LAN bypass fix) on the LIVE
dataplane, without sending anything on the wire.

Feeds hand-built frames to the attached XDP program with `bpftool prog run`
(BPF_PROG_RUN, in-kernel only) and checks the anom_spoofed_lan counter:

  router MAC + forged LAN IPv4 source      -> trust withheld   (+1)
  router MAC + the router's own IPv4       -> trusted          (+0)
  LAN-host MAC + LAN IPv4 source           -> trusted          (+0)
  router MAC + IPv6 link-local (RA/ND)     -> trusted          (+0)
  router MAC + IPv6 source in dst's /64    -> trust withheld   (+1)

Usage (on the appliance, after deploying + running xs-baseline):
  sudo python3 scripts/test-spoof-guard.py [iface]       # default vlan10
"""
import json, os, socket, struct, subprocess, sys, tempfile, urllib.request

IFACE = sys.argv[1] if len(sys.argv) > 1 else "vlan10"
PIN = f"/sys/fs/bpf/xdp-sentinel/{IFACE}"
PROG = f"{PIN}/xs_xdp_main"
MAP = f"{PIN}/xs_untrusted_l2"
METRICS = os.environ.get("XS_METRICS", "http://127.0.0.1:9464/metrics")


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def router():
    try:
        out = subprocess.run(["bpftool", "-j", "map", "dump", "pinned", MAP], capture_output=True, text=True, check=True).stdout
    except Exception as e:
        die(f"cannot read {MAP} ({e}); is the new dataplane deployed and are you root?")
    entries = json.loads(out)
    if not entries:
        die(f"{MAP} is empty -- add the router to /etc/xdp-sentinel/uplink.conf and run xs-baseline")
    e = entries[0]
    mac = bytes(int(b, 16) for b in e["key"][:6])
    own = bytes(int(b, 16) for b in e["value"][:4])
    return mac, socket.inet_ntoa(own)


def counter():
    txt = urllib.request.urlopen(METRICS, timeout=5).read().decode()
    for line in txt.splitlines():
        if line.startswith("xs_anomaly_packets_total{") and f'iface="{IFACE}"' in line and 'kind="spoofed_lan"' in line:
            return int(float(line.rsplit(" ", 1)[1]))
    return 0


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


TCP_ACK = struct.pack("!HHIIBBHHH", 51515, 8006, 1, 1, 5 << 4, 0x10, 65535, 0, 0)


def v4(src_mac, sip, dip):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(TCP_ACK), 1, 0, 64, 6, 0, socket.inet_aton(sip), socket.inet_aton(dip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return b"\x02\0\0\0\0\x01" + src_mac + b"\x08\x00" + ip + TCP_ACK


def v6(src_mac, sip, dip):
    ip = struct.pack("!IHBB16s16s", 6 << 28, len(TCP_ACK), 6, 64, socket.inet_pton(socket.AF_INET6, sip), socket.inet_pton(socket.AF_INET6, dip))
    return b"\x02\0\0\0\0\x01" + src_mac + b"\x86\xdd" + ip + TCP_ACK


def run(frame):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(frame)
    try:
        subprocess.run(["bpftool", "prog", "run", "pinned", PROG, "data_in", f.name, "repeat", "1"], capture_output=True, check=True)
    finally:
        os.unlink(f.name)


def lan_v6_prefix():
    """First non-link-local IPv6 network in the allowlist (the LAN /64), or None."""
    try:
        for line in open("/etc/xdp-sentinel/allowlist.conf"):
            net = line.split("#")[0].split()
            if net and ":" in net[0] and not net[0].lower().startswith("fe80"):
                return net[0].split("/")[0].rstrip(":")
    except OSError:
        pass
    return None


def main():
    if os.geteuid() != 0:
        die("run as root (bpftool prog run)")
    rmac, rip = router()
    lan_mac = b"\x02\x11\x22\x33\x44\x55"
    print(f"{IFACE}: upstream router {rmac.hex(':')} ({rip})")
    cases = [
        ("router MAC + forged LAN source 192.168.1.50", v4(rmac, "192.168.1.50", "192.168.1.173"), 1),
        (f"router MAC + router's own IP {rip}", v4(rmac, rip, "192.168.1.173"), 0 if rip != "0.0.0.0" else 1),
        ("LAN-host MAC + LAN source 192.168.1.50", v4(lan_mac, "192.168.1.50", "192.168.1.173"), 0),
        ("router MAC + IPv6 link-local fe80::1", v6(rmac, "fe80::1", "fe80::2"), 0),
    ]
    pfx = lan_v6_prefix()
    if pfx:
        cases.append((f"router MAC + IPv6 source in dst's /64 ({pfx}::/64)", v6(rmac, f"{pfx}::99", f"{pfx}::1"), 1))
    else:
        print("  (no IPv6 LAN prefix in allowlist.conf -- IPv6 /64 case skipped)")
    bad = 0
    for name, frame, want in cases:
        before = counter()
        run(frame)
        got = counter() - before
        ok = got == want
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: spoofed_lan +{got} (expected +{want})")
    print("all good" if not bad else f"{bad} case(s) failed")
    sys.exit(1 if bad else 0)


main()
