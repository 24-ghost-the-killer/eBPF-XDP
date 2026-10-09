#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Distributed stress-test CONTROLLER for xdp-sentinel.

  *** AUTHORIZED TESTING ONLY ***
  Only aim this at hosts you own or have explicit written permission to test.
  It coordinates a synchronized flood from every connected agent at once, which
  is indistinguishable from a DDoS to the target's network. Use it on your own
  lab/LAN.

You run this on one machine (the controller). On each of your other computers
you run `swarm_agent.py <controller-ip>:9000`; they connect here and wait.
Then from the prompt below you launch a synchronized attack across all of them.

  python3 swarm_control.py                 # listen on 0.0.0.0:9000
  python3 swarm_control.py --port 9000

Commands at the prompt:
  list                                  show connected bots
  attack <target> [options]             synchronized flood from all bots
      --vector udp|tcp-connect|super    (default super)
      --ports 80,443,53                 destination ports
      -d, --duration <s>                (default 15)
      --size <bytes>                    UDP payload (default per-vector)
  hammer <target> [-d 20]               MULTI-VECTOR: each bot a different attack
                                        (UDP spray + web-port UDP + reflection
                                        ports + TCP SYN) to exercise every layer
  quit
"""
from __future__ import annotations

import argparse
import json
import shlex
import socket
import threading
import time

AGENTS: dict[str, dict] = {}          # id -> {conn, name, cpus, addr}
RESULTS: dict[str, list] = {}         # attack_id -> [result,...]
LOCK = threading.Lock()


def send(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def handle_agent(conn, addr):
    aid = f"{addr[0]}:{addr[1]}"
    name = addr[0]
    try:
        f = conn.makefile("r")
        for line in f:
            msg = json.loads(line)
            t = msg.get("type")
            if t == "hello":
                name = msg.get("name", addr[0])
                with LOCK:
                    AGENTS[aid] = {"conn": conn, "name": name, "cpus": msg.get("cpus", 1), "addr": addr}
                print(f"\n[+] agent joined: {name} ({addr[0]}, {msg.get('cpus', 1)} cpus) — "
                      f"{len(AGENTS)} total\n> ", end="", flush=True)
            elif t == "result":
                with LOCK:
                    RESULTS.setdefault(msg["id"], []).append({**msg, "name": name})
            elif t == "refused":
                print(f"\n[!] {name} REFUSED: {msg.get('reason')}\n> ", end="", flush=True)
    except Exception:
        pass
    finally:
        with LOCK:
            AGENTS.pop(aid, None)
        print(f"\n[-] agent left: {name} — {len(AGENTS)} total\n> ", end="", flush=True)


def accept_loop(sock):
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            return
        threading.Thread(target=handle_agent, args=(conn, addr), daemon=True).start()


def cmd_list():
    with LOCK:
        agents = list(AGENTS.values())
    if not agents:
        print("  (no agents connected — run swarm_agent.py on your other machines)")
    for a in agents:
        print(f"  {a['name']:<20} {a['addr'][0]:<16} {a['cpus']} cpus")
    print(f"  {len(agents)} agent(s)")


def cmd_attack(argv):
    p = argparse.ArgumentParser(prog="attack", add_help=False)
    p.add_argument("target")
    p.add_argument("--vector", default="super", choices=["udp", "tcp-connect", "super"])
    p.add_argument("--ports", default=None)
    p.add_argument("-d", "--duration", type=float, default=15.0)
    p.add_argument("--size", type=int, default=None)
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return

    with LOCK:
        agents = list(AGENTS.values())
    if not agents:
        print("  no agents connected.")
        return

    aid = str(time.time())
    start_at = time.time() + 3.0  # synchronized start, 3s from now
    order = {
        "type": "attack", "id": aid, "target": a.target, "vector": a.vector,
        "ports": a.ports, "duration": a.duration, "size": a.size, "start_at": start_at,
    }
    with LOCK:
        RESULTS[aid] = []
    sent_to = 0
    for ag in agents:
        try:
            send(ag["conn"], order)
            sent_to += 1
        except Exception:
            pass
    print(f"  launched on {sent_to} bot(s): {a.vector} -> {a.target}, {a.duration:g}s, "
          f"synchronized start in 3s...")
    _collect(aid, sent_to, start_at, a.duration)


def _collect(aid, expect, start_at, duration):
    """Wait for results and print the aggregate."""
    deadline = start_at + duration + 20
    while time.time() < deadline:
        with LOCK:
            got = len(RESULTS.get(aid, []))
        if got >= expect:
            break
        time.sleep(0.5)
    with LOCK:
        res = RESULTS.get(aid, [])
    if not res:
        print("  no results reported yet.")
        return
    tot_pps = sum(r.get("pps", 0) for r in res)
    tot_gbit = sum(r.get("gbit", 0) for r in res)
    tot_sent = sum(r.get("sent", 0) for r in res)
    tot_mb = sum(r.get("mb", 0) for r in res)
    print(f"\n  === aggregate from {len(res)} bot(s) ===")
    for r in sorted(res, key=lambda r: -r.get("pps", 0)):
        print(f"    {r['name']:<20} {r.get('pps', 0):>12,.0f} pps  {r.get('gbit', 0):>6.2f} Gbit/s"
              + ("  " + r["note"] if r.get("note") else ""))
    print(f"    {'TOTAL':<20} {tot_pps:>12,.0f} pps  {tot_gbit:>6.2f} Gbit/s  "
          f"({tot_sent:,} pkts, {tot_mb:,.0f} MB)")
    print("  Watch the target:  ssh <host> 'sudo xdp stats -i wlo1 --interval 1'")


def cmd_hammer(argv):
    """Coordinated MULTI-VECTOR attack: each bot runs a different vector at once,
    to exercise every layer of the target's detection simultaneously."""
    p = argparse.ArgumentParser(prog="hammer", add_help=False)
    p.add_argument("target")
    p.add_argument("-d", "--duration", type=float, default=20.0)
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return
    with LOCK:
        agents = list(AGENTS.values())
    if not agents:
        print("  no bots connected.")
        return
    # round-robin attack profiles across the bots
    profiles = [
        ("super", None),                 # max-volume UDP spray
        ("udp", "80,443,8080"),          # UDP flood to web ports
        ("udp", "53,123,161"),           # UDP flood to DNS/NTP/SNMP (reflection-style)
        ("tcp-connect", "80,443,22"),    # TCP SYN-path flood
    ]
    aid = str(time.time())
    start_at = time.time() + 3.0
    with LOCK:
        RESULTS[aid] = []
    sent = 0
    print("  assigning vectors:")
    for i, ag in enumerate(agents):
        vec, ports = profiles[i % len(profiles)]
        order = {"type": "attack", "id": aid, "target": a.target, "vector": vec,
                 "ports": ports, "duration": a.duration, "size": None, "start_at": start_at}
        try:
            send(ag["conn"], order)
            sent += 1
            print(f"    {ag['name']:<20} -> {vec} {ports or '(spray)'}")
        except Exception:
            pass
    print(f"  MULTI-VECTOR hammer on {sent} bot(s), synchronized start in 3s, {a.duration:g}s...")
    _collect(aid, sent, start_at, a.duration)


def main():
    ap = argparse.ArgumentParser(description="distributed stress-test controller")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    print(__doc__.split("\n\n")[1].strip())  # print the AUTHORIZED-ONLY banner
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(64)
    threading.Thread(target=accept_loop, args=(sock,), daemon=True).start()
    print(f"\ncontroller listening on {args.host}:{args.port}")
    print("on each other machine run:  python3 swarm_agent.py <this-ip>:%d" % args.port)
    print("type 'help' for commands.\n")

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = shlex.split(line)
        cmd, argv = parts[0], parts[1:]
        if cmd in ("quit", "exit"):
            break
        elif cmd == "list":
            cmd_list()
        elif cmd == "attack":
            if not argv:
                print("  usage: attack <target> [--vector super] [--ports 80,443] [-d 15] [--size N]")
            else:
                cmd_attack(argv)
        elif cmd == "hammer":
            if not argv:
                print("  usage: hammer <target> [-d 20]   (multi-vector: every bot a different attack)")
            else:
                cmd_hammer(argv)
        elif cmd == "help":
            print(__doc__.split("Commands at the prompt:")[1])
        else:
            print(f"  unknown command: {cmd} (try 'help')")


if __name__ == "__main__":
    main()
