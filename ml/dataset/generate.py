#!/usr/bin/env python3
"""Generate a labelled synthetic dataset of feature-vector windows.

Until the lab capture (ml/dataset/lab_capture.py, needs TRex + wired hosts)
exists, this produces plausible feature rows for benign traffic and every
attack profile x intensity, so the Phase 9 detector and the Phase 10-12 models
are trainable and testable now. Rows are in the exact v1-schema order and carry
the schema_hash; features the live agent cannot yet fill are left blank (NaN),
exactly as in production.

  python3 ml/dataset/generate.py -o ml/dataset/synthetic.csv -n 500
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from schema import FEATURES, SCHEMA_HASH  # noqa: E402
from attacks.profiles import (  # noqa: E402
    ATTACK_TYPES, INTENSITIES, LABELS, profile_window,
)

# Features we cannot synthesise honestly (need heavy hitters / long history);
# emitted blank = NaN, matching the live agent.
MISSING = {
    "pps_baseline_ratio", "top1_src_share", "top10_src_share",
    "pps_zscore", "pps_accel", "unsupported_rate",
}


def jitter(x: float, rel: float = 0.15) -> float:
    return max(0.0, x * (1.0 + random.gauss(0.0, rel)))


def feature_value(name: str, w: dict, is_attack: bool) -> float:
    dt = 1.0
    pps = jitter(w["pps"])
    packets = pps * dt
    mean_size = jitter(w["mean_pkt_size"], 0.1)
    byts = packets * mean_size
    tcp = packets * w["share_tcp"]
    udp = packets * w["share_udp"]
    icmp = packets * w["share_icmp"]
    syn = packets * w["tcp_syn_frac"]
    ack = packets * w["tcp_ack_frac"]
    frag = packets * w["frag_frac"]
    malformed = packets * w["malformed_frac"]
    other = max(0.0, packets - tcp - udp - icmp)

    table = {
        "packets": packets,
        "bytes": byts,
        "pps": pps,
        "bps": 8.0 * byts / dt,
        "drop_pps": (0.9 * pps if is_attack else 0.0),
        "tcp_syn_rate": syn / dt,
        "tcp_synack_rate": jitter(ack * 0.02),
        "tcp_ack_rate": ack / dt,
        "tcp_rst_rate": jitter(tcp * 0.01),
        "tcp_fin_rate": jitter(tcp * 0.01),
        "tcp_syn_ack_ratio": syn / (ack + 1.0),
        "tcp_syn_share": syn / (tcp + 1.0),
        "tcp_bad_flags_rate": (jitter(packets * 0.3) if w["malformed_frac"] > 0 else jitter(tcp * 0.001)),
        "udp_pps": udp / dt,
        "udp_bps": 8.0 * udp * mean_size / dt,
        "udp_dport_top1_share": min(1.0, jitter(w["udp_dport_top1_share"], 0.05)),
        "udp_len_mismatch_rate": (jitter(udp * 0.2) if w["malformed_frac"] > 0 else 0.0),
        "icmp_pps": icmp / dt,
        "icmp_share": icmp / packets if packets else float("nan"),
        "frag_rate": frag / dt,
        "frag_share": frag / packets if packets else float("nan"),
        "unique_src": jitter(w["unique_src"], 0.1),
        "unique_flows": jitter(w["unique_flows"], 0.1),
        "new_src": jitter(w["unique_src"] * (0.9 if is_attack else 0.1), 0.2),
        "flows_per_src": w["unique_flows"] / max(1.0, w["unique_src"]),
        "dport_entropy": min(1.0, jitter(w["dport_entropy"], 0.1)),
        "mean_pkt_size": mean_size,
        "share_tcp": w["share_tcp"],
        "share_udp": w["share_udp"],
        "share_icmp": w["share_icmp"],
        "share_other": other / packets if packets else float("nan"),
        "malformed_rate": malformed / dt,
        "fano_factor": max(0.1, jitter(1.0 + (5.0 if is_attack else 0.0), 0.3)),
        "burstiness_cv": min(3.0, jitter(w["burstiness_cv"], 0.2)),
    }
    if name in MISSING:
        return float("nan")
    return table.get(name, float("nan"))


def gen_rows(writer, attack: str, intensity: str, n: int):
    is_attack = attack != "benign"
    label = LABELS[attack]
    for _ in range(n):
        w = profile_window(attack, intensity)
        row = []
        for name in FEATURES:
            v = feature_value(name, w, is_attack)
            row.append("" if (isinstance(v, float) and math.isnan(v)) else f"{v:.6g}")
        row += [attack, str(label), str(int(is_attack)), intensity]
        writer.writerow(row)


def main():
    ap = argparse.ArgumentParser(description="synthetic labelled feature dataset")
    ap.add_argument("-o", "--out", default=os.path.join(os.path.dirname(__file__), "synthetic.csv"))
    ap.add_argument("-n", "--per-condition", type=int, default=300,
                    help="rows per attack-type x intensity, and 3x that for benign")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    random.seed(args.seed)

    with open(args.out, "w", newline="") as fh:
        fh.write(f"# schema_hash: {SCHEMA_HASH}\n")
        writer = csv.writer(fh)
        writer.writerow(list(FEATURES) + ["attack_type", "label", "is_attack", "intensity"])
        total = 0
        # benign gets more rows (the negative class dominates real traffic)
        for intensity in INTENSITIES:
            gen_rows(writer, "benign", intensity, args.per_condition)
            total += args.per_condition
        for attack in ATTACK_TYPES:
            for intensity in INTENSITIES:
                gen_rows(writer, attack, intensity, args.per_condition)
                total += args.per_condition
    print(f"wrote {total} rows to {args.out}")
    print(f"  {len(ATTACK_TYPES)} attack types x {len(INTENSITIES)} intensities + benign")
    print(f"  schema_hash {SCHEMA_HASH}")


if __name__ == "__main__":
    main()
