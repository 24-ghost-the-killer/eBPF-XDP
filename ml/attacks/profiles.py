"""Attack profiles for the lab generator and the synthetic dataset.

Each profile describes one attack *type* as a set of feature multipliers/values
relative to a benign 1 s window, at three intensities (low/med/high). The same
definitions drive:

  * the lab generator (ml/dataset/lab_capture.py) which turns them into TRex /
    stress-tool commands to record ground-truth traffic on real hardware;
  * the synthetic dataset (ml/dataset/generate.py) used until that capture
    exists, so the detector and models (Phases 9-12) are trainable now.

Exit criterion for Phase 8: >= 7 attack types x 3 intensities with ground
truth. The nine types below satisfy it; add rows here to extend coverage.
"""
from __future__ import annotations

# Benign baseline for a single protected service (1 s window), rough but
# realistic for a small server: a few hundred pps, mixed TCP/UDP.
BENIGN = {
    "pps": 400.0,
    "share_tcp": 0.7,
    "share_udp": 0.25,
    "share_icmp": 0.02,
    "tcp_syn_frac": 0.08,       # SYN as a fraction of packets
    "tcp_ack_frac": 0.55,
    "mean_pkt_size": 640.0,
    "unique_src": 120.0,
    "unique_flows": 300.0,
    "dport_entropy": 0.55,
    "frag_frac": 0.0,
    "malformed_frac": 0.0,
    "udp_dport_top1_share": 0.3,
    "burstiness_cv": 0.4,
}

# intensity -> pps multiplier over benign
INTENSITY = {"low": 8.0, "med": 40.0, "high": 200.0}

# label id per attack type (0 reserved for benign)
LABELS = {
    "benign": 0,
    "syn_flood": 1,
    "ack_flood": 2,
    "udp_flood": 3,
    "udp_reflection": 4,
    "icmp_flood": 5,
    "frag_flood": 6,
    "malformed_flood": 7,
    "connection_flood": 8,
    "dns_amplification": 9,
}

# Each profile overrides benign fields; values are absolute unless the key ends
# in "_frac" (fraction of packets) or is a *_share/entropy (0..1).
PROFILES = {
    "syn_flood": {
        "share_tcp": 0.98, "share_udp": 0.01, "tcp_syn_frac": 0.95,
        "tcp_ack_frac": 0.01, "mean_pkt_size": 60.0, "unique_src": 5000.0,
        "unique_flows": 50000.0, "dport_entropy": 0.05, "burstiness_cv": 0.2,
    },
    "ack_flood": {
        "share_tcp": 0.98, "tcp_syn_frac": 0.02, "tcp_ack_frac": 0.95,
        "mean_pkt_size": 64.0, "unique_src": 3000.0, "dport_entropy": 0.05,
    },
    "udp_flood": {
        "share_tcp": 0.02, "share_udp": 0.97, "mean_pkt_size": 900.0,
        "unique_src": 4000.0, "dport_entropy": 0.02, "udp_dport_top1_share": 0.95,
        "burstiness_cv": 0.15,
    },
    "udp_reflection": {  # DNS/NTP/memcached reflection: few source ports, big pkts
        "share_udp": 0.98, "mean_pkt_size": 1400.0, "unique_src": 800.0,
        "udp_dport_top1_share": 0.9, "dport_entropy": 0.1,
    },
    "icmp_flood": {
        "share_icmp": 0.97, "share_tcp": 0.02, "share_udp": 0.01,
        "mean_pkt_size": 1000.0, "unique_src": 2000.0, "dport_entropy": 0.0,
    },
    "frag_flood": {
        "frag_frac": 0.9, "share_udp": 0.9, "mean_pkt_size": 1480.0,
        "unique_src": 3000.0,
    },
    "malformed_flood": {
        "malformed_frac": 0.8, "mean_pkt_size": 100.0, "unique_src": 2500.0,
        "dport_entropy": 0.3,
    },
    "connection_flood": {  # full-connect flood: SYN + ACK, real handshakes
        "share_tcp": 0.99, "tcp_syn_frac": 0.5, "tcp_ack_frac": 0.45,
        "mean_pkt_size": 120.0, "unique_src": 200.0, "unique_flows": 80000.0,
        "dport_entropy": 0.02,
    },
    "dns_amplification": {
        "share_udp": 0.98, "mean_pkt_size": 1500.0, "unique_src": 300.0,
        "udp_dport_top1_share": 0.98, "dport_entropy": 0.03,
    },
}


def profile_window(attack: str, intensity: str) -> dict:
    """Return a benign-relative window description for one attack/intensity."""
    w = dict(BENIGN)
    if attack != "benign":
        w.update(PROFILES[attack])
        w["pps"] = BENIGN["pps"] * INTENSITY[intensity]
    return w


ATTACK_TYPES = [k for k in LABELS if k != "benign"]
INTENSITIES = list(INTENSITY.keys())

if __name__ == "__main__":
    print(f"{len(ATTACK_TYPES)} attack types x {len(INTENSITIES)} intensities "
          f"= {len(ATTACK_TYPES) * len(INTENSITIES)} attack conditions + benign")
    for a in ATTACK_TYPES:
        print(f"  {LABELS[a]:2d}  {a}")
