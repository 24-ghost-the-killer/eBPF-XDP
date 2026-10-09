#!/usr/bin/env python3
"""Synthetic intelligence-metrics generator for the xdp-sentinel advanced
Grafana dashboard (Phase 6-13 gauges).

*** This is DEMO data, not real detections. *** It writes a Prometheus textfile
that node_exporter serves (scraped every 5s), so the Detection & Intelligence
panels show a believable, moving attack scenario without a live attack. A
companion gauge `xs_intelligence_synthetic 1` marks the data as synthetic.

Stop it with:  pkill -f xs-intel-gen
Remove the data:  rm -f /var/lib/xdp-sentinel/textfile/xs-intelligence.prom
"""
import math
import os
import random
import time

OUT = "/var/lib/xdp-sentinel/textfile/xs-intelligence.prom"
IFACE = "wlo1"
CLASSES = ["benign", "syn_flood", "ack_flood", "udp_flood", "udp_reflection",
           "icmp_flood", "frag_flood", "malformed_flood", "connection_flood",
           "dns_amplification"]
# attack types rotated per cycle (each is a real classifier class)
ROTATION = ["udp_flood", "syn_flood", "icmp_flood", "dns_amplification"]
CYCLE = 180.0  # seconds per scenario


def scenario(t):
    """Return the metric values for elapsed time t (seconds)."""
    cyc = int(t // CYCLE)
    p = (t % CYCLE) / CYCLE          # 0..1 within the cycle
    atk = ROTATION[cyc % len(ROTATION)]
    n = lambda s: random.gauss(0, s)  # noise

    # phase envelope: calm -> ramp -> attack -> mitigation -> recovery
    if p < 0.25:                      # calm
        sev = 0.0
    elif p < 0.35:                    # ramp
        sev = (p - 0.25) / 0.10
    elif p < 0.70:                    # sustained attack
        sev = 1.0
    elif p < 0.85:                    # mitigation holding
        sev = 0.9
    else:                             # recovery
        sev = max(0.0, 1.0 - (p - 0.85) / 0.15)
    sev = max(0.0, min(1.0, sev))

    anomaly_z = max(0.0, 1.5 + sev * 28 + n(0.8) * (0.3 + sev))
    anomaly01 = 1.0 - math.exp(-anomaly_z / 8.0)
    iforest = min(0.99, 0.30 + sev * 0.6 + n(0.03))
    ddos = min(0.99, sev * 0.97 + n(0.02)) if sev > 0.05 else max(0.0, 0.05 + n(0.02))
    risk = min(0.99, sev * 0.95 + n(0.02)) if sev > 0.05 else max(0.0, 0.03 + n(0.01))
    level = 0 if risk < 0.30 else 1 if risk < 0.50 else 2 if risk < 0.70 \
        else 3 if risk < 0.85 else 4 if risk < 0.95 else 5
    state = 0 if sev < 0.15 else 1 if sev < 0.55 else 2
    active = 1 if state == 2 else 0
    pps = 300 + sev * 480_000 + n(50 + sev * 8000)
    pps = max(0.0, pps)

    # per-class probabilities: benign dominant when calm, attack class when hot
    probs = {c: 0.0 for c in CLASSES}
    if state == 2:
        probs[atk] = max(0.0, 0.80 + n(0.05))
        rest = 1.0 - probs[atk]
        others = [c for c in CLASSES if c != atk]
        for c in others:
            probs[c] = max(0.0, rest / len(others) + n(0.01))
    else:
        probs["benign"] = max(0.0, 0.90 - sev * 0.4 + n(0.03))
        rest = 1.0 - probs["benign"]
        for c in CLASSES[1:]:
            probs[c] = max(0.0, rest / (len(CLASSES) - 1) + n(0.01))
    tot = sum(probs.values()) or 1.0
    probs = {c: v / tot for c, v in probs.items()}

    # auto-mitigation: the risk engine tightens the per-source rate limit as the
    # ladder climbs, and blocks the attack type at the top rung.
    mit_pps = {5: 500, 4: 1000, 3: 5000}.get(level, 0)
    mit_active = 1 if mit_pps > 0 else 0
    return dict(state=state, anomaly_z=anomaly_z, anomaly01=anomaly01,
                iforest=iforest, ddos=ddos, risk=risk, level=level, active=active,
                pps=pps, probs=probs, atk=atk, mit_pps=mit_pps, mit_active=mit_active)


def render(v, auto_actions):
    L = f'iface="{IFACE}"'
    out = []
    def g(name, help_, val, typ="gauge"):
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {typ}")
        out.append(f"{name}{{{L}}} {val}")
    g("xs_intelligence_synthetic", "1 = these intelligence metrics are SYNTHETIC demo data.", 1)
    g("xs_analysis_pps", "Packets/s in the last analysis window (synthetic).", round(v["pps"], 1))
    g("xs_threat_state", "Threat state: 0 normal, 1 suspect, 2 under attack (synthetic).", v["state"])
    g("xs_anomaly_score", "Statistical detector robust z-score (synthetic).", round(v["anomaly_z"], 2))
    g("xs_anomaly_score01", "Anomaly score normalised 0..1 (synthetic).", round(v["anomaly01"], 4))
    g("xs_anomaly_iforest", "Isolation Forest anomaly score 0..1 (synthetic).", round(v["iforest"], 4))
    g("xs_ddos_score", "DDoS classifier top non-benign probability (synthetic).", round(v["ddos"], 4))
    g("xs_risk", "Fused risk for the service 0..1 (synthetic).", round(v["risk"], 4))
    g("xs_risk_level", "Mitigation ladder level 0..5 (synthetic).", v["level"])
    g("xs_detection_active", "1 while an attack is detected (synthetic).", v["active"])
    g("xs_mitigation_active", "1 while auto-mitigation is applied (synthetic).", v["mit_active"])
    g("xs_mitigation_rate_pps", "Per-source rate limit the risk engine enforces, 0 = none (synthetic).", v["mit_pps"])
    out.append("# HELP xs_auto_actions_total Auto-mitigation changes applied (synthetic).")
    out.append("# TYPE xs_auto_actions_total counter")
    out.append(f"xs_auto_actions_total{{{L}}} {auto_actions}")
    out.append("# HELP xs_ddos_class_probability Per-class DDoS probability (synthetic).")
    out.append("# TYPE xs_ddos_class_probability gauge")
    for c, pv in v["probs"].items():
        out.append(f'xs_ddos_class_probability{{{L},class="{c}"}} {round(pv, 4)}')
    if v["active"]:
        out.append("# HELP xs_detection_info Active detection type, value 1 (synthetic).")
        out.append("# TYPE xs_detection_info gauge")
        out.append(f'xs_detection_info{{{L},type="{v["atk"]}"}} 1')
    return "\n".join(out) + "\n"


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    start = time.time()
    prev_level = 0
    auto_actions = 0
    while True:
        v = scenario(time.time() - start)
        if v["level"] != prev_level and v["level"] > 0:
            auto_actions += 1  # the risk engine changed the mitigation rung
        prev_level = v["level"]
        body = render(v, auto_actions)
        tmp = OUT + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(body)
        os.replace(tmp, OUT)  # atomic: node_exporter never reads a partial file
        time.sleep(5)


if __name__ == "__main__":
    main()
