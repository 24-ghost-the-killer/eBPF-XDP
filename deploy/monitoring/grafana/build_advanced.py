#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the advanced xdp-sentinel operations dashboard.

    python3 deploy/monitoring/grafana/build_advanced.py > \
        deploy/monitoring/grafana/dashboards/xdp-sentinel-advanced.json

A DDoS-protection operations view: protection overview, exact drop-reason
breakdown (rate-limited / blocked / validity), attack indicators, rate-limiter
effectiveness, protocol & parser detail, and host health. Colours use the
validated categorical + status palette (dataviz skill).
"""
import json
import sys

DS = {"type": "prometheus", "uid": "xs-prometheus"}
IF = 'iface=~"$iface"'
# Detection/intelligence gauges are pinned to the agent job so a textfile
# (node_exporter) source such as the synthetic demo can never leak into them.
AG = 'iface=~"$iface",job="xdp-sentinel-agent"'
RI = "$__rate_interval"
BLUE, ORANGE, AQUA, YELLOW, MAGENTA = "#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"
VIOLET, RED2 = "#9085e9", "#e66767"
GOOD, WARNING, SERIOUS, CRITICAL = "#0ca30c", "#fab219", "#ec835a", "#d03b3b"
MUTED = "#898781"

_id = iter(range(1, 2000))


def tgt(expr, legend, ref="A", instant=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref}
    if instant:
        t.update({"instant": True, "range": False, "format": "table"})
    return t


def g(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def overrides(colours, dashes=()):
    ov = []
    for name, c in colours.items():
        ov.append({"matcher": {"id": "byName", "options": name},
                   "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]})
    for name in dashes:
        ov.append({"matcher": {"id": "byName", "options": name},
                   "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}}]})
    return ov


def ts(title, desc, targets, unit, grid, colours=None, stacked=False, single=BLUE,
       fill=None, dashes=(), thr=None, soft_max=None, bars=False, interval=None, legend=None):
    multi = colours is not None and len(colours) >= 2
    d = {
        "unit": unit, "min": 0,
        "color": {"mode": "fixed", "fixedColor": single},
        "custom": {
            "drawStyle": "bars" if bars else "line",
            "lineWidth": 1 if bars else 2,
            "fillOpacity": fill if fill is not None else (80 if bars else (28 if stacked else 8)),
            "showPoints": "never", "pointSize": 8, "spanNulls": False,
            "stacking": {"mode": "normal" if stacked else "none", "group": "A"},
            "axisBorderShow": False,
            "thresholdsStyle": {"mode": "dashed" if thr else "off"},
            **({"axisSoftMax": soft_max} if soft_max is not None else {}),
        },
        "thresholds": {"mode": "absolute", "steps": [{"color": "transparent", "value": None}]
                       + ([{"color": WARNING, "value": thr}] if thr else [])},
    }
    if bars:
        d["decimals"] = 0
    p = {
        "id": next(_id), "type": "timeseries", "title": title, "description": desc,
        "datasource": DS, "gridPos": grid, "targets": targets,
        "fieldConfig": {"defaults": d, "overrides": overrides(colours or {}, dashes)},
        "options": {
            "legend": {"showLegend": (legend if legend is not None else multi),
                       "displayMode": "list", "placement": "bottom", "calcs": []},
            "tooltip": {"mode": "multi" if multi else "single", "sort": "desc"},
        },
    }
    if interval:
        p["interval"] = interval
    return p


def stat(title, desc, targets, unit, grid, colour=BLUE, steps=None, mappings=None,
         text="value", graph=True, dec=None):
    df = {
        "unit": unit,
        "color": {"mode": "thresholds"} if steps else {"mode": "fixed", "fixedColor": colour},
        "thresholds": {"mode": "absolute", "steps": steps or [{"color": colour, "value": None}]},
        "mappings": mappings or [],
    }
    if dec is not None:
        df["decimals"] = dec
    return {
        "id": next(_id), "type": "stat", "title": title, "description": desc,
        "datasource": DS, "gridPos": grid, "targets": targets,
        "fieldConfig": {"defaults": df, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "value" if steps else "none",
                    "graphMode": "area" if graph else "none", "textMode": text,
                    "justifyMode": "auto", "showPercentChange": False},
    }


def row(title, y):
    return {"id": next(_id), "type": "row", "title": title, "collapsed": False,
            "gridPos": g(0, y, 24, 1), "panels": []}


# helper prometheus fragments
def r(metric, sel=""):
    inside = IF + (("," + sel) if sel else "")
    return f"sum(rate({metric}{{{inside}}}[{RI}]))"


# clean pre-built expressions (avoids quoting hell inside f-strings)
RX = r("xs_rx_packets_total")
DROP = r("xs_verdict_packets_total", 'verdict="drop"')
RL = r("xs_policy_event_packets_total", 'event="rate_limited"')
BLK = r("xs_policy_event_packets_total", 'event="drop"')
SYN = r("xs_tcp_flags_packets_total", 'class="syn"')
ACK = r("xs_tcp_flags_packets_total", 'class="ack"')
DROPPCT = f"{DROP} / clamp_min({RX}, 1e-9)"
VALIDITY = f"clamp_min({DROP} - {RL} - {BLK}, 0)"
RATIO = f"{SYN} / ({ACK} + 1)"

panels = []
y = 0

# ---------------- Protection overview ----------------
panels.append(row("Protection overview", y)); y += 1
panels += [
    stat("Incoming", "All frames arriving per second.", [tgt(r("xs_rx_packets_total"), "in")],
         "pps", g(0, y, 4, 4), colour=BLUE),
    stat("Passed", "Frames delivered to the machine.",
         [tgt(r("xs_verdict_packets_total", 'verdict="pass"'), "pass")], "pps", g(4, y, 4, 4), colour=GOOD),
    stat("Dropped", "Frames dropped by the dataplane.",
         [tgt(r("xs_verdict_packets_total", 'verdict="drop"'), "drop")], "pps", g(8, y, 4, 4),
         steps=[{"color": GOOD, "value": None}, {"color": CRITICAL, "value": 1}]),
    stat("Drop rate", "Share of arriving frames dropped.",
         [tgt(DROPPCT, "drop%")], "percentunit", g(12, y, 4, 4), dec=1,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 0.05}, {"color": CRITICAL, "value": 0.3}]),
    stat("Dataplane", "XDP program attachment and mode.",
         [tgt(f"max by (mode) (xs_dataplane_attached{{{IF}}})", "{{mode}}")], "none", g(16, y, 4, 4),
         graph=False, text="value_and_name",
         steps=[{"color": CRITICAL, "value": None}, {"color": GOOD, "value": 1}],
         mappings=[{"type": "value", "options": {"1": {"text": "✓ protected", "index": 0}, "0": {"text": "✗ OFF", "index": 1}}}]),
    stat("Feed age", "Seconds since the agent last exported metrics.",
         [tgt('time() - max(node_textfile_mtime_seconds{file=~".*xdp-sentinel.*"} or (timestamp(xs_agent_up) * xs_agent_up))', "age")],
         "s", g(20, y, 4, 4), graph=False, dec=0,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 15}, {"color": CRITICAL, "value": 60}]),
]
y += 4

# ---------------- Mitigation activity ----------------
panels.append(row("Mitigation activity (per second)", y)); y += 1
panels += [
    stat("Rate-limited", "Flood packets dropped by the per-source rate limiter.",
         [tgt(r("xs_policy_event_packets_total", 'event="rate_limited"'), "rl")], "pps", g(0, y, 4, 4),
         colour=ORANGE, steps=[{"color": MUTED, "value": None}, {"color": ORANGE, "value": 1}]),
    stat("Blocked", "Packets dropped by a per-source block policy.",
         [tgt(r("xs_policy_event_packets_total", 'event="drop"'), "blk")], "pps", g(4, y, 4, 4),
         colour=MAGENTA, steps=[{"color": MUTED, "value": None}, {"color": MAGENTA, "value": 1}]),
    stat("Bad TCP flags", "Impossible-flag packets seen (dropped if the flag is on).",
         [tgt(r("xs_anomaly_packets_total", 'kind="tcp_bad_flags"'), "bad")], "pps", g(8, y, 4, 4),
         colour=YELLOW, steps=[{"color": MUTED, "value": None}, {"color": YELLOW, "value": 1}]),
    stat("Malformed", "Malformed frames (parser errors).",
         [tgt(r("xs_parse_outcome_packets_total", 'class="malformed"'), "mal")], "pps", g(12, y, 4, 4),
         colour=SERIOUS, steps=[{"color": MUTED, "value": None}, {"color": SERIOUS, "value": 1}]),
    stat("Allowlisted", "Packets passed because the source is allowlisted.",
         [tgt(r("xs_policy_event_packets_total", 'event="pass"'), "allow")], "pps", g(16, y, 4, 4),
         colour=GOOD),
    stat("Mitigation", "Active dataplane drop flags (1 = on).",
         [tgt(f"sum by (flag) (xs_config_flag{{{IF},flag!~\"check_.*\"}})", "{{flag}}")], "none",
         g(20, y, 4, 4), graph=False, text="value_and_name",
         steps=[{"color": MUTED, "value": None}, {"color": WARNING, "value": 1}],
         mappings=[{"type": "value", "options": {"0": {"text": "off", "index": 0}, "1": {"text": "ON", "index": 1}}}]),
]
y += 4

# ---------------- Traffic & drops over time ----------------
panels.append(row("Traffic and drops over time", y)); y += 1
panels += [
    ts("Passed vs dropped", "Stacked; top edge = total arriving. green = passed, red = dropped.",
       [tgt(f'sum by (verdict) (rate(xs_verdict_packets_total{{{IF},verdict=~"pass|drop"}}[{RI}]))', "{{verdict}}")],
       "pps", g(0, y, 12, 8), colours={"pass": GOOD, "drop": CRITICAL}, stacked=True),
    ts("Drops by reason", "Exact breakdown of every dropped packet: rate-limited (flood), "
       "blocked (per-source policy), validity (malformed / bad-flags / fragments / UDP filters).",
       [tgt(r("xs_policy_event_packets_total", 'event="rate_limited"'), "rate-limited", "A"),
        tgt(r("xs_policy_event_packets_total", 'event="drop"'), "blocked", "B"),
        tgt(VALIDITY, "validity", "C")],
       "pps", g(12, y, 12, 8), colours={"rate-limited": ORANGE, "blocked": MAGENTA, "validity": YELLOW}, stacked=True),
]
y += 8
panels += [
    ts("Throughput", "Bit rate of all frames seen by XDP.",
       [tgt(f"8 * {r('xs_rx_bytes_total')}", "throughput")], "bps", g(0, y, 12, 6)),
    ts("Drop rate %", "Share of arriving frames dropped, over time.",
       [tgt(DROPPCT, "drop%")], "percentunit", g(12, y, 12, 6), single=CRITICAL, fill=15),
]
y += 6

# ---------------- Attack indicators ----------------
panels.append(row("Attack indicators", y)); y += 1
panels += [
    ts("Connection attempts (SYN/s)", "New TCP connection attempts per second (SYN without ACK). "
       "A sharp climb is a SYN flood.",
       [tgt(r("xs_tcp_flags_packets_total", 'class="syn"'), "syn")], "pps", g(0, y, 8, 7), single=BLUE, fill=20),
    ts("SYN : ACK ratio", "SYN / (ACK+1). Sustained values >> 1 with high SYN rates = SYN flood "
       "(dashed line = 10).",
       [tgt(RATIO, "ratio")],
       "none", g(8, y, 8, 7), single=SERIOUS, thr=10, soft_max=12),
    ts("Rate limiter: tracked vs limited", "Packets evaluated by the per-source limiter vs those it "
       "dropped. A large limited fraction means active per-source flooding.",
       [tgt(r("xs_rate_tracked_packets_total"), "tracked", "A"),
        tgt(r("xs_policy_event_packets_total", 'event="rate_limited"'), "limited", "B")],
       "pps", g(16, y, 8, 7), colours={"tracked": BLUE, "limited": ORANGE}),
]
y += 7

# ---------------- Protocol & parser ----------------
panels.append(row("Protocol and parser detail", y)); y += 1
panels += [
    ts("Transport protocol mix", "Fully parsed IP packets by transport protocol.",
       [tgt(f"sum by (proto) (rate(xs_l4_packets_total{{{IF}}}[{RI}]))", "{{proto}}")], "pps",
       g(0, y, 8, 7), colours={"tcp": BLUE, "udp": ORANGE, "icmp": AQUA, "icmpv6": YELLOW, "other": MAGENTA}),
    ts("TCP flag classes", "syn / synack / ack / fin / rst per second.",
       [tgt(f"sum by (class) (rate(xs_tcp_flags_packets_total{{{IF}}}[{RI}]))", "{{class}}")], "pps",
       g(8, y, 8, 7), colours={"syn": BLUE, "synack": ORANGE, "ack": AQUA, "fin": YELLOW, "rst": MAGENTA}),
    ts("Header anomalies / min", "Anomalous headers per minute (bad flags, LAND, UDP length, IP options).",
       [tgt(f"round(sum by (kind) (increase(xs_anomaly_packets_total{{{IF}}}[$__interval])))", "{{kind}}")],
       "short", g(16, y, 8, 7),
       colours={"tcp_bad_flags": CRITICAL, "land": MAGENTA, "udp_len_mismatch": ORANGE, "ipv4_options": AQUA},
       bars=True, interval="1m"),
]
y += 7
panels.append(ts(
    "Malformed & unsupported / sec",
    "Two always-on lines (sit at 0 when traffic is clean, spike under a bad-packet attack): "
    "malformed = RFC-invalid frames (truncated, bad lengths); unsupported = legal but beyond the fast "
    "path (deep VLAN/IPv6 stacks). Per-outcome detail is in the xs_parse_outcome_packets_total metric.",
    [tgt(r("xs_parse_outcome_packets_total", 'class="malformed"'), "malformed", "A"),
     tgt(r("xs_parse_outcome_packets_total", 'class="unsupported"'), "unsupported", "B")],
    "pps", g(0, y, 12, 8), colours={"malformed": CRITICAL, "unsupported": WARNING}, fill=18))
panels.append(ts("XDP-seen vs NIC-received", "Packets counted by XDP vs the kernel's NIC counter; a "
                 "gap means traffic that bypassed the program (dashed = NIC).",
                 [tgt(r("xs_rx_packets_total"), "seen by XDP", "A"),
                  tgt(f'sum(rate(node_network_receive_packets_total{{device=~"$iface"}}[{RI}]))', "NIC received", "B")],
                 "pps", g(12, y, 12, 8), colours={"seen by XDP": BLUE, "NIC received": MUTED}, dashes=("NIC received",)))
y += 8

# ---------------- Flow telemetry (Phase 5) ----------------
panels.append(row("Flow telemetry (Phase 5)", y)); y += 1
SAMP_TAKEN = r("xs_sample_packets_total", 'event="taken"')
SAMP_DROP = r("xs_sample_packets_total", 'event="dropped"')
panels += [
    ts("Header sampling / sec", "Headers copied to the sample ring buffer (blue) vs reservations that "
       "failed because the collector fell behind (red). Sampling feeds the flow table and per-flow "
       "features; both sit at 0 until the 'sampling' config flag is enabled.",
       [tgt(SAMP_TAKEN, "sampled", "A"), tgt(SAMP_DROP, "ring-buffer drops", "B")],
       "pps", g(0, y, 12, 7), colours={"sampled": BLUE, "ring-buffer drops": CRITICAL}),
    ts("Sample coverage", "Share of arriving packets captured as samples (sampled / received). "
       "Low coverage under load discounts the confidence of sampled features.",
       [tgt(f"{SAMP_TAKEN} / clamp_min({RX}, 1e-9)", "coverage")],
       "percentunit", g(12, y, 12, 7), single=BLUE, fill=15),
]
y += 7

# ---------------- Layer 2/3 and fragmentation ----------------
panels.append(row("Layer 2/3, fragments, extension headers", y)); y += 1
panels += [
    ts("L3 protocol mix", "Frames per second by L3 protocol (valid header).",
       [tgt(f"sum by (proto) (rate(xs_l3_packets_total{{{IF}}}[{RI}]))", "{{proto}}")], "pps",
       g(0, y, 8, 7), colours={"ipv4": BLUE, "ipv6": AQUA, "arp": YELLOW, "other": MUTED}),
    ts("Fragments / sec", "IPv4/IPv6 fragments (first carries the L4 header, later do not). "
       "A fragment flood targets reassembly; drop them with the 'fragments' flag.",
       [tgt(f"sum by (kind) (rate(xs_fragment_packets_total{{{IF}}}[{RI}]))", "{{kind}}")], "pps",
       g(8, y, 8, 7), colours={"first": ORANGE, "later": CRITICAL}),
    ts("VLAN tags & IPv6 ext headers / sec", "Tagged frames (802.1Q / QinQ, by tag count) and IPv6 "
       "packets carrying extension headers.",
       [tgt(f"sum by (tags) (rate(xs_vlan_packets_total{{{IF}}}[{RI}]))", "vlan {{tags}}-tag", "A"),
        tgt(r("xs_ipv6_ext_packets_total"), "ipv6 ext", "B")], "pps",
       g(16, y, 8, 7), colours={"ipv6 ext": MAGENTA, "vlan 1-tag": AQUA, "vlan 2-tag": YELLOW}),
]
y += 7

# ---------------- Detection & Intelligence (Phase 6-13) ----------------
panels.append(row("Detection & Intelligence (Phase 6-13)", y)); y += 1
STATE_MAP = [{"type": "value", "options": {
    "0": {"text": "NORMAL", "index": 0}, "1": {"text": "SUSPECT", "index": 1},
    "2": {"text": "UNDER ATTACK", "index": 2}}}]
LEVEL_MAP = [{"type": "value", "options": {
    "0": {"text": "pass", "index": 0}, "1": {"text": "monitor", "index": 1},
    "2": {"text": "sample", "index": 2}, "3": {"text": "rate limit", "index": 3},
    "4": {"text": "aggressive", "index": 4}, "5": {"text": "block", "index": 5}}}]
panels += [
    stat("Threat state", "Overall state from the statistical detector (Phase 9): normal / suspect / "
         "under attack, computed live from the feature vector.",
         [tgt(f"max(xs_threat_state{{{AG}}})", "state")], "none", g(0, y, 6, 4), graph=False,
         mappings=STATE_MAP,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 1}, {"color": CRITICAL, "value": 2}]),
    stat("Risk level", "Mitigation ladder position the risk engine (Phase 13) would apply for the service.",
         [tgt(f"max(xs_risk_level{{{AG}}})", "level")], "none", g(6, y, 6, 4), graph=False,
         mappings=LEVEL_MAP,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 2}, {"color": SERIOUS, "value": 4}, {"color": CRITICAL, "value": 5}]),
    stat("Anomaly (robust z)", "Statistical anomaly score; > 8 marks the window anomalous.",
         [tgt(f"max(xs_anomaly_score{{{AG}}})", "z")], "none", g(12, y, 6, 4), dec=1,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 4}, {"color": CRITICAL, "value": 8}]),
    stat("DDoS score", "DDoS classifier (Phase 11) top non-benign probability.",
         [tgt(f"max(xs_ddos_score{{{AG}}})", "ddos")], "percentunit", g(18, y, 6, 4), dec=0,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 0.5}, {"color": CRITICAL, "value": 0.85}]),
]
y += 4
panels += [
    ts("Risk & model scores (0-1)", "Fused risk (red), normalised statistical anomaly, DDoS-classifier "
       "score and Isolation-Forest anomaly score over time. All produced by the agent's analysis loop.",
       [tgt(f"max(xs_risk{{{AG}}})", "risk", "A"),
        tgt(f"max(xs_anomaly_score01{{{AG}}})", "anomaly (stat)", "B"),
        tgt(f"max(xs_ddos_score{{{AG}}})", "ddos", "C"),
        tgt(f"max(xs_anomaly_iforest{{{AG}}})", "anomaly (iforest)", "D")],
       "percentunit", g(0, y, 12, 7),
       colours={"risk": CRITICAL, "anomaly (stat)": ORANGE, "ddos": MAGENTA, "anomaly (iforest)": AQUA}),
    ts("DDoS classifier — class probabilities", "Per-attack-type probability from the CART classifier "
       "(sums to 1 across classes). The dominant non-benign class names the attack.",
       [tgt(f"xs_ddos_class_probability{{{AG}}}", "{{class}}")],
       "percentunit", g(12, y, 12, 7)),
]
y += 7
MIT_MAP = [{"type": "value", "options": {
    "0": {"text": "INACTIVE", "index": 0}, "1": {"text": "BLOCKING", "index": 1}}}]
panels += [
    ts("Auto-mitigation: per-source limit enforced", "The per-source packets/s ceiling the risk engine "
       "applies as it climbs the ladder (lower = more aggressive, 0 = none). The dataplane throttles each "
       "flooding source to this rate while normal traffic passes.",
       [tgt(f"max(xs_mitigation_rate_pps{{{AG}}})", "rate limit")], "pps", g(0, y, 12, 6),
       single=ORANGE, fill=20),
    stat("Mitigation", "Whether the risk engine is actively blocking/throttling right now.",
         [tgt(f"max(xs_mitigation_active{{{AG}}})", "active")], "none", g(12, y, 6, 6), graph=False,
         mappings=MIT_MAP,
         steps=[{"color": GOOD, "value": None}, {"color": CRITICAL, "value": 1}]),
    stat("Auto-actions", "Total mitigation changes the risk engine has applied.",
         [tgt(f"max(xs_auto_actions_total{{{AG}}})", "actions")], "none", g(18, y, 6, 6), colour=BLUE),
]
y += 6

# ---------------- Multi-layer detection ----------------
panels.append(row("Multi-layer detection (L2 / L3 / L4 / L7)", y)); y += 1
LAYER_MAP = [{"type": "value", "options": {
    "0": {"text": "NORMAL", "index": 0}, "1": {"text": "ELEVATED", "index": 1},
    "2": {"text": "ATTACK", "index": 2}}}]


def layer_stat(title, layer, x, desc):
    return stat(title, desc, [tgt(f'max(xs_layer_state{{{AG},layer="{layer}"}})', layer)],
                "none", g(x, y, 6, 4), graph=False, mappings=LAYER_MAP,
                steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 1},
                       {"color": CRITICAL, "value": 2}])


panels += [
    layer_stat("Layer 2 — Ethernet", "l2", 0,
               "ARP floods, non-IP ethertype floods, VLAN abuse."),
    layer_stat("Layer 3 — IP / ICMP", "l3", 6,
               "ICMP floods, fragment floods, LAND attacks."),
    layer_stat("Layer 4 — TCP / UDP", "l4", 12,
               "SYN/ACK/RST floods, UDP floods, impossible TCP flags, malformed UDP."),
    layer_stat("Layer 7 — Application", "l7", 18,
               "HTTP/DNS floods need reverse-proxy or DNS logs (not visible to XDP); stays NORMAL until that source is wired."),
]
y += 4
panels.append(ts(
    "Active per-layer attacks", "Which layer and attack type is firing right now (1 = active). "
    "L2: arp/ethertype/vlan floods; L3: icmp/frag/land; L4: syn/ack/rst/udp floods, bad flags, malformed UDP.",
    [tgt(f"xs_layer_detection{{{AG}}}", "{{layer}}: {{type}}")], "short", g(0, y, 24, 7), bars=True))
y += 7

# ---------------- Connection tracking ----------------
panels.append(ts(
    "Untracked TCP / sec — ACK/RST flood (conntrack shadow)",
    "TCP packets matching no tracked flow: an ACK/RST for a connection that never handshook here. "
    "In shadow (conntrack on, drop_untracked off) this is what connection-tracking WOULD drop — it "
    "should sit at ~0 for normal traffic and spike under an ACK/RST flood. Enable XS_CONNTRACK_ENFORCE "
    "to actually drop it (zero-collateral, after validating this line).",
    [tgt(r("xs_conntrack_packets_total", 'event="untracked"'), "untracked")],
    "pps", g(0, y, 24, 6), single=CRITICAL, fill=15))
y += 6

# ---------------- Host ----------------
panels.append(row("Host health", y)); y += 1
panels += [
    ts("Softirq CPU: busiest core vs average", "XDP/NAPI run in softirq. A core near 100% = packet loss "
       "before XDP (generic-mode / single-queue limit).",
       [tgt(f'max(rate(node_cpu_seconds_total{{mode="softirq"}}[{RI}]))', "busiest core", "A"),
        tgt(f'avg(rate(node_cpu_seconds_total{{mode="softirq"}}[{RI}]))', "average", "B")],
       "percentunit", g(0, y, 12, 7), colours={"busiest core": CRITICAL, "average": BLUE}),
    ts("NIC receive drops / errors", "Packets the host failed to receive (ring full) or received with errors "
       "— resource exhaustion before XDP.",
       [tgt(f'sum(rate(node_network_receive_drop_total{{device=~"$iface"}}[{RI}]))', "drops", "A"),
        tgt(f'sum(rate(node_network_receive_errs_total{{device=~"$iface"}}[{RI}]))', "errors", "B")],
       "pps", g(12, y, 12, 7), colours={"drops": ORANGE, "errors": CRITICAL}),
]
y += 7

dash = {
    "uid": "xdp-sentinel-advanced",
    "title": "xdp-sentinel — advanced",
    "description": "Advanced DDoS-protection operations view: drop-reason breakdown, attack indicators, "
                   "rate-limiter effectiveness, protocol/parser detail, host health.",
    "tags": ["xdp-sentinel", "xdp", "ddos", "advanced"],
    "timezone": "browser", "editable": False, "graphTooltip": 1, "refresh": "5s",
    "time": {"from": "now-30m", "to": "now"},
    "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
    "schemaVersion": 41, "version": 1,
    "templating": {"list": [{
        "name": "iface", "label": "Interface", "type": "query", "datasource": DS,
        "query": {"query": "label_values(xs_rx_packets_total, iface)", "refId": "iface"},
        "definition": "label_values(xs_rx_packets_total, iface)",
        "refresh": 2, "includeAll": True, "multi": True, "sort": 1,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
    }]},
    "annotations": {"list": []}, "links": [], "panels": panels,
}
json.dump(dash, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
