#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the xdp-sentinel Grafana dashboard (Phase 1 metrics).

    python3 deploy/monitoring/grafana/build_dashboard.py > \
        deploy/monitoring/grafana/dashboards/xdp-sentinel-dataplane.json

Design rules (docs/observability.md, dataviz method):
  * series colours are fixed per entity, from the validated categorical order
    (dark-mode steps, validated against Grafana's dark panel surface #181b1f);
  * one y-axis per panel: pps and bit/s never share a chart;
  * >= 2 series always have a legend; single-series panels have none;
  * more than 8 categories (parse outcomes) -> single-hue ranked bar gauge,
    never generated hues;
  * status colours only for state (attached, freshness), with text labels.
"""
import json
import sys

DS = {"type": "prometheus", "uid": "xs-prometheus"}
IF = 'iface=~"$iface"'
RI = "$__rate_interval"
# Rare events (anomalies, fragments) are shown as counts per >= 1 min bucket,
# drawn as bars: a per-second rate of 1-2 events a minute only flaps.
BUCKET = "$__interval"

# categorical slots 1..5 (dark steps)
BLUE, ORANGE, AQUA, YELLOW, MAGENTA = "#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"
# status palette
GOOD, WARNING, CRITICAL = "#0ca30c", "#fab219", "#d03b3b"

_next_id = iter(range(1, 1000))


def target(expr, legend, ref, instant=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref}
    if instant:
        t.update({"instant": True, "range": False, "format": "table"})
    return t


def colour_overrides(colours):
    return [
        {"matcher": {"id": "byName", "options": name},
         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
        for name, c in colours.items()
    ]


def timeseries(title, desc, targets, unit, grid, colours=None, stacked=False, single=None,
               threshold_line=None, dashed=(), soft_max=None, bars=False, interval=None):
    multi = colours is not None and len(colours) >= 2
    defaults = {
        "unit": unit,
        "min": 0,
        "color": {"mode": "fixed", "fixedColor": single or BLUE},
        "custom": {
            "drawStyle": "bars" if bars else "line",
            "lineWidth": 1 if bars else 2,
            "lineInterpolation": "linear",
            "fillOpacity": 85 if bars else (30 if stacked else 8),
            "gradientMode": "none",
            "showPoints": "never",
            "pointSize": 8,
            "spanNulls": False,
            "stacking": {"mode": "normal" if stacked else "none", "group": "A"},
            "axisBorderShow": False,
            "axisPlacement": "auto",
            "thresholdsStyle": {"mode": "dashed" if threshold_line else "off"},
            **({"axisSoftMax": soft_max} if soft_max is not None else {}),
        },
        "thresholds": {"mode": "absolute", "steps": [{"color": "transparent", "value": None}]
                       + ([{"color": WARNING, "value": threshold_line}] if threshold_line else [])},
    }
    if bars:
        defaults["decimals"] = 0
    panel = {
        "id": next(_next_id), "type": "timeseries", "title": title, "description": desc,
        "datasource": DS, "gridPos": grid, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": colour_overrides(colours or {}) + [
            {"matcher": {"id": "byName", "options": name},
             "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}}]}
            for name in dashed]},
        "options": {
            "legend": {"showLegend": multi, "displayMode": "list", "placement": "bottom", "calcs": []},
            "tooltip": {"mode": "multi" if multi else "single", "sort": "desc"},
        },
    }
    if interval:
        panel["interval"] = interval  # minimum bucket for $__interval
    return panel


def stat(title, desc, targets, unit, grid, colour=BLUE, steps=None, mappings=None,
         text_mode="value", graph=True, decimals=None):
    defaults = {
        "unit": unit,
        "color": {"mode": "thresholds"} if steps else {"mode": "fixed", "fixedColor": colour},
        "thresholds": {"mode": "absolute", "steps": steps or [{"color": colour, "value": None}]},
        "mappings": mappings or [],
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "id": next(_next_id), "type": "stat", "title": title, "description": desc,
        "datasource": DS, "gridPos": grid, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "value" if steps else "none",
            "graphMode": "area" if graph else "none",
            "textMode": text_mode,
            "justifyMode": "auto",
            "orientation": "auto",
            "showPercentChange": False,
        },
    }


def g(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def row(title, y):
    return {"id": next(_next_id), "type": "row", "title": title, "collapsed": False,
            "gridPos": g(0, y, 24, 1), "panels": []}


panels = []
y = 0
panels += [
    stat("Incoming now", "Frames per second seen at the XDP ingress point.",
         [target(f"sum(rate(xs_rx_packets_total{{{IF}}}[{RI}]))", "in", "A")],
        "pps", g(0, y, 6, 4), colour=BLUE),
    stat("Passed now", "Frames per second passed by the XDP program.",
         [target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="pass"}}[{RI}]))', "through", "A")],
        "pps", g(6, y, 6, 4), colour=GOOD),
    stat("Dropped now", "Frames per second dropped by the XDP program.",
         [target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))', "dropped", "A")],
        "pps", g(12, y, 6, 4), steps=[{"color": GOOD, "value": None}, {"color": CRITICAL, "value": 1}]),
    stat("Drop rate", "Dropped packets as a share of packets seen at XDP.",
         [target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))'
                 f" / clamp_min(sum(rate(xs_rx_packets_total{{{IF}}}[{RI}])), 1e-9)", "drop share", "A")],
        "percentunit", g(18, y, 6, 4), decimals=2,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 0.01}, {"color": CRITICAL, "value": 0.1}]),
    stat("Dataplane", "Whether the xdp-sentinel program pinned for the interface is the one attached, and in which XDP mode.",
         [target(f"max by (mode) (xs_dataplane_attached{{{IF}}})", "{{mode}}", "A")],
         "none", g(16, y, 4, 4), graph=False, text_mode="value_and_name",
         steps=[{"color": CRITICAL, "value": None}, {"color": GOOD, "value": 1}],
         mappings=[{"type": "value", "options": {
             "1": {"text": "✓ attached", "index": 0},
             "0": {"text": "✗ NOT attached", "index": 1}}}]),
    stat("Metrics age", "Seconds since the exporter last wrote xdp-sentinel metrics (written every 5 s). High = the feed is stale.",
         [target('time() - max(node_textfile_mtime_seconds{file=~".*xdp-sentinel.*"})', "age", "A")],
         "s", g(20, y, 4, 4), graph=False, decimals=0,
         steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 15}, {"color": CRITICAL, "value": 60}]),
]
y += 4

panels += [
    stat("Total received", "Frames seen by XDP since the dataplane counters were created.",
         [target(f"sum(xs_rx_packets_total{{{IF}}})", "in", "A")],
        "short", g(0, y, 8, 4), colour=BLUE, graph=False, decimals=0),
    stat("Total passed", "Frames passed by the XDP program.",
         [target(f'sum(xs_verdict_packets_total{{{IF},verdict="pass"}})', "through", "A")],
        "short", g(8, y, 8, 4), colour=GOOD, graph=False, decimals=0),
    stat("Total dropped", "Total frames dropped by the dataplane.",
         [target(f'sum(xs_verdict_packets_total{{{IF},verdict="drop"}})', "dropped", "A")],
        "short", g(16, y, 8, 4), graph=False, decimals=0,
         steps=[{"color": GOOD, "value": None}, {"color": CRITICAL, "value": 1}]),
    stat("Total data through", "Total bytes seen by the XDP program.",
         [target(f"sum(xs_rx_bytes_total{{{IF}}})", "bytes", "A")],
         "bytes", g(18, y, 6, 4), colour=BLUE, graph=False),
]
y += 4

panels += [
    timeseries("Incoming, passed, and dropped packets",
               "Packet rates at XDP ingress and the final pass/drop verdicts. Incoming should equal passed plus dropped.",
               [target(f"sum(rate(xs_rx_packets_total{{{IF}}}[{RI}]))", "Incoming", "A"),
                target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="pass"}}[{RI}]))', "Passed", "B"),
                target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))', "Dropped", "C")],
               "pps", g(0, y, 24, 10), colours={"Incoming": BLUE, "Passed": GOOD, "Dropped": CRITICAL}),
    timeseries("Throughput",
               "Bit rate of all frames seen by XDP (L2 frame length, without FCS).",
               [target(f"8 * sum(rate(xs_rx_bytes_total{{{IF}}}[{RI}]))", "throughput", "A")],
               "bps", g(12, y, 12, 8)),
]
y += 8
panels += [
    timeseries("Transport protocol mix",
               "Fully parsed IP packets per second by transport protocol.",
               [target(f"sum by (proto) (rate(xs_l4_packets_total{{{IF}}}[{RI}]))", "{{proto}}", "A")],
               "pps", g(0, y, 12, 8),
               colours={"tcp": BLUE, "udp": ORANGE, "icmp": AQUA, "icmpv6": YELLOW, "other": MAGENTA}),
    timeseries("TCP flag classes",
               "syn = SYN without ACK (connection attempts), synack, ack = pure ACK/data, fin, rst.",
               [target(f"sum by (class) (rate(xs_tcp_flags_packets_total{{{IF}}}[{RI}]))", "{{class}}", "A")],
               "pps", g(12, y, 12, 8),
               colours={"syn": BLUE, "synack": ORANGE, "ack": AQUA, "fin": YELLOW, "rst": MAGENTA}),
]
y += 8

panels.append(row("Anomalies and parser", y)); y += 1
panels += [
    timeseries("SYN-to-ACK ratio",
               "SYN rate / (ACK rate + 1). Sustained values far above 1 with high SYN rates indicate a SYN flood "
               "(dashed line: 10, the SynFlood alert ratio).",
               [target(f'sum(rate(xs_tcp_flags_packets_total{{{IF},class="syn"}}[{RI}]))'
                       f' / (sum(rate(xs_tcp_flags_packets_total{{{IF},class="ack"}}[{RI}])) + 1)',
                       "ratio", "A")],
               "none", g(0, y, 6, 8), threshold_line=10, soft_max=12),
    timeseries("Header anomalies per minute",
               "Packets with anomalous headers per 1-minute bucket (counted; passed unless drop flags are enabled).",
               [target(f"round(sum by (kind) (increase(xs_anomaly_packets_total{{{IF}}}[{BUCKET}])))", "{{kind}}", "A")],
               "short", g(6, y, 6, 8), bars=True, interval="1m",
               colours={"tcp_bad_flags": BLUE, "udp_len_mismatch": ORANGE, "ipv4_options": AQUA, "land": YELLOW}),
    timeseries("Fragments & IPv6 ext headers / min",
               "Packets per 1-minute bucket. first = first fragment (carries the L4 header), later = non-first "
               "fragments; ipv6 ext headers includes routine MLD (Hop-by-Hop) traffic.",
               [target(f"round(sum by (kind) (increase(xs_fragment_packets_total{{{IF}}}[{BUCKET}])))", "{{kind}}", "A"),
                target(f"round(sum(increase(xs_ipv6_ext_packets_total{{{IF}}}[{BUCKET}])))", "ipv6 ext headers", "B")],
               "short", g(12, y, 6, 8), bars=True, interval="1m",
               colours={"first": BLUE, "later": ORANGE, "ipv6 ext headers": AQUA}),
    stat("Validity mitigation", "Dataplane drop flags (sentinelctl config). All off = observe only, the safe default.",
         [target(f"max by (flag) (xs_config_flag{{{IF}}})", "{{flag}}", "A")],
         "none", g(18, y, 6, 8), graph=False, text_mode="value_and_name",
         steps=[{"color": "#898781", "value": None}, {"color": WARNING, "value": 1}],
         mappings=[{"type": "value", "options": {
             "0": {"text": "off", "index": 0}, "1": {"text": "ON", "index": 1}}}]),
]
y += 8

parse_bars = {
    "id": next(_next_id), "type": "bargauge",
    "title": "Unsupported and malformed frames by parse outcome (pps, last 5 min)",
    "description": "Every frame gets exactly one parse outcome; this ranks the non-OK ones "
                   "(err_* = malformed, unsup_* = legal but beyond the fast path). Only outcomes seen are listed.",
    "datasource": DS, "gridPos": g(0, y, 12, 9),
    "targets": [target(f'sum by (outcome) (rate(xs_parse_outcome_packets_total{{{IF},class!="ok"}}[5m])) > 0',
                       "{{outcome}}", "A", instant=True)],
    "transformations": [{"id": "sortBy", "options": {"sort": [{"field": "Value", "desc": True}]}}],
    "fieldConfig": {"defaults": {
        "unit": "pps", "min": 0, "decimals": 2,
        "color": {"mode": "fixed", "fixedColor": BLUE},
        "thresholds": {"mode": "absolute", "steps": [{"color": BLUE, "value": None}]},
        "displayName": "${__field.labels.outcome}",
        "noValue": "none: every frame in the last 5 min parsed OK",
    }, "overrides": []},
    "options": {
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
        "orientation": "horizontal", "displayMode": "basic", "valueMode": "text",
        "showUnfilled": True, "namePlacement": "left", "sizing": "auto", "minVizHeight": 12,
    },
}
panels.append(parse_bars)
panels.append(timeseries(
    "Seen by XDP vs received by the NIC",
    "Packets per second counted by the XDP program vs the kernel's interface counter. "
    "They should coincide (the NIC line is dashed so both stay visible); a gap means traffic that bypassed or preceded the program.",
    [target(f"sum(rate(xs_rx_packets_total{{{IF}}}[{RI}]))", "seen by XDP", "A"),
     target(f'sum(rate(node_network_receive_packets_total{{device=~"$iface"}}[{RI}]))', "NIC received", "B")],
    "pps", g(12, y, 12, 9), colours={"seen by XDP": BLUE, "NIC received": ORANGE}, dashed=("NIC received",)))
y += 9

panels.append(row("Host", y)); y += 1
panels += [
    timeseries("Softirq CPU time: busiest core vs average",
               "XDP and NAPI run in softirq context. The busiest core saturating (near 100%) means packet loss "
               "before XDP; compare with the average to spot uneven RSS/IRQ distribution.",
               [target(f'max(rate(node_cpu_seconds_total{{mode="softirq"}}[{RI}]))', "busiest core", "A"),
                target(f'avg(rate(node_cpu_seconds_total{{mode="softirq"}}[{RI}]))', "average", "B")],
               "percentunit", g(0, y, 12, 8), colours={"busiest core": BLUE, "average": ORANGE}),
    timeseries("NIC receive drops and errors",
               "Packets the host failed to receive (ring full, no buffer) or received with errors.",
               [target(f'sum(rate(node_network_receive_drop_total{{device=~"$iface"}}[{RI}]))', "drops", "A"),
                target(f'sum(rate(node_network_receive_errs_total{{device=~"$iface"}}[{RI}]))', "errors", "B")],
               "pps", g(12, y, 12, 8), colours={"drops": BLUE, "errors": ORANGE}),
]

# Traffic-first layout: keep drops on their own scale so they remain visible
# even when pass volume is much larger.
panels = [
    stat("Incoming now", "Packets per second seen at XDP ingress.",
        [target(f"sum(rate(xs_rx_packets_total{{{IF}}}[{RI}]))", "incoming", "A")],
        "pps", g(0, 0, 6, 4), colour=BLUE),
    stat("Passed now", "Packets per second passed by XDP.",
        [target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="pass"}}[{RI}]))', "passed", "A")],
        "pps", g(6, 0, 6, 4), colour=GOOD),
    stat("Dropped now", "Packets per second dropped by XDP.",
        [target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))', "dropped", "A")],
        "pps", g(12, 0, 6, 4), steps=[{"color": GOOD, "value": None}, {"color": CRITICAL, "value": 1}]),
    stat("Drop share", "Dropped packets as a share of incoming packets.",
         [target(f'clamp_max(sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))'
             f" / clamp_min(sum(rate(xs_rx_packets_total{{{IF}}}[{RI}])), 1e-9), 1)", "drop share", "A")],
        "percentunit", g(18, 0, 6, 4), decimals=2,
        steps=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 0.01}, {"color": CRITICAL, "value": 0.1}]),
    timeseries("Ingress and passed packets", "Incoming packets compared with the pass verdict over time.",
            [target(f"sum(rate(xs_rx_packets_total{{{IF}}}[{RI}]))", "incoming", "A"),
             target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="pass"}}[{RI}]))', "passed", "B")],
               "pps", g(0, 5, 16, 10), colours={"incoming": BLUE, "passed": GOOD}, dashed=("passed",)),
    timeseries("Dropped packets", "Drop rate on its own scale, so low-volume drops are easy to see.",
            [target(f'sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))', "dropped", "A")],
            "pps", g(16, 5, 8, 10), single=CRITICAL, bars=True),
    timeseries("Link traffic", "Incoming Ethernet throughput, excluding the frame check sequence.",
            [target(f"8 * sum(rate(xs_rx_bytes_total{{{IF}}}[{RI}]))", "incoming", "A")],
            "bps", g(0, 16, 12, 8), single=BLUE),
    timeseries("Dropped share over time", "Fraction of XDP ingress packets receiving a drop verdict.",
               [target(f'clamp_max(sum(rate(xs_verdict_packets_total{{{IF},verdict="drop"}}[{RI}]))'
                   f" / clamp_min(sum(rate(xs_rx_packets_total{{{IF}}}[{RI}])), 1e-9), 1)", "drop share", "A")],
            "percentunit", g(12, 16, 12, 8), single=ORANGE),
    stat("Packets received", "Cumulative frames seen by XDP.",
        [target(f"sum(xs_rx_packets_total{{{IF}}})", "received", "A")],
        "short", g(0, 25, 6, 4), colour=BLUE, graph=False, decimals=0),
    stat("Packets passed", "Cumulative frames passed by XDP.",
        [target(f'sum(xs_verdict_packets_total{{{IF},verdict="pass"}})', "passed", "A")],
        "short", g(6, 25, 6, 4), colour=GOOD, graph=False, decimals=0),
    stat("Packets dropped", "Cumulative frames dropped by XDP.",
        [target(f'sum(xs_verdict_packets_total{{{IF},verdict="drop"}})', "dropped", "A")],
        "short", g(12, 25, 6, 4), colour=CRITICAL, graph=False, decimals=0),
    stat("Bytes received", "Cumulative Ethernet bytes seen by XDP, excluding the frame check sequence.",
        [target(f"sum(xs_rx_bytes_total{{{IF}}})", "bytes", "A")],
        "bytes", g(18, 25, 6, 4), colour=BLUE, graph=False),
    timeseries("Protocol rates", "Fully parsed IP packets per second by transport protocol.",
        [target(f"sum by (proto) (rate(xs_l4_packets_total{{{IF}}}[{RI}]))", "{{proto}}", "A")],
        "pps", g(0, 30, 12, 8),
        colours={"tcp": BLUE, "udp": ORANGE, "icmp": AQUA, "icmpv6": YELLOW, "other": MAGENTA}),
    timeseries("TCP flag classes", "TCP segments per second grouped by flag class; SYN shows connection attempts.",
        [target(f"sum by (class) (rate(xs_tcp_flags_packets_total{{{IF}}}[{RI}]))", "{{class}}", "A")],
        "pps", g(12, 30, 12, 8),
        colours={"syn": BLUE, "synack": ORANGE, "ack": AQUA, "fin": YELLOW, "rst": MAGENTA}),
    timeseries("Malformed packet rates", "Packets per second with parser-classified malformed headers.",
        [target(f'sum by (outcome) (rate(xs_parse_outcome_packets_total{{{IF},class="malformed"}}[{RI}]))',
                "{{outcome}}", "A")],
        "pps", g(0, 39, 12, 8), single=CRITICAL),
    timeseries("Header anomalies", "Observed header anomalies per second; these are counted, not necessarily dropped.",
        [target(f"sum by (kind) (rate(xs_anomaly_packets_total{{{IF}}}[{RI}]))", "{{kind}}", "A")],
        "pps", g(12, 39, 12, 8),
        colours={"tcp_bad_flags": CRITICAL, "udp_len_mismatch": ORANGE,
                 "ipv4_options": BLUE, "land": MAGENTA}),
    timeseries("Fragment rates", "First and later IPv4/IPv6 fragments per second.",
        [target(f"sum by (kind) (rate(xs_fragment_packets_total{{{IF}}}[{RI}]))", "{{kind}}", "A")],
        "pps", g(0, 48, 12, 8), colours={"first": BLUE, "later": ORANGE}),
    stat("Mitigation flags", "1 = enabled. Enabled flags describe drop behavior; they do not indicate packets were dropped.",
        [target(f"max by (flag) (xs_config_flag{{{IF}}})", "{{flag}}", "A")],
        "none", g(12, 48, 12, 8), graph=False, text_mode="value_and_name",
        steps=[{"color": "#747c83", "value": None}, {"color": WARNING, "value": 1}],
        mappings=[{"type": "value", "options": {
            "0": {"text": "off", "index": 0}, "1": {"text": "ON", "index": 1}}}]),
]

dashboard = {
    "uid": "xdp-sentinel-dataplane",
    "title": "XDP Traffic and Drops",
    "description": "Live packet flow, dropped traffic, link throughput, and cumulative XDP verdicts.",
    "tags": ["xdp-sentinel", "xdp", "ddos"],
    "timezone": "browser",
    "editable": False,
    "graphTooltip": 1,  # shared crosshair
    "refresh": "5s",
    "time": {"from": "now-30m", "to": "now"},
    "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
    "schemaVersion": 41,
    "version": 1,
    "templating": {"list": [{
        "name": "iface", "label": "Interface", "type": "query", "datasource": DS,
        "query": {"query": "label_values(xs_rx_packets_total, iface)", "refId": "iface"},
        "definition": "label_values(xs_rx_packets_total, iface)",
        "refresh": 2, "includeAll": True, "allValue": ".*", "multi": True, "sort": 1,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
    }]},
    "annotations": {"list": []},
    "links": [],
    "panels": panels,
}

json.dump(dashboard, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
