//! Prometheus text-format rendering of dataplane counters, shared by
//! `sentinelctl` (textfile exporter) and `sentinel-agent` (`/metrics`).
//!
//! Metric names follow docs/observability.md: one family per counter group,
//! the member encoded as a label, `_packets_total` / `_bytes_total` suffixes.
//! Every label value comes from the static counter table, never from packet
//! contents, so metric cardinality is fixed and bounded.

use std::fmt::Write;

use crate::abi::{parse_class, ParseClass, CNT_PARSE_BASE, COUNTERS};
use crate::Snapshot;

/// Map a counter name to its Prometheus family and optional `(label, value)`.
pub fn prom_family(name: &str) -> (&'static str, Option<(&'static str, &str)>) {
    const GROUPS: &[(&str, &str, &str)] = &[
        ("verdict_", "verdict", "verdict"),
        ("l2_vlan", "vlan", "tags"),
        ("l3_", "l3", "proto"),
        ("l4_", "l4", "proto"),
        ("frag_", "fragment", "kind"),
        ("tcp_", "tcp_flags", "class"),
        ("anom_", "anomaly", "kind"),
        ("parse_", "parse_outcome", "outcome"),
        // Phase 2/3 policy sub-counters -> one family, event = drop|expired|pass|rate_limited.
        ("policy_", "policy_event", "event"),
        ("allow_", "policy_event", "event"),
    ];
    for (prefix, family, label) in GROUPS {
        if let Some(rest) = name.strip_prefix(prefix) {
            return (family, Some((label, rest)));
        }
    }
    match name {
        "rx" => ("rx", None),
        "ipv6_ext" => ("ipv6_ext", None),
        "rate_limited" => ("policy_event", Some(("event", "rate_limited"))),
        "rate_tracked" => ("rate_tracked", None),
        // Phase 5 sampling accounting.
        "sampled" => ("sample", Some(("event", "taken"))),
        "sample_drop" => ("sample", Some(("event", "dropped"))),
        // Connection tracking: untracked TCP (ACK/RST flood).
        "ct_untracked" => ("conntrack", Some(("event", "untracked"))),
        // Every counter has a family (enforced by a test); keep a sane
        // fallback rather than panicking in an exporter.
        _ => ("other", Some(("counter", name))),
    }
}

const PROM_HELP: &[(&str, &str)] = &[
    ("rx", "Frames seen by the XDP program"),
    ("verdict", "Frames by final XDP verdict"),
    ("vlan", "Frames by number of VLAN tags present in the frame"),
    ("l3", "Frames by L3 protocol (valid header)"),
    ("l4", "Fully parsed IP packets by transport protocol"),
    ("fragment", "IPv4/IPv6 fragments (first = carries L4 header)"),
    ("ipv6_ext", "IPv6 packets with at least one extension header"),
    ("tcp_flags", "TCP segments by flag class"),
    ("anomaly", "Header anomalies on parseable packets"),
    ("parse_outcome", "Parser outcome; exactly one per frame (class: ok, unsupported, malformed)"),
    (
        "policy_event",
        "Phase 2/3 policy actions (event: drop = blocked, expired = TTL lapsed, pass = allowlisted, rate_limited)",
    ),
    ("rate_tracked", "IP packets evaluated by the per-source rate limiter"),
    ("sample", "Phase 5 header sampling (event: taken = to ring buffer, dropped = reserve failed)"),
    ("conntrack", "Connection tracking: TCP packets with no matching flow (ACK/RST flood)"),
    ("other", "Unmapped counters"),
];

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// Render one interface's cumulative counters in the Prometheus text
/// exposition format. Samples of a family are contiguous with a single
/// HELP/TYPE header, as the format requires. `attached_mode` is one of
/// "native", "generic", "offload", "none".
pub fn prometheus(
    iface: &str,
    snap: &Snapshot,
    attached_mode: &str,
    flags: &[(&str, bool)],
) -> String {
    let iface = escape_label(iface);
    let mut out = String::new();
    let mut families: Vec<&'static str> = Vec::new();
    for def in COUNTERS {
        let (fam, _) = prom_family(def.name);
        if !families.contains(&fam) {
            families.push(fam);
        }
    }
    for unit in ["packets", "bytes"] {
        for fam in &families {
            let metric = format!("xs_{fam}_{unit}_total");
            let help = PROM_HELP.iter().find(|(f, _)| f == fam).map(|(_, h)| *h).unwrap_or("");
            let _ = writeln!(out, "# HELP {metric} {help} ({unit}).");
            let _ = writeln!(out, "# TYPE {metric} counter");
            for def in COUNTERS {
                let (f, label) = prom_family(def.name);
                if f != *fam {
                    continue;
                }
                let c = snap.get(def.slot);
                let v = if unit == "packets" { c.packets } else { c.bytes };
                let mut labels = format!("iface=\"{iface}\"");
                if let Some((k, val)) = label {
                    let _ = write!(labels, ",{k}=\"{}\"", escape_label(val));
                }
                if *fam == "parse_outcome" {
                    let class = match parse_class(def.slot - CNT_PARSE_BASE) {
                        ParseClass::Ok => "ok",
                        ParseClass::Unsupported => "unsupported",
                        ParseClass::Malformed => "malformed",
                    };
                    let _ = write!(labels, ",class=\"{class}\"");
                }
                let _ = writeln!(out, "{metric}{{{labels}}} {v}");
            }
        }
    }
    let _ = writeln!(
        out,
        "# HELP xs_dataplane_attached 1 if the xdp-sentinel program is attached, by XDP mode."
    );
    let _ = writeln!(out, "# TYPE xs_dataplane_attached gauge");
    let attached = u8::from(attached_mode != "none");
    let _ = writeln!(
        out,
        "xs_dataplane_attached{{iface=\"{iface}\",mode=\"{}\"}} {attached}",
        escape_label(attached_mode)
    );
    let _ = writeln!(out, "# HELP xs_config_flag Dataplane config flags (1 = enabled).");
    let _ = writeln!(out, "# TYPE xs_config_flag gauge");
    for (name, on) in flags {
        let _ =
            writeln!(out, "xs_config_flag{{iface=\"{iface}\",flag=\"{name}\"}} {}", u8::from(*on));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_counter_has_a_family() {
        for def in COUNTERS {
            assert_ne!(prom_family(def.name).0, "other", "{} unmapped", def.name);
        }
        assert_eq!(prom_family("verdict_drop"), ("verdict", Some(("verdict", "drop"))));
        assert_eq!(prom_family("rate_limited"), ("policy_event", Some(("event", "rate_limited"))));
    }

    #[test]
    fn families_contiguous_with_one_header() {
        let text = prometheus("eth0", &Snapshot::default(), "native", &[("drop_malformed", true)]);
        let mut seen_type = std::collections::HashSet::new();
        let mut closed = std::collections::HashSet::new();
        let mut last = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split_whitespace().next().unwrap().to_string();
                assert!(seen_type.insert(name), "duplicate TYPE: {line}");
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let metric = line.split('{').next().unwrap().to_string();
            if metric != last {
                assert!(closed.insert(last.clone()), "family {metric} not contiguous");
                last = metric;
            }
        }
        assert!(text.contains("xs_rx_packets_total{iface=\"eth0\"} 0"));
        assert!(text.contains(r#"xs_dataplane_attached{iface="eth0",mode="native"} 1"#));
        assert!(text.contains(r#"xs_config_flag{iface="eth0",flag="drop_malformed"} 1"#));
    }
}
