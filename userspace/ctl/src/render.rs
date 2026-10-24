//! Human and JSON rendering of counter snapshots (platform independent).

use serde_json::{json, Map, Value};
use xs_common::abi::COUNTERS;
use xs_common::Snapshot;

/// Render a snapshot as a table. With `interval_s`, `snap` is a delta and
/// rates are shown.
#[allow(dead_code)] // unused on non-Linux builds
pub fn table(iface: &str, snap: &Snapshot, interval_s: Option<f64>, all: bool) -> String {
    let mut out = String::new();
    match interval_s {
        Some(dt) => out.push_str(&format!("interface {iface}: last {dt:.2}s\n")),
        None => out.push_str(&format!("interface {iface}: cumulative since map creation\n")),
    }
    out.push_str(&format!("{:<28} {:>16} {:>18}", "counter", "packets", "bytes"));
    if interval_s.is_some() {
        out.push_str(&format!(" {:>14} {:>12}", "pps", "Mbit/s"));
    }
    out.push('\n');
    for def in COUNTERS {
        let c = snap.get(def.slot);
        if !all && c.packets == 0 {
            continue;
        }
        out.push_str(&format!("{:<28} {:>16} {:>18}", def.name, c.packets, c.bytes));
        if let Some(dt) = interval_s {
            let pps = c.packets as f64 / dt;
            let mbps = c.bytes as f64 * 8.0 / dt / 1e6;
            out.push_str(&format!(" {:>14.0} {:>12.2}", pps, mbps));
        }
        out.push('\n');
    }
    out
}

/// Render a snapshot as a JSON object keyed by stable counter names.
#[allow(dead_code)] // unused on non-Linux builds
pub fn json(iface: &str, snap: &Snapshot, interval_s: Option<f64>, unix_ms: u128) -> Value {
    let mut counters = Map::new();
    for def in COUNTERS {
        let c = snap.get(def.slot);
        let mut v = json!({ "packets": c.packets, "bytes": c.bytes });
        if let Some(dt) = interval_s {
            v["pps"] = json!(c.packets as f64 / dt);
            v["bps"] = json!(c.bytes as f64 * 8.0 / dt);
        }
        counters.insert(def.name.to_string(), v);
    }
    json!({
        "iface": iface,
        "timestamp_unix_ms": unix_ms,
        "interval_s": interval_s,
        "counters": counters,
    })
}

/// Re-exported from the shared crate so `render::prometheus` keeps working.
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))] // only used by linux.rs
pub use xs_common::metrics::prometheus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_hides_zero_rows() {
        let snap = Snapshot::default();
        let t = table("eth0", &snap, None, false);
        assert_eq!(t.lines().count(), 2); // title + header
        let t = table("eth0", &snap, None, true);
        assert_eq!(t.lines().count(), 2 + COUNTERS.len());
    }

    #[test]
    fn json_has_every_counter() {
        let v = json("eth0", &Snapshot::default(), Some(1.0), 0);
        assert_eq!(v["counters"].as_object().unwrap().len(), COUNTERS.len());
        assert_eq!(v["counters"]["rx"]["pps"], 0.0);
    }
}
