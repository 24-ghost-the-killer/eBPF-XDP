//! Phase 6 feature extraction.
//!
//! Materialises the normative feature set of docs/feature-schema.md into a
//! fixed, ordered vector. Every batch, ClickHouse row and model artefact
//! carries [`schema_hash`], the SHA-256 of the canonical schema text, so a
//! model is only ever fed vectors whose schema it was trained on.
//!
//! What is derivable from the Phase 1-5 telemetry (counters, HLL, dport
//! histogram, sub-windows) is computed; features needing heavy-hitters (P5),
//! sampled-header reconstruction or long history are emitted as NaN, which is
//! the schema's explicit "missing" value (tree models handle it natively).

use crate::sha256;

/// One feature: stable name, provenance letter, and its definition. The order
/// of this table IS the vector order and feeds the schema hash; never reorder
/// or rename a released entry (append only).
#[derive(Clone, Copy, Debug)]
pub struct FeatureDef {
    pub name: &'static str,
    pub prov: char,
    pub def: &'static str,
}

macro_rules! f {
    ($name:literal, $prov:literal, $def:literal) => {
        FeatureDef { name: $name, prov: $prov, def: $def }
    };
}

/// The v1 feature schema, in vector order.
pub const SCHEMA: &[FeatureDef] = &[
    // volume
    f!("packets", 'C', "packets in window"),
    f!("bytes", 'C', "L2 bytes in window"),
    f!("pps", 'C', "packets / dt"),
    f!("bps", 'C', "8 * bytes / dt"),
    f!("drop_pps", 'C', "dropped packets / dt"),
    f!("pps_baseline_ratio", 'D', "pps / baseline_pps(scope, hour_of_week)"),
    // tcp
    f!("tcp_syn_rate", 'C', "SYN without ACK per s"),
    f!("tcp_synack_rate", 'C', "SYN+ACK per s"),
    f!("tcp_ack_rate", 'C', "pure ACK per s"),
    f!("tcp_rst_rate", 'C', "RST per s"),
    f!("tcp_fin_rate", 'C', "FIN per s"),
    f!("tcp_syn_ack_ratio", 'D', "syn / (ack + 1)"),
    f!("tcp_syn_share", 'D', "syn / (tcp + 1)"),
    f!("tcp_bad_flags_rate", 'C', "NULL/XMAS/SYN+FIN/... per s"),
    // udp / icmp / frag
    f!("udp_pps", 'C', "UDP packets per s"),
    f!("udp_bps", 'C', "UDP bits per s"),
    f!("udp_dport_top1_share", 'P', "share to the most-hit destination port"),
    f!("udp_len_mismatch_rate", 'C', "UDP length mismatches per s"),
    f!("icmp_pps", 'C', "ICMP+ICMPv6 per s"),
    f!("icmp_share", 'C', "icmp / packets"),
    f!("frag_rate", 'C', "fragments per s"),
    f!("frag_share", 'C', "fragments / packets"),
    // addresses / ports (cardinality)
    f!("unique_src", 'H', "distinct source addresses (HLL)"),
    f!("unique_flows", 'H', "distinct 5-tuples (HLL)"),
    f!("new_src", 'H', "sources not seen in the previous 10 s"),
    f!("flows_per_src", 'D', "unique_flows / unique_src"),
    f!("top1_src_share", 'C', "share from the top source (heavy hitters)"),
    f!("top10_src_share", 'C', "share from the top 10 sources"),
    f!("dport_entropy", 'P', "normalised entropy of the dport histogram"),
    // sizes
    f!("mean_pkt_size", 'C', "bytes / packets"),
    // protocol distribution / validity
    f!("share_tcp", 'C', "tcp / packets"),
    f!("share_udp", 'C', "udp / packets"),
    f!("share_icmp", 'C', "icmp / packets"),
    f!("share_other", 'C', "other L4 / packets"),
    f!("malformed_rate", 'C', "malformed packets per s"),
    f!("unsupported_rate", 'C', "unsupported packets per s"),
    // temporal
    f!("pps_accel", 'D', "(pps_t - pps_{t-1}) / dt"),
    f!("pps_zscore", 'D', "(pps - median) / (1.4826 * MAD)"),
    f!("burstiness_cv", 'C', "CV of the 10 x 100 ms sub-window counts"),
    f!("fano_factor", 'C', "variance / mean of sub-window counts"),
];

/// Number of features in the schema.
pub const N: usize = SCHEMA.len();

/// Schema version tag.
pub const SCHEMA_VERSION: &str = "v1";

/// Canonical schema text: one `name|prov|def` line per feature, version
/// header first. Deterministic, so its SHA-256 is stable across builds.
pub fn schema_canonical() -> String {
    let mut s = format!("feature_schema {SCHEMA_VERSION}\n");
    for d in SCHEMA {
        s.push_str(&format!("{}|{}|{}\n", d.name, d.prov, d.def));
    }
    s
}

/// The schema hash carried by every feature batch and model artefact.
pub fn schema_hash() -> String {
    sha256::hex(schema_canonical().as_bytes())
}

/// The schema as `ml/feature_schema/v1.yaml` text.
pub fn schema_yaml() -> String {
    let mut s = format!(
        "# xdp-sentinel feature schema {SCHEMA_VERSION}\n# schema_hash: {}\nversion: {SCHEMA_VERSION}\nfeatures:\n",
        schema_hash()
    );
    for d in SCHEMA {
        s.push_str(&format!(
            "  - name: {}\n    provenance: {}\n    definition: \"{}\"\n",
            d.name, d.prov, d.def
        ));
    }
    s
}

/// Raw per-window inputs, collected by the agent from the dataplane.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowInput {
    pub dt_s: f64,
    pub packets: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub tcp_syn: u64,
    pub tcp_synack: u64,
    pub tcp_ack: u64,
    pub tcp_rst: u64,
    pub tcp_fin: u64,
    pub tcp_bad_flags: u64,
    pub tcp_total: u64,
    pub udp: u64,
    pub udp_bytes: u64,
    pub udp_len_mismatch: u64,
    pub icmp: u64,
    /// IPv6-specific raw counts. NOT part of the model feature vector (SCHEMA) —
    /// they feed the rule-based IPv6 classifier only, so adding them never changes
    /// the schema hash and the trained models keep loading.
    pub ipv6: u64,
    pub icmpv6: u64,
    pub ipv6_ext: u64,
    pub frag: u64,
    pub other_l4: u64,
    pub malformed: u64,
    pub unsupported: u64,
    pub unique_src: f64,
    pub unique_flows: f64,
    pub new_src: f64,
    pub udp_dport_top1_share: f64,
    pub dport_entropy: f64,
    /// Ten 100 ms sub-window packet counts for burstiness/Fano.
    pub sub_counts: [u64; 10],
    /// Previous window's pps, for acceleration (NaN if none).
    pub prev_pps: f64,
    /// Robust baseline of pps for the same hour-of-week (median, MAD).
    pub baseline_pps: f64,
    pub baseline_mad: f64,
}

const NAN: f64 = f64::NAN;
fn ratio(x: f64, y: f64) -> f64 {
    x / (y + 1.0)
}

/// Compute the ordered feature vector for one window.
pub fn compute(w: &WindowInput) -> Vec<f64> {
    let dt = if w.dt_s > 0.0 { w.dt_s } else { 1.0 };
    let pk = w.packets as f64;
    let pps = pk / dt;
    let bps = 8.0 * w.bytes as f64 / dt;

    // sub-window burstiness (coefficient of variation) and Fano factor
    let (mean, var) = {
        let n = w.sub_counts.len() as f64;
        let m = w.sub_counts.iter().map(|&c| c as f64).sum::<f64>() / n;
        let v = w.sub_counts.iter().map(|&c| (c as f64 - m).powi(2)).sum::<f64>() / n;
        (m, v)
    };
    let burstiness_cv = if mean > 0.0 { var.sqrt() / mean } else { NAN };
    let fano = if mean > 0.0 { var / mean } else { NAN };

    let pps_accel = if w.prev_pps.is_nan() { NAN } else { (pps - w.prev_pps) / dt };
    let pps_zscore =
        if w.baseline_mad > 0.0 { (pps - w.baseline_pps) / (1.4826 * w.baseline_mad) } else { NAN };
    let baseline_ratio = if w.baseline_pps > 0.0 { pps / w.baseline_pps } else { NAN };

    let val = |name: &str| -> f64 {
        match name {
            "packets" => pk,
            "bytes" => w.bytes as f64,
            "pps" => pps,
            "bps" => bps,
            "drop_pps" => w.dropped as f64 / dt,
            "pps_baseline_ratio" => baseline_ratio,
            "tcp_syn_rate" => w.tcp_syn as f64 / dt,
            "tcp_synack_rate" => w.tcp_synack as f64 / dt,
            "tcp_ack_rate" => w.tcp_ack as f64 / dt,
            "tcp_rst_rate" => w.tcp_rst as f64 / dt,
            "tcp_fin_rate" => w.tcp_fin as f64 / dt,
            "tcp_syn_ack_ratio" => ratio(w.tcp_syn as f64, w.tcp_ack as f64),
            "tcp_syn_share" => ratio(w.tcp_syn as f64, w.tcp_total as f64),
            "tcp_bad_flags_rate" => w.tcp_bad_flags as f64 / dt,
            "udp_pps" => w.udp as f64 / dt,
            "udp_bps" => 8.0 * w.udp_bytes as f64 / dt,
            "udp_dport_top1_share" => w.udp_dport_top1_share,
            "udp_len_mismatch_rate" => w.udp_len_mismatch as f64 / dt,
            "icmp_pps" => w.icmp as f64 / dt,
            "icmp_share" => {
                if pk > 0.0 {
                    w.icmp as f64 / pk
                } else {
                    NAN
                }
            }
            "frag_rate" => w.frag as f64 / dt,
            "frag_share" => {
                if pk > 0.0 {
                    w.frag as f64 / pk
                } else {
                    NAN
                }
            }
            "unique_src" => w.unique_src,
            "unique_flows" => w.unique_flows,
            "new_src" => w.new_src,
            "flows_per_src" => {
                if w.unique_src > 0.0 {
                    w.unique_flows / w.unique_src
                } else {
                    NAN
                }
            }
            "top1_src_share" => NAN, // needs heavy hitters (Phase 5 refinement)
            "top10_src_share" => NAN,
            "dport_entropy" => w.dport_entropy,
            "mean_pkt_size" => {
                if pk > 0.0 {
                    w.bytes as f64 / pk
                } else {
                    NAN
                }
            }
            "share_tcp" => {
                if pk > 0.0 {
                    w.tcp_total as f64 / pk
                } else {
                    NAN
                }
            }
            "share_udp" => {
                if pk > 0.0 {
                    w.udp as f64 / pk
                } else {
                    NAN
                }
            }
            "share_icmp" => {
                if pk > 0.0 {
                    w.icmp as f64 / pk
                } else {
                    NAN
                }
            }
            "share_other" => {
                if pk > 0.0 {
                    w.other_l4 as f64 / pk
                } else {
                    NAN
                }
            }
            "malformed_rate" => w.malformed as f64 / dt,
            "unsupported_rate" => w.unsupported as f64 / dt,
            "pps_accel" => pps_accel,
            "pps_zscore" => pps_zscore,
            "burstiness_cv" => burstiness_cv,
            "fano_factor" => fano,
            _ => NAN,
        }
    };
    SCHEMA.iter().map(|d| val(d.name)).collect()
}

/// Index of a named feature in the vector (for consumers).
pub fn index_of(name: &str) -> Option<usize> {
    SCHEMA.iter().position(|d| d.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_hash_is_stable_and_hex() {
        let h = schema_hash();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // deterministic
        assert_eq!(h, schema_hash());
    }

    #[test]
    fn vector_length_matches_schema() {
        let v = compute(&WindowInput { dt_s: 1.0, ..Default::default() });
        assert_eq!(v.len(), N);
        assert_eq!(SCHEMA.len(), N);
    }

    #[test]
    fn syn_flood_signature() {
        // 100k SYN, few ACK: high syn rate, high syn/ack ratio, high syn share.
        let w = WindowInput {
            dt_s: 1.0,
            packets: 100_000,
            tcp_syn: 100_000,
            tcp_ack: 10,
            tcp_total: 100_010,
            ..Default::default()
        };
        let v = compute(&w);
        let syn_rate = v[index_of("tcp_syn_rate").unwrap()];
        let ratio = v[index_of("tcp_syn_ack_ratio").unwrap()];
        let share = v[index_of("tcp_syn_share").unwrap()];
        assert!((syn_rate - 100_000.0).abs() < 1.0);
        assert!(ratio > 9000.0);
        assert!(share > 0.99);
    }

    #[test]
    fn missing_is_nan_not_zero() {
        let v = compute(&WindowInput { dt_s: 1.0, packets: 0, ..Default::default() });
        assert!(v[index_of("mean_pkt_size").unwrap()].is_nan());
        assert!(v[index_of("top1_src_share").unwrap()].is_nan());
    }

    #[test]
    fn burstiness_flat_vs_spiky() {
        let flat =
            WindowInput { dt_s: 1.0, sub_counts: [100; 10], packets: 1000, ..Default::default() };
        let mut spiky = flat;
        spiky.sub_counts = [1000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cv_flat = compute(&flat)[index_of("burstiness_cv").unwrap()];
        let cv_spiky = compute(&spiky)[index_of("burstiness_cv").unwrap()];
        assert!(cv_flat < 0.01);
        assert!(cv_spiky > cv_flat);
    }
}
