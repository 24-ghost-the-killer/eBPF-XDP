//! Phase 9 statistical baseline detector.
//!
//! Deterministic, model-free attack detection over the Phase 6 feature vectors:
//!
//!   * [`RobustBaseline`]: per-feature streaming median + MAD, so a robust
//!     z-score `(x - median) / (1.4826 * MAD)` flags any feature that departs
//!     from its recent normal range without being skewed by the outliers it is
//!     meant to catch. The baseline only learns from windows judged normal.
//!   * [`Cusum`]: a one-sided CUSUM on the pps z-score catches slow, sustained
//!     ramps that never trip a single-window threshold.
//!   * deterministic rules: absolute traffic-shape signatures that name the
//!     attack type (SYN flood, UDP reflection, fragment flood, ...).
//!
//! A window is anomalous if the robust score crosses `z_threshold`, the CUSUM
//! alarms, or a rule fires. The high z-threshold keeps the clean-traffic false
//! positive rate low (Phase 9 exit criterion); [`tests::clean_fpr_is_low`]
//! checks it on noisy benign windows.

use std::collections::VecDeque;

use crate::features::index_of;

/// Attack types the rules can name (mirror of ml/attacks/profiles.py labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackType {
    SynFlood,
    AckFlood,
    RstFlood,
    FinFlood,
    UdpFlood,
    UdpReflection,
    IcmpFlood,
    FragFlood,
    MalformedFlood,
    ConnectionFlood,
    DnsAmplification,
    Ipv6Flood,
    Icmpv6Flood,
    Ipv6ExtFlood,
}

impl AttackType {
    pub fn as_str(self) -> &'static str {
        match self {
            AttackType::SynFlood => "syn_flood",
            AttackType::AckFlood => "ack_flood",
            AttackType::RstFlood => "rst_flood",
            AttackType::FinFlood => "fin_flood",
            AttackType::UdpFlood => "udp_flood",
            AttackType::UdpReflection => "udp_reflection",
            AttackType::IcmpFlood => "icmp_flood",
            AttackType::FragFlood => "frag_flood",
            AttackType::MalformedFlood => "malformed_flood",
            AttackType::ConnectionFlood => "connection_flood",
            AttackType::DnsAmplification => "dns_amplification",
            AttackType::Ipv6Flood => "ipv6_flood",
            AttackType::Icmpv6Flood => "icmpv6_flood",
            AttackType::Ipv6ExtFlood => "ipv6_ext_flood",
        }
    }
}

/// IPv6-specific classification from raw counts, kept OUT of the model feature
/// vector (so it never changes the schema hash). Called alongside `classify`;
/// when it fires it refines a generic result into the precise IPv6 attack type.
/// Returns None for non-IPv6-dominant traffic so the normal path is used.
pub fn classify_ipv6(wi: &crate::features::WindowInput) -> Option<AttackType> {
    let pkts = wi.packets as f64;
    if pkts < 1.0 || (wi.ipv6 as f64) < 0.5 * pkts {
        return None; // not IPv6-dominant
    }
    // Extension-header flood: a large share of IPv6 packets carry ext headers
    // (rare in normal traffic). Most specific, so checked first.
    if (wi.ipv6_ext as f64) > 0.4 * (wi.ipv6 as f64) {
        return Some(AttackType::Ipv6ExtFlood);
    }
    // ICMPv6 flood: ICMPv6 dominates (it is also counted in `icmp`, so without
    // this it would mislabel as a generic icmp_flood).
    if (wi.icmpv6 as f64) > 0.6 * pkts {
        return Some(AttackType::Icmpv6Flood);
    }
    // Generic IPv6 volumetric flood (not TCP/UDP/ICMP-shaped enough to name).
    Some(AttackType::Ipv6Flood)
}

/// A window's detection result.
#[derive(Clone, Debug)]
pub struct Detection {
    pub anomalous: bool,
    /// Robust anomaly score = max |z| over the monitored features.
    pub score: f64,
    pub cusum_alarm: bool,
    pub suspected: Option<AttackType>,
    pub reasons: Vec<String>,
}

/// Streaming per-feature robust baseline over a fixed window of recent values.
#[derive(Debug)]
pub struct RobustBaseline {
    windows: Vec<VecDeque<f64>>,
    cap: usize,
}

impl RobustBaseline {
    pub fn new(n_features: usize, cap: usize) -> Self {
        RobustBaseline {
            windows: (0..n_features).map(|_| VecDeque::with_capacity(cap)).collect(),
            cap: cap.max(8),
        }
    }

    fn median_mad(vals: &VecDeque<f64>) -> Option<(f64, f64)> {
        let mut v: Vec<f64> = vals.iter().copied().filter(|x| x.is_finite()).collect();
        if v.len() < 8 {
            return None;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let med = v[v.len() / 2];
        let mut dev: Vec<f64> = v.iter().map(|x| (x - med).abs()).collect();
        dev.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Some((med, dev[dev.len() / 2]))
    }

    /// Robust z-score of feature `i` for value `x` (NaN where no baseline yet).
    pub fn zscore_at(&self, i: usize, x: f64) -> f64 {
        if !x.is_finite() || i >= self.windows.len() {
            return f64::NAN;
        }
        match Self::median_mad(&self.windows[i]) {
            Some((med, mad)) if mad > 1e-9 => (x - med) / (1.4826 * mad),
            // MAD == 0 (a constant feature): any change is a strong signal.
            Some((med, _)) => {
                if (x - med).abs() > 1e-9 {
                    f64::INFINITY
                } else {
                    0.0
                }
            }
            None => f64::NAN,
        }
    }

    /// Robust z-scores for a whole feature vector (NaN where no baseline yet).
    pub fn zscores(&self, vec: &[f64]) -> Vec<f64> {
        vec.iter().enumerate().map(|(i, &x)| self.zscore_at(i, x)).collect()
    }

    /// Fold a window into the baseline (only call for windows judged normal).
    pub fn learn(&mut self, vec: &[f64]) {
        for (i, &x) in vec.iter().enumerate() {
            if !x.is_finite() {
                continue;
            }
            let w = &mut self.windows[i];
            if w.len() == self.cap {
                w.pop_front();
            }
            w.push_back(x);
        }
    }
}

/// One-sided CUSUM for a standardised signal (detects sustained upward shift).
#[derive(Clone, Debug)]
pub struct Cusum {
    s: f64,
    k: f64, // slack (allowance)
    h: f64, // decision threshold
}

impl Cusum {
    pub fn new(k: f64, h: f64) -> Self {
        Cusum { s: 0.0, k, h }
    }
    /// Feed a standardised value; returns true while in alarm.
    pub fn update(&mut self, z: f64) -> bool {
        if !z.is_finite() {
            return self.s > self.h;
        }
        self.s = (self.s + z - self.k).max(0.0);
        self.s > self.h
    }
    pub fn reset(&mut self) {
        self.s = 0.0;
    }
}

fn get(vec: &[f64], name: &str) -> f64 {
    index_of(name).map(|i| vec[i]).unwrap_or(f64::NAN)
}

/// Deterministic traffic-shape rules. Returns the strongest matching type.
pub fn classify(vec: &[f64]) -> Option<AttackType> {
    let f = |n: &str| get(vec, n);
    let syn_share = f("tcp_syn_share");
    let syn_ack = f("tcp_syn_ack_ratio");
    let share_tcp = f("share_tcp");
    let share_udp = f("share_udp");
    let share_icmp = f("share_icmp");
    let frag_share = f("frag_share");
    let malformed = f("malformed_rate");
    let pps = f("pps");
    let mean_size = f("mean_pkt_size");
    let dport_top1 = f("udp_dport_top1_share");
    let dport_entropy = f("dport_entropy");
    let flows_per_src = f("flows_per_src");
    let ack_rate = f("tcp_ack_rate");
    let rst_rate = f("tcp_rst_rate");
    let fin_rate = f("tcp_fin_rate");
    let bad_flags_rate = f("tcp_bad_flags_rate");

    // Order matters: most specific first.
    if malformed.is_finite() && malformed > 1000.0 {
        return Some(AttackType::MalformedFlood);
    }
    if frag_share.is_finite() && frag_share > 0.4 {
        return Some(AttackType::FragFlood);
    }
    if share_icmp.is_finite() && share_icmp > 0.6 {
        return Some(AttackType::IcmpFlood);
    }
    if share_udp.is_finite() && share_udp > 0.7 {
        if mean_size.is_finite() && mean_size > 1200.0 && dport_top1 > 0.9 {
            return Some(AttackType::DnsAmplification);
        }
        if mean_size.is_finite() && mean_size > 1000.0 && dport_top1 > 0.8 {
            return Some(AttackType::UdpReflection);
        }
        if dport_entropy.is_finite() && dport_entropy < 0.25 {
            return Some(AttackType::UdpFlood);
        }
        return Some(AttackType::UdpFlood);
    }
    if share_tcp.is_finite() && share_tcp > 0.8 {
        if syn_share > 0.6 && syn_ack > 8.0 {
            return Some(AttackType::SynFlood);
        }
        if flows_per_src.is_finite() && flows_per_src > 50.0 && syn_share > 0.3 {
            return Some(AttackType::ConnectionFlood);
        }
        // TCP-dominant flood with few SYNs = a non-handshake flag flood. Pick the
        // dominant flag class by its per-second rate (generalized TCP flag engine,
        // rather than a hard-coded rule per combination). A flood of impossible
        // flag combinations (NULL/XMAS/SYN+FIN/...) shows up as tcp_bad_flags and
        // is treated as malformed. RST- and FIN-dominant floods are named
        // explicitly; anything else non-SYN falls back to the ACK/untracked case.
        // All three are mitigated the same safe way (conntrack drop_untracked +
        // rate limit), so misattribution between them never breaks real TCP.
        if syn_share < 0.2 {
            let rates = [
                (AttackType::AckFlood, ack_rate),
                (AttackType::RstFlood, rst_rate),
                (AttackType::FinFlood, fin_rate),
                (AttackType::MalformedFlood, bad_flags_rate),
            ];
            let dominant = rates
                .iter()
                .filter(|(_, r)| r.is_finite() && *r > 0.0)
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            return Some(dominant.map(|(t, _)| *t).unwrap_or(AttackType::AckFlood));
        }
    }
    let _ = pps;
    None
}

/// The Phase 9 detector: robust baseline + CUSUM on pps + rules.
#[derive(Debug)]
pub struct Detector {
    baseline: RobustBaseline,
    cusum_pps: Cusum,
    z_threshold: f64,
    /// Features whose deviation counts toward the anomaly score.
    monitored: Vec<usize>,
    /// Windows to keep baseline learning frozen after any elevation, so a slow
    /// ramp ("boiling frog") cannot be absorbed into the baseline as normal.
    learn_freeze: u32,
}

impl Detector {
    pub fn new(n_features: usize) -> Self {
        // Count/rate features only. Ratios (syn/ack, entropies) and cardinality
        // swing wildly at a few packets per window, so they are NOT part of the
        // anomaly score -- they were the source of false z-spikes at idle.
        let monitored = [
            "pps",
            "bps",
            "tcp_syn_rate",
            "udp_pps",
            "icmp_pps",
            "frag_rate",
            "malformed_rate",
        ]
        .iter()
        .filter_map(|n| index_of(n))
        .collect();
        Detector {
            baseline: RobustBaseline::new(n_features, 256),
            // k=0.5 sigma slack, h=8 sigma cumulative: slow ramps, low FPR.
            cusum_pps: Cusum::new(0.5, 8.0),
            z_threshold: 8.0,
            monitored,
            learn_freeze: 0,
        }
    }

    /// Warm the baseline with a window known to be benign (bootstrap).
    pub fn observe_normal(&mut self, vec: &[f64]) {
        self.baseline.learn(vec);
    }

    /// Evaluate one window. Learns from it only if it is judged normal, so an
    /// attack cannot poison the baseline.
    pub fn detect(&mut self, vec: &[f64]) -> Detection {
        // Only the monitored features (plus pps) need a robust z-score.
        let mut score = 0.0f64;
        for &i in &self.monitored {
            let zi = self.baseline.zscore_at(i, vec[i]).abs();
            if zi.is_finite() && zi > score {
                score = zi;
            }
        }
        let pps_z = index_of("pps").map(|i| self.baseline.zscore_at(i, vec[i])).unwrap_or(f64::NAN);
        let cusum_alarm = self.cusum_pps.update(if pps_z.is_finite() { pps_z } else { 0.0 });
        let suspected = classify(vec);

        let mut reasons = Vec::new();
        if score > self.z_threshold {
            reasons.push(format!("robust z-score {score:.1} > {:.0}", self.z_threshold));
        }
        if cusum_alarm {
            reasons.push("CUSUM: sustained pps ramp".to_string());
        }
        if let Some(t) = suspected {
            reasons.push(format!("rule: {} signature", t.as_str()));
        }
        // A rule match (traffic-shape signature) only counts as a detection
        // when the window is also statistically elevated -- otherwise a benign
        // UDP-heavy or SYN-heavy moment at idle would be flagged as an attack.
        let rule_confirmed = suspected.is_some() && (score > self.z_threshold / 2.0 || cusum_alarm);
        let anomalous = score > self.z_threshold || cusum_alarm || rule_confirmed;

        // Freeze baseline learning for a while after any elevation, so a slow
        // upward ramp cannot be gradually learned as the new "normal".
        if score > self.z_threshold / 2.0 || cusum_alarm {
            self.learn_freeze = 60;
        } else if self.learn_freeze > 0 {
            self.learn_freeze -= 1;
        }
        // Learn only from clearly-normal windows, and only when not frozen.
        if !anomalous && self.learn_freeze == 0 && score < self.z_threshold / 2.0 {
            self.baseline.learn(vec);
        }
        Detection { anomalous, score, cusum_alarm, suspected, reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::{self, WindowInput};

    // Build a benign window with small random-free variation via a seed.
    fn benign(seed: u64) -> Vec<f64> {
        let r = ((seed.wrapping_mul(2654435761)) % 100) as f64 / 100.0; // 0..1
        features::compute(&WindowInput {
            dt_s: 1.0,
            packets: (380.0 + 40.0 * r) as u64,
            bytes: (380.0 * 640.0) as u64,
            tcp_syn: 30,
            tcp_ack: 210,
            tcp_total: 280,
            udp: 100,
            icmp: 8,
            unique_src: 120.0,
            unique_flows: 300.0,
            dport_entropy: 0.55,
            sub_counts: [38, 40, 39, 41, 40, 38, 42, 39, 40, 41],
            ..Default::default()
        })
    }

    fn syn_flood() -> Vec<f64> {
        features::compute(&WindowInput {
            dt_s: 1.0,
            packets: 200_000,
            bytes: 200_000 * 60,
            tcp_syn: 195_000,
            tcp_ack: 20,
            tcp_total: 199_000,
            udp: 500,
            unique_src: 5000.0,
            unique_flows: 50000.0,
            dport_entropy: 0.05,
            sub_counts: [20000; 10],
            ..Default::default()
        })
    }

    fn udp_reflection() -> Vec<f64> {
        features::compute(&WindowInput {
            dt_s: 1.0,
            packets: 80_000,
            bytes: 80_000 * 1400,
            udp: 79_000,
            udp_bytes: 79_000 * 1400,
            tcp_total: 500,
            unique_src: 800.0,
            unique_flows: 4000.0,
            udp_dport_top1_share: 0.9,
            dport_entropy: 0.1,
            sub_counts: [8000; 10],
            ..Default::default()
        })
    }

    fn warm(d: &mut Detector) {
        for s in 0..300 {
            d.observe_normal(&benign(s));
        }
    }

    fn tcp_flag_flood(syn: u64, ack: u64, rst: u64, fin: u64, bad: u64) -> Vec<f64> {
        let total = syn + ack + rst + fin + bad + 100;
        features::compute(&WindowInput {
            dt_s: 1.0,
            packets: total,
            bytes: total * 60,
            tcp_syn: syn,
            tcp_ack: ack,
            tcp_rst: rst,
            tcp_fin: fin,
            tcp_bad_flags: bad,
            tcp_total: total,
            unique_src: 5000.0,
            unique_flows: 50000.0,
            sub_counts: [(total / 10).max(1); 10],
            ..Default::default()
        })
    }

    #[test]
    fn classify_signatures() {
        assert_eq!(classify(&syn_flood()), Some(AttackType::SynFlood));
        assert_eq!(classify(&udp_reflection()), Some(AttackType::UdpReflection));
        assert_eq!(classify(&benign(7)), None);
    }

    #[test]
    fn ipv6_classifier() {
        let base = |ipv6, icmpv6, ext| WindowInput {
            dt_s: 1.0, packets: 100_000, bytes: 100_000 * 80,
            ipv6, icmpv6, ipv6_ext: ext, sub_counts: [10_000; 10], ..Default::default()
        };
        // ICMPv6 flood: IPv6-dominant, ICMPv6 dominates.
        assert_eq!(classify_ipv6(&base(99_000, 98_000, 0)), Some(AttackType::Icmpv6Flood));
        // Extension-header flood: most IPv6 packets carry ext headers.
        assert_eq!(classify_ipv6(&base(99_000, 0, 90_000)), Some(AttackType::Ipv6ExtFlood));
        // Generic IPv6 volumetric.
        assert_eq!(classify_ipv6(&base(99_000, 0, 0)), Some(AttackType::Ipv6Flood));
        // Not IPv6-dominant -> None (normal path handles it).
        assert_eq!(classify_ipv6(&base(1_000, 0, 0)), None);
    }

    #[test]
    fn generalized_tcp_flag_engine() {
        // Each non-SYN TCP flood is named by its dominant flag class.
        assert_eq!(classify(&tcp_flag_flood(10, 190_000, 10, 10, 0)), Some(AttackType::AckFlood));
        assert_eq!(classify(&tcp_flag_flood(10, 10, 190_000, 10, 0)), Some(AttackType::RstFlood));
        assert_eq!(classify(&tcp_flag_flood(10, 10, 10, 190_000, 0)), Some(AttackType::FinFlood));
        // A flood of impossible flag combos (NULL/XMAS/SYN+FIN) -> malformed.
        assert_eq!(classify(&tcp_flag_flood(10, 10, 10, 10, 190_000)), Some(AttackType::MalformedFlood));
        // A real SYN flood is still a SYN flood, not caught by the flag engine.
        assert_eq!(classify(&syn_flood()), Some(AttackType::SynFlood));
    }

    #[test]
    fn detects_attacks() {
        let mut d = Detector::new(features::N);
        warm(&mut d);
        let syn = d.detect(&syn_flood());
        assert!(syn.anomalous);
        assert_eq!(syn.suspected, Some(AttackType::SynFlood));
        let refl = d.detect(&udp_reflection());
        assert!(refl.anomalous);
        assert_eq!(refl.suspected, Some(AttackType::UdpReflection));
    }

    #[test]
    fn clean_fpr_is_low() {
        let mut d = Detector::new(features::N);
        warm(&mut d);
        let mut fp = 0;
        let n = 5000;
        for s in 1000..(1000 + n) {
            if d.detect(&benign(s)).anomalous {
                fp += 1;
            }
        }
        // Benign windows should almost never be flagged.
        assert!(fp <= n / 100, "false positives {fp}/{n}");
    }
}
