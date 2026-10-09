//! Phase 5 flow-aggregation, userspace side (algorithms only; the agent wires
//! these to the BPF maps and ring buffer).
//!
//! * [`Hll`]: merges per-CPU HyperLogLog registers (element-wise max) and
//!   estimates cardinality (unique sources / flows) with bias correction.
//! * [`Sample`]: decodes one `struct xs_sample` from the ring buffer.
//! * [`FlowTable`]: reconstructs flows from samples, with `last_seen` eviction.
//! * [`dport`]: top-1 share and normalised entropy of the exact port histogram.
//!
//! Nothing here is Linux-specific, so it is unit-tested on any host.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// HyperLogLog precision `p` (mirror of `XS_HLL_P`): 2^p registers.
pub const HLL_P: u32 = 12;
/// Number of registers per sketch (`XS_HLL_REGISTERS`).
pub const HLL_REGISTERS: usize = 1 << HLL_P;

/// Sketch indices, mirror of `enum xs_hll_sketch`.
pub const HLL_SRC: usize = 0;
pub const HLL_FLOW: usize = 1;
pub const HLL_N: usize = 2;
pub const HLL_EPOCHS: usize = 2;

/// A merged HyperLogLog register bank for one sketch/epoch.
#[derive(Clone, Debug)]
pub struct Hll {
    regs: Vec<u8>,
}

impl Default for Hll {
    fn default() -> Self {
        Hll { regs: vec![0u8; HLL_REGISTERS] }
    }
}

impl Hll {
    /// Merge one CPU's registers for a given epoch/sketch into this bank.
    /// `flat` is the whole flattened `struct xs_hll` for one CPU
    /// (`XS_HLL_EPOCHS * XS_HLL_N * XS_HLL_REGISTERS` bytes).
    pub fn merge_cpu(&mut self, flat: &[u8], epoch: usize, sketch: usize) {
        let base = (epoch * HLL_N + sketch) * HLL_REGISTERS;
        let Some(slice) = flat.get(base..base + HLL_REGISTERS) else { return };
        for (r, &v) in self.regs.iter_mut().zip(slice) {
            if v > *r {
                *r = v;
            }
        }
    }

    /// Estimate the cardinality. Raw HLL estimator with the standard
    /// small-range (linear counting) correction; the 1.6% error at p=12 makes
    /// the large-range (2^32) correction irrelevant for a single interface.
    pub fn estimate(&self) -> f64 {
        let m = HLL_REGISTERS as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &r in &self.regs {
            sum += 2f64.powi(-(r as i32));
            if r == 0 {
                zeros += 1;
            }
        }
        let raw = alpha * m * m / sum;
        // Linear counting when many registers are still empty (small sets).
        if raw <= 2.5 * m && zeros > 0 {
            return m * (m / zeros as f64).ln();
        }
        raw
    }

    /// Union with another bank (registers are max-mergeable). Used for the
    /// `new_src` / `new_flow_rate` features (|HLL(t) ∪ HLL(history)|).
    pub fn union(&self, other: &Hll) -> Hll {
        let mut out = self.clone();
        for (o, &v) in out.regs.iter_mut().zip(&other.regs) {
            if v > *o {
                *o = v;
            }
        }
        out
    }

    pub fn registers(&self) -> &[u8] {
        &self.regs
    }
}

/// One sampled packet header (`struct xs_sample`, 64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub ts_ns: u64,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub pkt_len: u16,
    pub ip_id: u16,
    pub l4_proto: u8,
    pub tcp_flags: u8,
    pub ttl: u8,
    pub verdict: u8,
    pub rx_queue: u8,
    pub parse_rc: u8,
    pub l3: u8,
    pub flags: u8,
    pub tcp_window: u16,
}

/// Byte length of `struct xs_sample`.
pub const SAMPLE_SIZE: usize = 64;

impl Sample {
    pub fn from_bytes(b: &[u8]) -> Option<Sample> {
        if b.len() < SAMPLE_SIZE {
            return None;
        }
        let u16le = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let mut saddr = [0u8; 16];
        let mut daddr = [0u8; 16];
        saddr.copy_from_slice(&b[8..24]);
        daddr.copy_from_slice(&b[24..40]);
        Some(Sample {
            ts_ns: u64::from_ne_bytes(b[0..8].try_into().ok()?),
            saddr,
            daddr,
            // sport/dport are stored network order (__be16); expose host order.
            sport: u16::from_be_bytes([b[40], b[41]]),
            dport: u16::from_be_bytes([b[42], b[43]]),
            pkt_len: u16le(44),
            ip_id: u16le(46),
            l4_proto: b[48],
            tcp_flags: b[49],
            ttl: b[50],
            verdict: b[51],
            rx_queue: b[52],
            parse_rc: b[53],
            l3: b[54],
            flags: b[55],
            tcp_window: u16le(56),
        })
    }

    fn ip(a: &[u8; 16]) -> IpAddr {
        // ::ffff:a.b.c.d -> IPv4
        if a[..10].iter().all(|&x| x == 0) && a[10] == 0xff && a[11] == 0xff {
            IpAddr::V4(Ipv4Addr::new(a[12], a[13], a[14], a[15]))
        } else {
            IpAddr::V6(Ipv6Addr::from(*a))
        }
    }

    pub fn src_ip(&self) -> IpAddr {
        Self::ip(&self.saddr)
    }
    pub fn dst_ip(&self) -> IpAddr {
        Self::ip(&self.daddr)
    }
}

/// Userspace flow key (mirror of `feature-schema.md` FlowKey, without VLAN).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
}

/// Reconstructed per-flow record (subset of the design's FlowRec).
#[derive(Clone, Copy, Debug)]
pub struct FlowRec {
    pub first_ns: u64,
    pub last_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub flags_union: u8,
    pub size_min: u16,
    pub size_max: u16,
}

impl FlowRec {
    pub fn duration_ns(&self) -> u64 {
        self.last_ns.saturating_sub(self.first_ns)
    }
}

/// Flow table reconstructed from samples, bounded by capacity with
/// `last_seen` eviction (the design's timer-wheel eviction, simplified).
#[allow(missing_debug_implementations)]
pub struct FlowTable {
    map: HashMap<FlowKey, FlowRec>,
    capacity: usize,
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        FlowTable { map: HashMap::new(), capacity: capacity.max(1) }
    }

    pub fn observe(&mut self, s: &Sample) {
        let key = FlowKey {
            src: s.saddr,
            dst: s.daddr,
            sport: s.sport,
            dport: s.dport,
            proto: s.l4_proto,
        };
        let e = self.map.entry(key).or_insert(FlowRec {
            first_ns: s.ts_ns,
            last_ns: s.ts_ns,
            packets: 0,
            bytes: 0,
            flags_union: 0,
            size_min: u16::MAX,
            size_max: 0,
        });
        e.last_ns = s.ts_ns;
        e.packets += 1;
        e.bytes += s.pkt_len as u64;
        e.flags_union |= s.tcp_flags;
        e.size_min = e.size_min.min(s.pkt_len);
        e.size_max = e.size_max.max(s.pkt_len);
        if self.map.len() > self.capacity {
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some((&k, _)) = self.map.iter().min_by_key(|(_, v)| v.last_ns) {
            self.map.remove(&k);
        }
    }

    /// Drop flows whose `last_ns` is older than `now_ns - idle_ns`.
    pub fn expire(&mut self, now_ns: u64, idle_ns: u64) {
        let cutoff = now_ns.saturating_sub(idle_ns);
        self.map.retain(|_, v| v.last_ns >= cutoff);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowRec)> {
        self.map.iter()
    }
}

/// Statistics over the exact destination-port histogram (merged over CPUs).
pub mod dport {
    /// Share of packets going to the single most-hit port (concentration).
    pub fn top1_share(hist: &[u64]) -> f64 {
        let total: u64 = hist.iter().sum();
        if total == 0 {
            return f64::NAN;
        }
        let top = hist.iter().copied().max().unwrap_or(0);
        top as f64 / total as f64
    }

    /// Shannon entropy of the port distribution, normalised to 0..1 by
    /// log2(number of observed ports). 1 = uniform spread, ~0 = one port.
    pub fn entropy(hist: &[u64]) -> f64 {
        let total: u64 = hist.iter().sum();
        if total == 0 {
            return f64::NAN;
        }
        let total = total as f64;
        let mut h = 0.0f64;
        let mut observed = 0usize;
        for &c in hist {
            if c > 0 {
                let p = c as f64 / total;
                h -= p * p.log2();
                observed += 1;
            }
        }
        if observed <= 1 {
            0.0
        } else {
            h / (observed as f64).log2()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hll_counts_within_error() {
        // Insert N distinct 64-bit hashes the same way the dataplane does.
        let mut regs = vec![0u8; HLL_EPOCHS * HLL_N * HLL_REGISTERS];
        let n: u64 = 50_000;
        for i in 0..n {
            // splitmix64, matching xs_mix64.
            let mut x = i.wrapping_mul(0x9e3779b97f4a7c15);
            x ^= x >> 30;
            x = x.wrapping_mul(0xbf58476d1ce4e5b9);
            x ^= x >> 27;
            x = x.wrapping_mul(0x94d049bb133111eb);
            x ^= x >> 31;
            let idx = (x >> (64 - HLL_P)) as usize & (HLL_REGISTERS - 1);
            let shifted = x << HLL_P;
            let rank = if shifted == 0 { 64 - HLL_P + 1 } else { shifted.leading_zeros() + 1 };
            // epoch 0, sketch HLL_SRC
            let off = HLL_SRC * HLL_REGISTERS + idx;
            if (rank as u8) > regs[off] {
                regs[off] = rank as u8;
            }
        }
        let mut h = Hll::default();
        h.merge_cpu(&regs, 0, HLL_SRC);
        let est = h.estimate();
        let err = (est - n as f64).abs() / n as f64;
        assert!(err < 0.03, "HLL estimate {est} for {n} distinct, error {err}");
    }

    #[test]
    fn hll_small_set_linear_counting() {
        let mut regs = vec![0u8; HLL_EPOCHS * HLL_N * HLL_REGISTERS];
        for i in 0..10u64 {
            let x = i.wrapping_mul(0x9e3779b97f4a7c15) ^ 0x1234;
            let idx = (x >> (64 - HLL_P)) as usize & (HLL_REGISTERS - 1);
            let rank = ((x << HLL_P).leading_zeros() + 1) as u8;
            regs[idx] = regs[idx].max(rank);
        }
        let mut h = Hll::default();
        h.merge_cpu(&regs, 0, HLL_SRC);
        let est = h.estimate();
        assert!((est - 10.0).abs() < 3.0, "small-set estimate {est}");
    }

    #[test]
    fn sample_decode_v4() {
        let mut b = [0u8; SAMPLE_SIZE];
        b[0..8].copy_from_slice(&123u64.to_ne_bytes());
        // ::ffff:198.51.100.1
        b[18] = 0xff;
        b[19] = 0xff;
        b[20..24].copy_from_slice(&[198, 51, 100, 1]);
        b[40..42].copy_from_slice(&40000u16.to_be_bytes());
        b[42..44].copy_from_slice(&443u16.to_be_bytes());
        b[44..46].copy_from_slice(&1500u16.to_ne_bytes());
        b[48] = 6;
        let s = Sample::from_bytes(&b).unwrap();
        assert_eq!(s.src_ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(s.sport, 40000);
        assert_eq!(s.dport, 443);
        assert_eq!(s.pkt_len, 1500);
        assert_eq!(s.l4_proto, 6);
    }

    #[test]
    fn flow_table_aggregates_and_evicts() {
        let mut t = FlowTable::new(2);
        let mk = |ts: u64, dp: u16, len: u16| {
            let mut b = [0u8; SAMPLE_SIZE];
            b[0..8].copy_from_slice(&ts.to_ne_bytes());
            b[18] = 0xff;
            b[19] = 0xff;
            b[20..24].copy_from_slice(&[10, 0, 0, 1]);
            b[42..44].copy_from_slice(&dp.to_be_bytes());
            b[44..46].copy_from_slice(&len.to_ne_bytes());
            b[48] = 17;
            Sample::from_bytes(&b).unwrap()
        };
        t.observe(&mk(1, 53, 100));
        t.observe(&mk(2, 53, 200));
        assert_eq!(t.len(), 1);
        let (_, rec) = t.iter().next().unwrap();
        assert_eq!(rec.packets, 2);
        assert_eq!(rec.bytes, 300);
        assert_eq!(rec.size_max, 200);
        // two more distinct flows exceed capacity 2 -> oldest evicted
        t.observe(&mk(3, 80, 100));
        t.observe(&mk(4, 443, 100));
        assert!(t.len() <= 2);
    }

    #[test]
    fn dport_stats() {
        let mut hist = vec![0u64; 65536];
        hist[53] = 900;
        hist[443] = 100;
        assert!((dport::top1_share(&hist) - 0.9).abs() < 1e-9);
        let e = dport::entropy(&hist);
        assert!(e > 0.0 && e < 1.0);
        // single port -> zero entropy, full concentration
        let mut one = vec![0u64; 65536];
        one[80] = 500;
        assert_eq!(dport::entropy(&one), 0.0);
        assert!((dport::top1_share(&one) - 1.0).abs() < 1e-9);
    }
}
