//! Mirror of `ebpf/src/abi.h`.
//!
//! Keep in sync with the C header. `tests::counter_table_matches_abi_h`
//! parses the header and fails on any drift in counter slots or parse
//! outcome codes; the `const` assertions below pin the struct sizes.

use std::fmt;

use serde::Serialize;
use thiserror::Error;

/// `XS_ABI_VERSION`.
pub const ABI_VERSION: u32 = 1;
/// `XS_CNT_SLOTS`: counter slots in one per-CPU `struct xs_stats`.
pub const CNT_SLOTS: usize = 128;
/// `XS_CNT_PARSE_BASE`: first slot of the parse-outcome histogram.
pub const CNT_PARSE_BASE: usize = 64;
/// `XS_PARSE_RC_MAX`.
pub const PARSE_RC_MAX: usize = 24;

/// `sizeof(struct xs_counter)`.
pub const COUNTER_SIZE: usize = 16;
/// `sizeof(struct xs_stats)`: value size of the `xs_stats` map (per CPU).
pub const STATS_SIZE: usize = CNT_SLOTS * COUNTER_SIZE;
/// `sizeof(struct xs_config)`: value size of the `xs_config` map.
pub const CONFIG_SIZE: usize = 64;

const _: () = assert!(STATS_SIZE == 2048);
const _: () = assert!(CNT_PARSE_BASE + PARSE_RC_MAX <= CNT_SLOTS);

/// Errors decoding or validating dataplane ABI values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AbiError {
    #[error("{what}: expected {expected} bytes, got {got}")]
    Size { what: &'static str, expected: usize, got: usize },
    #[error("unknown config flag bits {0:#x}")]
    UnknownFlags(u32),
    #[error("invalid interface name {0:?}")]
    InterfaceName(String),
}

/// How a parse outcome is treated by the dataplane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseClass {
    /// Well formed (`XS_PARSE_OK`, `XS_PARSE_NOT_IP`).
    Ok,
    /// Legal but not parsed by the fast path; always passed.
    Unsupported,
    /// Malformed; dropped only with `drop_malformed`.
    Malformed,
}

/// Static description of one counter slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterDef {
    pub slot: usize,
    /// Stable metric name (`XS_CNT_FOO` -> `foo`, parse outcome
    /// `XS_PARSE_FOO` -> `parse_foo`). Dashboards and ClickHouse history
    /// key on it: never rename.
    pub name: &'static str,
    pub help: &'static str,
}

macro_rules! c {
    ($slot:expr, $name:literal, $help:literal) => {
        CounterDef { slot: $slot, name: $name, help: $help }
    };
}

/// Every allocated counter slot, in slot order.
pub const COUNTERS: &[CounterDef] = &[
    c!(0, "rx", "frames seen by the XDP program"),
    c!(1, "verdict_pass", "frames passed to the kernel stack"),
    c!(2, "verdict_drop", "frames dropped"),
    c!(3, "verdict_tx", "frames bounced with XDP_TX (reserved)"),
    c!(4, "verdict_redirect", "frames redirected (reserved)"),
    c!(5, "policy_drop", "dropped by a per-source block policy"),
    c!(6, "allow_pass", "passed because the source is allowlisted"),
    c!(7, "policy_expired", "a matching policy was ignored (TTL expired)"),
    c!(8, "l2_vlan1", "frames with one VLAN tag"),
    c!(9, "l2_vlan2", "frames with two VLAN tags (QinQ)"),
    c!(10, "rate_limited", "dropped by the per-source rate limiter"),
    c!(11, "rate_tracked", "IP packets that passed through the rate limiter"),
    c!(12, "sampled", "headers copied to the sample ring buffer"),
    c!(13, "sample_drop", "sample ring-buffer reserve failures (collector behind)"),
    c!(14, "ct_untracked", "TCP packets matching no tracked flow (ACK/RST flood)"),
    c!(16, "l3_ipv4", "frames with a valid IPv4 header"),
    c!(17, "l3_ipv6", "frames with a valid IPv6 header"),
    c!(18, "l3_arp", "ARP frames"),
    c!(19, "l3_other", "other ethertypes and 802.3 length frames"),
    c!(24, "l4_tcp", "fully parsed TCP packets (incl. non-first fragments)"),
    c!(25, "l4_udp", "fully parsed UDP packets (incl. non-first fragments)"),
    c!(26, "l4_icmp", "ICMPv4 packets"),
    c!(27, "l4_icmpv6", "ICMPv6 packets"),
    c!(28, "l4_other", "other transport protocols"),
    c!(32, "frag_first", "first fragments (offset 0, more-fragments set)"),
    c!(33, "frag_later", "non-first fragments"),
    c!(34, "ipv6_ext", "IPv6 packets with at least one extension header"),
    c!(40, "tcp_syn", "TCP SYN without ACK"),
    c!(41, "tcp_synack", "TCP SYN+ACK"),
    c!(42, "tcp_ack", "TCP ACK without SYN/FIN/RST"),
    c!(43, "tcp_fin", "TCP segments with FIN"),
    c!(44, "tcp_rst", "TCP segments with RST"),
    c!(48, "anom_ipv4_options", "IPv4 headers carrying options"),
    c!(49, "anom_tcp_bad_flags", "TCP flag combinations no conforming stack sends"),
    c!(50, "anom_udp_len_mismatch", "UDP length shorter than the IP payload"),
    c!(51, "anom_land", "source address equals destination address"),
    c!(64, "parse_ok", "parse outcome: well formed IP"),
    c!(65, "parse_not_ip", "parse outcome: non-IP ethertype"),
    c!(66, "parse_unsup_vlan_depth", "parse outcome: more than two VLAN tags"),
    c!(67, "parse_unsup_ipv6_ext_depth", "parse outcome: IPv6 extension chain too long"),
    c!(72, "parse_err_eth_trunc", "parse outcome: truncated Ethernet header"),
    c!(73, "parse_err_vlan_trunc", "parse outcome: truncated VLAN tag"),
    c!(74, "parse_err_ipv4_trunc", "parse outcome: truncated IPv4 header"),
    c!(75, "parse_err_ipv4_version", "parse outcome: IPv4 ethertype, version != 4"),
    c!(76, "parse_err_ipv4_ihl", "parse outcome: IPv4 IHL < 5"),
    c!(77, "parse_err_ipv4_totlen", "parse outcome: IPv4 total length invalid"),
    c!(78, "parse_err_ipv6_trunc", "parse outcome: truncated IPv6 header"),
    c!(79, "parse_err_ipv6_version", "parse outcome: IPv6 ethertype, version != 6"),
    c!(80, "parse_err_ipv6_plen", "parse outcome: IPv6 payload length invalid"),
    c!(81, "parse_err_ipv6_ext_trunc", "parse outcome: truncated IPv6 extension header"),
    c!(82, "parse_err_frag_tiny", "parse outcome: first fragment without full L4 header"),
    c!(83, "parse_err_tcp_trunc", "parse outcome: truncated TCP header"),
    c!(84, "parse_err_tcp_doff", "parse outcome: invalid TCP data offset"),
    c!(85, "parse_err_udp_trunc", "parse outcome: truncated UDP header"),
    c!(86, "parse_err_udp_len", "parse outcome: invalid UDP length"),
    c!(87, "parse_err_icmp_trunc", "parse outcome: truncated ICMP header"),
];

/// `enum xs_parse_rc` value of the first malformed outcome.
pub const PARSE_ERR_FIRST: usize = 8;

/// Classification of a parse outcome code.
pub fn parse_class(rc: usize) -> ParseClass {
    match rc {
        0 | 1 => ParseClass::Ok,
        rc if rc < PARSE_ERR_FIRST => ParseClass::Unsupported,
        _ => ParseClass::Malformed,
    }
}

/// Look up the definition of a slot.
pub fn counter_def(slot: usize) -> Option<&'static CounterDef> {
    COUNTERS.iter().find(|d| d.slot == slot)
}

/// Well-known slots used by consumers.
pub mod slot {
    pub const RX: usize = 0;
    pub const VERDICT_PASS: usize = 1;
    pub const VERDICT_DROP: usize = 2;
    pub const VERDICT_TX: usize = 3;
    pub const VERDICT_REDIRECT: usize = 4;
}

/// `struct xs_counter`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

impl Counter {
    /// Decode one counter from its 16-byte native-endian representation.
    pub fn from_ne_bytes(b: &[u8; COUNTER_SIZE]) -> Self {
        let (p, by) = b.split_at(8);
        Counter {
            packets: u64::from_ne_bytes(p.try_into().expect("split at 8")),
            bytes: u64::from_ne_bytes(by.try_into().expect("split at 8")),
        }
    }

    /// Wrap-safe difference. Counters are monotonic u64s that never reset,
    /// so `later - earlier` modulo 2^64 is the true delta even across a wrap.
    pub fn wrapping_sub(self, earlier: Counter) -> Counter {
        Counter {
            packets: self.packets.wrapping_sub(earlier.packets),
            bytes: self.bytes.wrapping_sub(earlier.bytes),
        }
    }
}

/// `enum xs_config_flags`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ConfigFlags(u32);

impl ConfigFlags {
    pub const DROP_MALFORMED: ConfigFlags = ConfigFlags(1 << 0);
    pub const DROP_BAD_TCP_FLAGS: ConfigFlags = ConfigFlags(1 << 1);
    pub const DROP_FRAGMENTS: ConfigFlags = ConfigFlags(1 << 2);
    pub const DROP_UDP_DNS: ConfigFlags = ConfigFlags(1 << 3);
    pub const DROP_UDP: ConfigFlags = ConfigFlags(1 << 7);
    /// Managed automatically by the block/allow commands, not by `config`.
    pub const CHECK_ALLOW: ConfigFlags = ConfigFlags(1 << 4);
    pub const CHECK_POLICY: ConfigFlags = ConfigFlags(1 << 5);
    /// Managed by `sentinelctl ratelimit`, not by `config`.
    pub const RATELIMIT: ConfigFlags = ConfigFlags(1 << 6);
    /// Phase 5 flow-aggregation stages, managed by the agent collector.
    pub const SAMPLING: ConfigFlags = ConfigFlags(1 << 8);
    pub const HLL: ConfigFlags = ConfigFlags(1 << 9);
    pub const DPORT_HIST: ConfigFlags = ConfigFlags(1 << 10);
    /// Aggregate (interface-wide) rate limiter; params in global_rl_*.
    pub const GLOBAL_RL: ConfigFlags = ConfigFlags(1 << 11);
    /// Per-vector validity drops, enabled by the risk engine under attack.
    pub const DROP_ICMP: ConfigFlags = ConfigFlags(1 << 12);
    pub const DROP_SYN: ConfigFlags = ConfigFlags(1 << 13);
    pub const DROP_ACK: ConfigFlags = ConfigFlags(1 << 14);
    pub const DROP_UDP_STRICT: ConfigFlags = ConfigFlags(1 << 15);
    /// Connection tracking (anti ACK/RST flood). CONNTRACK counts untracked TCP
    /// (shadow); DROP_UNTRACKED also drops it.
    pub const CONNTRACK: ConfigFlags = ConfigFlags(1 << 16);
    pub const DROP_UNTRACKED: ConfigFlags = ConfigFlags(1 << 17);
    pub const KNOWN: u32 = 0b11_1111_1111_1111_1111;
    /// Bits an operator toggles directly (the rest are auto-managed).
    pub const OPERATOR: u32 = 0b1000_1111;

    /// Names in bit order, used for display and the CLI.
    pub const NAMES: [(ConfigFlags, &'static str); 18] = [
        (Self::DROP_MALFORMED, "drop_malformed"),
        (Self::DROP_BAD_TCP_FLAGS, "drop_bad_tcp_flags"),
        (Self::DROP_FRAGMENTS, "drop_fragments"),
        (Self::DROP_UDP_DNS, "drop_udp_dns"),
        (Self::DROP_UDP, "drop_udp"),
        (Self::CHECK_ALLOW, "check_allow"),
        (Self::CHECK_POLICY, "check_policy"),
        (Self::RATELIMIT, "ratelimit"),
        (Self::SAMPLING, "sampling"),
        (Self::HLL, "hll"),
        (Self::DPORT_HIST, "dport_hist"),
        (Self::GLOBAL_RL, "global_rl"),
        (Self::DROP_ICMP, "drop_icmp"),
        (Self::DROP_SYN, "drop_syn"),
        (Self::DROP_ACK, "drop_ack"),
        (Self::DROP_UDP_STRICT, "drop_udp_strict"),
        (Self::CONNTRACK, "conntrack"),
        (Self::DROP_UNTRACKED, "drop_untracked"),
    ];

    /// Validate bits coming from an operator or API before they reach the
    /// dataplane: unknown bits are rejected, never silently written.
    pub fn from_bits(bits: u32) -> Result<Self, AbiError> {
        if bits & !Self::KNOWN != 0 {
            return Err(AbiError::UnknownFlags(bits & !Self::KNOWN));
        }
        Ok(ConfigFlags(bits))
    }

    /// Accept whatever the dataplane map currently holds (it may have been
    /// written by a newer version); unknown bits are preserved on rewrite.
    pub fn from_bits_retain(bits: u32) -> Self {
        ConfigFlags(bits)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn contains(self, other: ConfigFlags) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn set(&mut self, other: ConfigFlags, on: bool) {
        if on {
            self.0 |= other.0;
        } else {
            self.0 &= !other.0;
        }
    }
}

impl fmt::Debug for ConfigFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> =
            Self::NAMES.iter().filter(|(fl, _)| self.contains(*fl)).map(|(_, n)| *n).collect();
        if names.is_empty() {
            write!(f, "(none, observe only)")?;
        } else {
            write!(f, "{}", names.join("|"))?;
        }
        let unknown = self.0 & !Self::KNOWN;
        if unknown != 0 {
            write!(f, " +unknown {unknown:#x}")?;
        }
        Ok(())
    }
}

/// `struct xs_config`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub abi_version: u32,
    pub flags: ConfigFlags,
    /// Rate limiter: ns between conforming packets (1e9 / pps); 0 = unset.
    pub rl_interval_ns: u32,
    /// Rate limiter: bucket depth in packets (burst tolerance).
    pub rl_burst: u32,
    /// Phase 5: active HyperLogLog epoch (0/1), flipped by the collector.
    pub hll_epoch: u32,
    /// Phase 5: sample 1-in-2^sample_shift packets (0 = every packet).
    pub sample_shift: u32,
    /// Aggregate limiter: ns between packets globally (1e9 / global_pps); 0 = unset.
    pub global_rl_interval_ns: u32,
    /// Aggregate limiter: bucket depth in packets.
    pub global_rl_burst: u32,
}

impl Config {
    pub fn from_bytes(b: &[u8]) -> Result<Self, AbiError> {
        if b.len() != CONFIG_SIZE {
            return Err(AbiError::Size { what: "xs_config", expected: CONFIG_SIZE, got: b.len() });
        }
        Ok(Config {
            abi_version: u32::from_ne_bytes(b[0..4].try_into().expect("4 bytes")),
            flags: ConfigFlags::from_bits_retain(u32::from_ne_bytes(
                b[4..8].try_into().expect("4 bytes"),
            )),
            rl_interval_ns: u32::from_ne_bytes(b[8..12].try_into().expect("4 bytes")),
            rl_burst: u32::from_ne_bytes(b[12..16].try_into().expect("4 bytes")),
            hll_epoch: u32::from_ne_bytes(b[16..20].try_into().expect("4 bytes")),
            sample_shift: u32::from_ne_bytes(b[20..24].try_into().expect("4 bytes")),
            global_rl_interval_ns: u32::from_ne_bytes(b[24..28].try_into().expect("4 bytes")),
            global_rl_burst: u32::from_ne_bytes(b[28..32].try_into().expect("4 bytes")),
        })
    }

    /// Encode. Reserved bytes are written as zero.
    pub fn to_bytes(self) -> [u8; CONFIG_SIZE] {
        let mut b = [0u8; CONFIG_SIZE];
        b[0..4].copy_from_slice(&self.abi_version.to_ne_bytes());
        b[4..8].copy_from_slice(&self.flags.bits().to_ne_bytes());
        b[8..12].copy_from_slice(&self.rl_interval_ns.to_ne_bytes());
        b[12..16].copy_from_slice(&self.rl_burst.to_ne_bytes());
        b[16..20].copy_from_slice(&self.hll_epoch.to_ne_bytes());
        b[20..24].copy_from_slice(&self.sample_shift.to_ne_bytes());
        b[24..28].copy_from_slice(&self.global_rl_interval_ns.to_ne_bytes());
        b[28..32].copy_from_slice(&self.global_rl_burst.to_ne_bytes());
        b
    }

    /// Configured packets/second, or 0 if the limiter is unset.
    pub fn rl_pps(&self) -> u32 {
        1_000_000_000u32.checked_div(self.rl_interval_ns).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Parse `NAME = value,` enumerators with a given prefix from abi.h.
    fn enumerators(src: &str, prefix: &str) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for line in src.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix(prefix) else { continue };
            let Some((name, value)) = rest.split_once('=') else { continue };
            // `3,  /* comment */` -> `3`
            let value = value.split_whitespace().next().unwrap_or("").trim_end_matches(',');
            if let Ok(v) = value.parse::<usize>() {
                out.insert(name.trim().to_ascii_lowercase(), v);
            }
        }
        out
    }

    #[test]
    fn counter_table_matches_abi_h() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ebpf/src/abi.h");
        let src = std::fs::read_to_string(path).expect("read abi.h");

        let mut expected: BTreeMap<usize, String> = BTreeMap::new();
        for (name, v) in enumerators(&src, "XS_CNT_") {
            if name == "parse_base" || name == "slots" {
                continue;
            }
            expected.insert(v, name);
        }
        for (name, v) in enumerators(&src, "XS_PARSE_") {
            if name == "err_first" || name == "rc_max" {
                continue;
            }
            expected.insert(CNT_PARSE_BASE + v, format!("parse_{name}"));
        }
        let ours: BTreeMap<usize, String> =
            COUNTERS.iter().map(|d| (d.slot, d.name.to_string())).collect();
        assert_eq!(ours, expected, "userspace counter table drifted from ebpf/src/abi.h");

        let get = |p: &str, n: &str| enumerators(&src, p)[n];
        assert_eq!(get("XS_CNT_", "slots"), CNT_SLOTS);
        assert_eq!(get("XS_CNT_", "parse_base"), CNT_PARSE_BASE);
        assert_eq!(get("XS_PARSE_", "rc_max"), PARSE_RC_MAX);
        assert_eq!(get("XS_PARSE_", "err_first"), PARSE_ERR_FIRST);
        assert!(src.contains(&format!("#define XS_ABI_VERSION {ABI_VERSION}")));
    }

    #[test]
    fn counter_slots_sorted_and_unique() {
        assert!(COUNTERS.windows(2).all(|w| w[0].slot < w[1].slot));
        assert!(COUNTERS.iter().all(|d| d.slot < CNT_SLOTS));
    }

    #[test]
    fn config_roundtrip_and_validation() {
        let mut flags = ConfigFlags::default();
        flags.set(ConfigFlags::DROP_MALFORMED, true);
        flags.set(ConfigFlags::DROP_FRAGMENTS, true);
        let cfg = Config { abi_version: ABI_VERSION, flags, ..Default::default() };
        assert_eq!(Config::from_bytes(&cfg.to_bytes()).unwrap(), cfg);
        assert_eq!(flags.bits(), 0b101);
        assert_eq!(ConfigFlags::from_bits(1 << 20), Err(AbiError::UnknownFlags(1 << 20)));
        assert!(Config::from_bytes(&[0u8; 8]).is_err());
        assert_eq!(format!("{:?}", flags), "drop_malformed|drop_fragments");
    }

    #[test]
    fn counter_wraps() {
        let a = Counter { packets: u64::MAX - 1, bytes: 10 };
        let b = Counter { packets: 3, bytes: 25 };
        assert_eq!(b.wrapping_sub(a), Counter { packets: 5, bytes: 15 });
    }

    #[test]
    fn parse_classes() {
        assert_eq!(parse_class(0), ParseClass::Ok);
        assert_eq!(parse_class(3), ParseClass::Unsupported);
        assert_eq!(parse_class(8), ParseClass::Malformed);
    }
}
