//! Mirror of the Phase 2 policy ABI (`struct xs_policy`, `struct xs_allow`,
//! the LPM key structs, and the `xs_action` / `xs_trust` enums in
//! `ebpf/src/abi.h`).
//!
//! Encoders/decoders work on explicit byte layouts (no `unsafe` transmutes),
//! matching how the dataplane reads the maps:
//!   * `xs_policy_v4` key: source IPv4, network order (`__be32`);
//!   * `xs_policy_v6` key: the first 8 address bytes (the /64), which is what
//!     the XDP program `memcpy`s into its `__u64` key;
//!   * LPM keys: native-endian `u32` prefix length followed by the address
//!     bytes in network order (the layout `BPF_MAP_TYPE_LPM_TRIE` requires).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::abi::AbiError;

/// `sizeof(struct xs_policy)`.
pub const POLICY_SIZE: usize = 32;
/// `sizeof(struct xs_allow)`.
pub const ALLOW_SIZE: usize = 16;
/// `sizeof(struct xs_lpm_v4)`.
pub const LPM_V4_SIZE: usize = 8;
/// `sizeof(struct xs_lpm_v6)`.
pub const LPM_V6_SIZE: usize = 20;

/// `enum xs_action`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Action {
    Pass = 0,
    #[default]
    Drop = 1,
}

impl Action {
    pub fn from_u8(v: u8) -> Result<Self, AbiError> {
        match v {
            0 => Ok(Action::Pass),
            1 => Ok(Action::Drop),
            _ => Err(AbiError::UnknownFlags(v as u32)),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Drop => "drop",
        }
    }
}

/// `enum xs_trust`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Trust {
    #[default]
    Full = 0,
    DynamicExempt = 1,
}

impl Trust {
    pub fn from_u8(v: u8) -> Result<Self, AbiError> {
        match v {
            0 => Ok(Trust::Full),
            1 => Ok(Trust::DynamicExempt),
            _ => Err(AbiError::UnknownFlags(v as u32)),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Full => "full",
            Trust::DynamicExempt => "dynamic_exempt",
        }
    }
}

/// `enum xs_policy_reason`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Reason {
    Unspec = 0,
    #[default]
    Manual = 1,
    Flood = 2,
    Scan = 3,
}

impl Reason {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => Reason::Flood,
            3 => Reason::Scan,
            0 => Reason::Unspec,
            _ => Reason::Manual,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Unspec => "unspecified",
            Reason::Manual => "manual",
            Reason::Flood => "flood",
            Reason::Scan => "scan",
        }
    }
}

/// `struct xs_policy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// CLOCK_MONOTONIC deadline in ns; 0 = never expires.
    pub expires_ns: u64,
    pub policy_id: u32,
    pub action: Action,
    pub reason: Reason,
}

impl Policy {
    pub fn to_bytes(self) -> [u8; POLICY_SIZE] {
        let mut b = [0u8; POLICY_SIZE];
        b[0..8].copy_from_slice(&self.expires_ns.to_ne_bytes());
        b[8..12].copy_from_slice(&self.policy_id.to_ne_bytes());
        b[12] = self.action as u8;
        b[13] = self.reason as u8;
        // b[14..16] padding, b[16..32] reserved (Phase 3), left zero.
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, AbiError> {
        if b.len() != POLICY_SIZE {
            return Err(AbiError::Size { what: "xs_policy", expected: POLICY_SIZE, got: b.len() });
        }
        Ok(Policy {
            expires_ns: u64::from_ne_bytes(b[0..8].try_into().unwrap()),
            policy_id: u32::from_ne_bytes(b[8..12].try_into().unwrap()),
            action: Action::from_u8(b[12])?,
            reason: Reason::from_u8(b[13]),
        })
    }
}

/// `struct xs_allow`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Allow {
    pub expires_ns: u64,
    pub trust: Trust,
}

impl Allow {
    pub fn to_bytes(self) -> [u8; ALLOW_SIZE] {
        let mut b = [0u8; ALLOW_SIZE];
        b[0..8].copy_from_slice(&self.expires_ns.to_ne_bytes());
        b[8] = self.trust as u8;
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, AbiError> {
        if b.len() != ALLOW_SIZE {
            return Err(AbiError::Size { what: "xs_allow", expected: ALLOW_SIZE, got: b.len() });
        }
        Ok(Allow {
            expires_ns: u64::from_ne_bytes(b[0..8].try_into().unwrap()),
            trust: Trust::from_u8(b[8])?,
        })
    }
}

/// Exact-match key for `xs_policy_v4` (source IPv4, network order).
pub fn policy_key_v4(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

/// Exact-match key for `xs_policy_v6`: the /64, i.e. the first 8 address
/// bytes. This is the byte image of the `__u64` key the dataplane builds.
pub fn policy_key_v6(ip: Ipv6Addr) -> [u8; 8] {
    let o = ip.octets();
    o[0..8].try_into().unwrap()
}

/// Decode a `xs_policy_v4` key back to an address (for listing).
pub fn policy_addr_v4(key: &[u8]) -> Option<Ipv4Addr> {
    let a: [u8; 4] = key.get(0..4)?.try_into().ok()?;
    Some(Ipv4Addr::from(a))
}

/// LPM key for the allowlist. `prefixlen` is in bits; `addr` is masked to it.
pub fn lpm_key(ip: IpAddr, prefixlen: u8) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(&(prefixlen as u32).to_ne_bytes());
    match ip {
        IpAddr::V4(v4) => k.extend_from_slice(&mask_v4(v4, prefixlen).octets()),
        IpAddr::V6(v6) => k.extend_from_slice(&mask_v6(v6, prefixlen).octets()),
    }
    k
}

/// Decode an LPM key `(prefixlen, addr)` for listing.
pub fn lpm_decode(key: &[u8]) -> Option<(IpAddr, u8)> {
    let plen = u32::from_ne_bytes(key.get(0..4)?.try_into().ok()?) as u8;
    match key.len() {
        LPM_V4_SIZE => {
            let a: [u8; 4] = key[4..8].try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(a)), plen))
        }
        LPM_V6_SIZE => {
            let a: [u8; 16] = key[4..20].try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(a)), plen))
        }
        _ => None,
    }
}

fn mask_v4(ip: Ipv4Addr, prefixlen: u8) -> Ipv4Addr {
    if prefixlen >= 32 {
        return ip;
    }
    let bits = u32::from(ip);
    let mask = if prefixlen == 0 { 0 } else { u32::MAX << (32 - prefixlen) };
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(ip: Ipv6Addr, prefixlen: u8) -> Ipv6Addr {
    if prefixlen >= 128 {
        return ip;
    }
    let bits = u128::from(ip);
    let mask = if prefixlen == 0 { 0 } else { u128::MAX << (128 - prefixlen) };
    Ipv6Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_roundtrip() {
        let p =
            Policy { expires_ns: 123, policy_id: 7, action: Action::Drop, reason: Reason::Manual };
        assert_eq!(Policy::from_bytes(&p.to_bytes()).unwrap(), p);
        assert_eq!(p.to_bytes().len(), POLICY_SIZE);
    }

    #[test]
    fn allow_roundtrip() {
        let a = Allow { expires_ns: 0, trust: Trust::DynamicExempt };
        assert_eq!(Allow::from_bytes(&a.to_bytes()).unwrap(), a);
    }

    #[test]
    fn v4_key_is_network_order() {
        assert_eq!(policy_key_v4("1.2.3.4".parse().unwrap()), [1, 2, 3, 4]);
        assert_eq!(policy_addr_v4(&[1, 2, 3, 4]).unwrap(), "1.2.3.4".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn v6_key_is_first_8_bytes() {
        let ip: Ipv6Addr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        assert_eq!(policy_key_v6(ip), [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02]);
    }

    #[test]
    fn lpm_masks_and_roundtrips() {
        // 10.1.2.3/24 masks host bits and encodes prefixlen + masked addr.
        let k = lpm_key("10.1.2.3".parse().unwrap(), 24);
        assert_eq!(k.len(), LPM_V4_SIZE);
        assert_eq!(&k[4..8], &[10, 1, 2, 0]);
        let (ip, plen) = lpm_decode(&k).unwrap();
        assert_eq!((ip, plen), ("10.1.2.0".parse::<IpAddr>().unwrap(), 24));

        let k6 = lpm_key("2001:db8::1".parse().unwrap(), 32);
        assert_eq!(k6.len(), LPM_V6_SIZE);
        let (ip6, plen6) = lpm_decode(&k6).unwrap();
        assert_eq!(plen6, 32);
        assert_eq!(ip6, "2001:db8::".parse::<IpAddr>().unwrap());
    }
}
