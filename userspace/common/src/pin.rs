//! bpffs pin layout.
//!
//! Every interface gets its own directory so two interfaces never share
//! maps by accident and a single interface can be torn down independently:
//!
//! ```text
//! /sys/fs/bpf/xdp-sentinel/<ifname>/xs_xdp_main   program (introspection)
//! /sys/fs/bpf/xdp-sentinel/<ifname>/xs_stats      per-CPU counters
//! /sys/fs/bpf/xdp-sentinel/<ifname>/xs_config     runtime config
//! ```
//!
//! Pinned maps outlive every userspace process: the dataplane keeps its
//! counters and config (and, from Phase 2, its policies with their TTLs)
//! across agent crashes and restarts.

use std::path::{Path, PathBuf};

use crate::abi::AbiError;

pub const DEFAULT_PIN_ROOT: &str = "/sys/fs/bpf/xdp-sentinel";
pub const PROG_NAME: &str = "xs_xdp_main";
pub const MAP_STATS: &str = "xs_stats";
pub const MAP_CONFIG: &str = "xs_config";
/// Phase 2 policy and allowlist maps.
pub const MAP_POLICY_V4: &str = "xs_policy_v4";
pub const MAP_POLICY_V6: &str = "xs_policy_v6";
pub const MAP_ALLOW_V4: &str = "xs_allow_v4";
pub const MAP_ALLOW_V6: &str = "xs_allow_v6";
/// Phase 3 per-source rate-limiter state maps.
pub const MAP_RL_V4: &str = "xs_rl_v4";
pub const MAP_RL_V6: &str = "xs_rl_v6";
/// Per-destination victim accounting (dropped attack packets by dst IPv4).
pub const MAP_VICTIM_V4: &str = "xs_victim_v4";
/// Per-source attacker accounting (dropped attack packets by src IPv4).
pub const MAP_ATTACKER_V4: &str = "xs_attacker_v4";
/// Per-destination victim accounting, IPv6 (keyed by the full /128 dst).
pub const MAP_VICTIM_V6: &str = "xs_victim_v6";
/// Per-source attacker accounting, IPv6 (keyed by the src /64 prefix).
pub const MAP_ATTACKER_V6: &str = "xs_attacker_v6";
/// Service allowlist: destinations under default-deny.
pub const MAP_PROTECTED_V4: &str = "xs_protected_v4";
/// Service allowlist: permitted {dst,proto,dport} services on protected dsts.
pub const MAP_SERVICE_V4: &str = "xs_service_v4";
/// IPv6 twins of the service allowlist maps.
pub const MAP_PROTECTED_V6: &str = "xs_protected_v6";
pub const MAP_SERVICE_V6: &str = "xs_service_v6";
/// Honeypot addresses: the on-switch, the addresses, and every source that touched one.
pub const MAP_HONEYPOT_ON: &str = "xs_honeypot_on";
pub const MAP_HONEYPOT_V4: &str = "xs_honeypot_v4";
pub const MAP_HONEYPOT_SRC: &str = "xs_honeypot_src";
/// LAN guard: config, ARP bindings, spoof records, approved MACs, unapproved devices seen.
pub const MAP_LANGUARD: &str = "xs_languard_cfg";
pub const MAP_ARP_BIND: &str = "xs_arp_bind";
pub const MAP_ARP_SPOOF: &str = "xs_arp_spoof";
pub const MAP_NAC_MAC: &str = "xs_nac_mac";
pub const MAP_NAC_SEEN: &str = "xs_nac_seen";
/// Attack signatures: drop-shape counts and the approved rules.
pub const MAP_SIG_SEEN: &str = "xs_sig_seen";
pub const MAP_SIG_RULES: &str = "xs_sig_rules";

/// Linux IFNAMSIZ including the terminating NUL.
const IFNAMSIZ: usize = 16;

/// Validated per-interface pin directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinLayout {
    iface: String,
    dir: PathBuf,
}

impl PinLayout {
    /// The interface name becomes a path component, so it is validated with
    /// the kernel's own rules (`dev_valid_name()`): this rejects `..`, `/`
    /// and anything that could escape the pin root.
    pub fn new(root: &Path, iface: &str) -> Result<Self, AbiError> {
        validate_ifname(iface)?;
        Ok(PinLayout { iface: iface.to_string(), dir: root.join(iface) })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn map(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn prog(&self) -> PathBuf {
        self.dir.join(PROG_NAME)
    }
}

/// Mirror of the kernel's `dev_valid_name()`.
pub fn validate_ifname(name: &str) -> Result<(), AbiError> {
    let bad = name.is_empty()
        || name.len() >= IFNAMSIZ
        || name == "."
        || name == ".."
        || name.chars().any(|c| c == '/' || c == ':' || c.is_whitespace() || c == '\0');
    if bad {
        return Err(AbiError::InterfaceName(name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_paths() {
        let l = PinLayout::new(Path::new(DEFAULT_PIN_ROOT), "eth0").unwrap();
        assert_eq!(l.map(MAP_STATS), PathBuf::from("/sys/fs/bpf/xdp-sentinel/eth0/xs_stats"));
        assert_eq!(l.prog(), PathBuf::from("/sys/fs/bpf/xdp-sentinel/eth0/xs_xdp_main"));
    }

    #[test]
    fn rejects_hostile_names() {
        for bad in ["", ".", "..", "../x", "a/b", "eth0:1", "a b", "sixteen-chars-xx", "x\0"] {
            assert!(validate_ifname(bad).is_err(), "{bad:?} accepted");
        }
        for good in ["eth0", "enp65s0f0np0", "ens1f0.100", "veth-xs0"] {
            assert!(validate_ifname(good).is_ok(), "{good:?} rejected");
        }
    }
}
