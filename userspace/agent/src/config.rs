//! Agent configuration, parsed from a TOML file with strict (unknown-field)
//! validation so a typo is an error, never a silently ignored setting.
//!
//! Example (`/etc/xdp-sentinel/config.toml`):
//!
//! ```toml
//! metrics_addr = "127.0.0.1:9464"
//! pin_root     = "/sys/fs/bpf/xdp-sentinel"
//! bpf_obj      = "/usr/lib/xdp-sentinel/xdp_main.bpf.o"
//!
//! [[interface]]
//! name = "wlo1"
//! mode = "generic"   # "native" | "generic"
//! attach = true      # false = only read metrics from an already-attached prog
//!
//! # Optional: interfaces that are the two legs of ONE inline bridge. They share
//! # a single connection-tracking table, so a flow's outbound half (seen on one
//! # leg) and its reply (seen on the other) match instead of the reply reading
//! # as an untracked ACK/RST flood.
//! shared_conntrack = ["vlan10", "vlan20"]
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:9464".parse().expect("valid default addr")
}
fn default_pin_root() -> PathBuf {
    PathBuf::from(xs_common::pin::DEFAULT_PIN_ROOT)
}
fn default_bpf_obj() -> PathBuf {
    PathBuf::from("/usr/lib/xdp-sentinel/xdp_main.bpf.o")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Driver (native) XDP.
    #[default]
    Native,
    /// Generic (skb) XDP.
    Generic,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only read by linux.rs
    #[serde(default)]
    pub mode: Mode,
    /// If true (default) the agent attaches the program (reusing pinned maps);
    /// if false it only reads metrics from whatever is already attached.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only read by linux.rs
    #[serde(default = "default_true")]
    pub attach: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the Prometheus `/metrics` endpoint listens on.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,
    #[serde(default = "default_pin_root")]
    pub pin_root: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only read by linux.rs
    #[serde(default = "default_bpf_obj")]
    pub bpf_obj: PathBuf,
    /// Interfaces to manage. Renamed `interface` in TOML (`[[interface]]`).
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<Interface>,
    /// Interfaces (bridge legs) that share one conntrack table (see above).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only read by linux.rs
    #[serde(default)]
    pub shared_conntrack: Vec<String>,
}

impl Config {
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        if cfg.interfaces.is_empty() {
            anyhow::bail!("config has no [[interface]] entries; nothing to manage");
        }
        for i in &cfg.interfaces {
            xs_common::pin::validate_ifname(&i.name)?;
        }
        for n in &cfg.shared_conntrack {
            if !cfg.interfaces.iter().any(|i| &i.name == n) {
                anyhow::bail!("shared_conntrack lists \"{n}\", which is not a configured [[interface]]");
            }
        }
        if cfg.shared_conntrack.len() == 1 {
            anyhow::bail!("shared_conntrack needs at least two interfaces (the bridge legs)");
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal() {
        let c = Config::from_toml("[[interface]]\nname = \"eth0\"\n").unwrap();
        assert_eq!(c.interfaces.len(), 1);
        assert_eq!(c.interfaces[0].name, "eth0");
        assert_eq!(c.interfaces[0].mode, Mode::Native);
        assert!(c.interfaces[0].attach);
        assert_eq!(c.metrics_addr, default_metrics_addr());
    }

    #[test]
    fn parses_full() {
        let c = Config::from_toml(
            r#"
            metrics_addr = "0.0.0.0:9500"
            pin_root = "/x"
            [[interface]]
            name = "wlo1"
            mode = "generic"
            attach = false
        "#,
        )
        .unwrap();
        assert_eq!(c.metrics_addr.to_string(), "0.0.0.0:9500");
        assert_eq!(c.interfaces[0].mode, Mode::Generic);
        assert!(!c.interfaces[0].attach);
    }

    #[test]
    fn rejects_unknown_field_and_bad_iface() {
        assert!(Config::from_toml("nope = 1\n[[interface]]\nname=\"eth0\"").is_err());
        assert!(Config::from_toml("[[interface]]\nname = \"a/b\"").is_err());
        assert!(Config::from_toml("metrics_addr = \"127.0.0.1:9464\"").is_err());
        // no interfaces
    }

    #[test]
    fn shared_conntrack_must_name_configured_legs() {
        let ok = Config::from_toml("shared_conntrack = [\"a\", \"b\"]\n[[interface]]\nname=\"a\"\n[[interface]]\nname=\"b\"").unwrap();
        assert_eq!(ok.shared_conntrack, vec!["a", "b"]);
        assert!(Config::from_toml("shared_conntrack = [\"a\", \"x\"]\n[[interface]]\nname=\"a\"\n[[interface]]\nname=\"b\"").is_err());
        assert!(Config::from_toml("shared_conntrack = [\"a\"]\n[[interface]]\nname=\"a\"").is_err());
        assert!(Config::from_toml("[[interface]]\nname=\"a\"").unwrap().shared_conntrack.is_empty());
    }
}
