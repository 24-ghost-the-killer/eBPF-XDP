//! Persistent mitigation state.
//!
//! The dataplane's config (drop flags + rate-limiter parameters) lives in a
//! pinned BPF map, which does not survive a reboot. To make an operator's
//! settings durable, `sentinelctl` writes them here whenever they change, and
//! `sentinel-agent` restores them on startup after (re)attaching.
//!
//! Only the operator-controlled parts are persisted. The auto-managed
//! `CHECK_ALLOW` / `CHECK_POLICY` / `SERVICE_ALLOW` bits are cleared before saving, because
//! they are derived from the (ephemeral, TTL'd) policy maps and must start
//! clear on a fresh boot. Blocks and allowlist entries are deliberately not
//! persisted: they are dynamic and carry their own TTLs.

use std::io;
use std::path::PathBuf;

use crate::abi::{Config, ConfigFlags};

/// Default directory for state files (override with `XS_STATE_DIR`).
pub const DEFAULT_DIR: &str = "/var/lib/xdp-sentinel";

pub fn dir() -> PathBuf {
    std::env::var_os("XS_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

pub fn file(iface: &str) -> PathBuf {
    dir().join(format!("{iface}.state"))
}

/// Persist the operator-relevant config for `iface`. Best-effort: callers
/// typically ignore the error so a read-only state dir never fails a command.
pub fn save(iface: &str, cfg: &Config) -> io::Result<()> {
    let mut c = *cfg;
    // CHECK_* / SERVICE_ALLOW are derived from the ephemeral policy maps and must
    // start clear on a fresh boot. GLOBAL_RL / DROP_UNTRACKED / DROP_UDP_STRICT are
    // armed only by the risk engine (no operator CLI sets them), so they must never
    // be persisted either: a `config` read-modify-write issued while the agent had
    // them armed would otherwise freeze an active mitigation into the "operator"
    // baseline and pin it on forever (per-source RATELIMIT stays persistable — it
    // is an operator-settable baseline via `sentinelctl ratelimit`).
    let managed = ConfigFlags::CHECK_ALLOW.bits()
        | ConfigFlags::CHECK_POLICY.bits()
        | ConfigFlags::SERVICE_ALLOW.bits()
        | ConfigFlags::GLOBAL_RL.bits()
        | ConfigFlags::DROP_UNTRACKED.bits()
        | ConfigFlags::DROP_UDP_STRICT.bits();
    c.flags = ConfigFlags::from_bits_retain(c.flags.bits() & !managed);
    // The aggregate-limiter params belong to GLOBAL_RL; drop them with the flag.
    c.global_rl_interval_ns = 0;
    c.global_rl_burst = 0;
    std::fs::create_dir_all(dir())?;
    let path = file(iface);
    // Write-then-rename so a reader never sees a half-written file.
    let tmp = path.with_extension("state.tmp");
    std::fs::write(&tmp, c.to_bytes())?;
    std::fs::rename(&tmp, &path)
}

/// Load a previously saved config for `iface`, or None if there is none.
pub fn load(iface: &str) -> Option<Config> {
    let bytes = std::fs::read(file(iface)).ok()?;
    Config::from_bytes(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::ABI_VERSION;

    #[test]
    fn save_load_roundtrip_clears_managed_bits() {
        let tmp = std::env::temp_dir().join(format!("xs-state-test-{}", std::process::id()));
        std::env::set_var("XS_STATE_DIR", &tmp);
        let mut flags = ConfigFlags::default();
        flags.set(ConfigFlags::DROP_MALFORMED, true);
        flags.set(ConfigFlags::RATELIMIT, true);
        flags.set(ConfigFlags::CHECK_POLICY, true); // must NOT be persisted
        let cfg = Config {
            abi_version: ABI_VERSION,
            flags,
            rl_interval_ns: 100_000,
            rl_burst: 50,
            ..Default::default()
        };
        save("eth9", &cfg).unwrap();
        let got = load("eth9").unwrap();
        assert!(got.flags.contains(ConfigFlags::DROP_MALFORMED));
        assert!(got.flags.contains(ConfigFlags::RATELIMIT));
        assert!(!got.flags.contains(ConfigFlags::CHECK_POLICY));
        assert_eq!(got.rl_interval_ns, 100_000);
        assert_eq!(got.rl_burst, 50);
        assert!(load("nonexistent").is_none());
        std::fs::remove_dir_all(&tmp).ok();
        std::env::remove_var("XS_STATE_DIR");
    }
}
