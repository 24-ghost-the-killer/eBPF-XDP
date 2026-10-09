//! Phase 2 block/allow/list commands: read and write the pinned policy and
//! allowlist maps, and keep the config's CHECK_* bits in step with whether
//! those maps are non-empty (so the dataplane only pays for the lookups when
//! there is something to find).
//!
//! Deadlines are computed against CLOCK_MONOTONIC, the clock the dataplane's
//! `bpf_ktime_get_ns()` reads, so a TTL means the same thing on both sides
//! and NTP steps cannot move it.

use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use xs_common::abi::ABI_VERSION;
use xs_common::pin::{
    PinLayout, MAP_ALLOW_V4, MAP_ALLOW_V6, MAP_CONFIG, MAP_POLICY_V4, MAP_POLICY_V6,
};
use xs_common::policy::{
    self, Action, Allow, Policy, Reason, Trust, ALLOW_SIZE, LPM_V4_SIZE, LPM_V6_SIZE, POLICY_SIZE,
};
use xs_common::{Config, ConfigFlags};

use crate::TrustArg;

fn now_monotonic_ns() -> u64 {
    // SAFETY: clock_gettime writes a valid timespec through the pointer; the
    // struct is zero-initialised (a valid timespec) and outlives the call.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: CLOCK_MONOTONIC is a valid clock id and &mut ts is writable.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn deadline(ttl_s: u64) -> u64 {
    if ttl_s == 0 {
        0 // never expires
    } else {
        now_monotonic_ns().saturating_add(ttl_s.saturating_mul(1_000_000_000))
    }
}

fn open(layout: &PinLayout, name: &str) -> Result<MapHandle> {
    let path = layout.map(name);
    MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open {path:?} (is the program attached? it may predate Phase 2)"))
}

fn is_nonempty(map: &MapHandle) -> bool {
    map.keys().next().is_some()
}

/// Parse a CIDR ("10.0.0.0/8") or a bare IP ("10.0.0.1" = host route) into an
/// address and a prefix length, validating the prefix against the family.
fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    match s.split_once('/') {
        Some((addr, plen)) => {
            let ip: IpAddr = addr.parse().with_context(|| format!("invalid address {addr:?}"))?;
            let plen: u8 =
                plen.parse().with_context(|| format!("invalid prefix length {plen:?}"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if plen > max {
                bail!(
                    "prefix /{plen} is too long for {}",
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
                );
            }
            Ok((ip, plen))
        }
        None => {
            let ip: IpAddr = s.parse().with_context(|| format!("invalid CIDR or IP {s:?}"))?;
            Ok((ip, if ip.is_ipv4() { 32 } else { 128 }))
        }
    }
}

/// After any change, set CHECK_ALLOW / CHECK_POLICY to match whether the
/// corresponding maps hold anything. Never touches the operator drop flags.
fn refresh_check_bits(layout: &PinLayout) -> Result<()> {
    let allow =
        is_nonempty(&open(layout, MAP_ALLOW_V4)?) || is_nonempty(&open(layout, MAP_ALLOW_V6)?);
    let policy_ =
        is_nonempty(&open(layout, MAP_POLICY_V4)?) || is_nonempty(&open(layout, MAP_POLICY_V6)?);

    let cfg_map = open(layout, MAP_CONFIG)?;
    let mut cfg = read_config(&cfg_map)?;
    let before = cfg.flags;
    cfg.flags.set(ConfigFlags::CHECK_ALLOW, allow);
    cfg.flags.set(ConfigFlags::CHECK_POLICY, policy_);
    if cfg.flags != before {
        cfg.abi_version = ABI_VERSION;
        write_config(&cfg_map, cfg)?;
    }
    Ok(())
}

fn read_config(map: &MapHandle) -> Result<Config> {
    let raw = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow!("xs_config has no element 0"))?;
    Ok(Config::from_bytes(&raw)?)
}

fn write_config(map: &MapHandle, cfg: Config) -> Result<()> {
    map.update(&0u32.to_ne_bytes(), &cfg.to_bytes(), MapFlags::ANY)?;
    Ok(())
}

pub fn ratelimit(layout: &PinLayout, pps: u32, burst: u32) -> Result<()> {
    let cfg_map = open(layout, MAP_CONFIG)?;
    let mut cfg = read_config(&cfg_map)?;
    if pps == 0 {
        cfg.flags.set(ConfigFlags::RATELIMIT, false);
        cfg.rl_interval_ns = 0;
        cfg.rl_burst = 0;
        cfg.abi_version = ABI_VERSION;
        write_config(&cfg_map, cfg)?;
        let _ = xs_common::state::save(layout.iface(), &cfg);
        println!("per-source rate limiter disabled");
        return Ok(());
    }
    let burst = if burst == 0 { (pps / 10).max(20) } else { burst };
    cfg.flags.set(ConfigFlags::RATELIMIT, true);
    cfg.rl_interval_ns = 1_000_000_000 / pps;
    cfg.rl_burst = burst;
    cfg.abi_version = ABI_VERSION;
    write_config(&cfg_map, cfg)?;
    let _ = xs_common::state::save(layout.iface(), &cfg);
    println!("per-source rate limiter: {pps} pps/source, burst {burst} packets (allowlisted sources exempt)");
    Ok(())
}

pub fn block(layout: &PinLayout, ip: IpAddr, ttl_s: u64) -> Result<()> {
    let (key, map_name) = match ip {
        IpAddr::V4(v4) => (policy::policy_key_v4(v4).to_vec(), MAP_POLICY_V4),
        IpAddr::V6(v6) => (policy::policy_key_v6(v6).to_vec(), MAP_POLICY_V6),
    };
    let pol = Policy {
        expires_ns: deadline(ttl_s),
        policy_id: (now_monotonic_ns() as u32) | 1,
        action: Action::Drop,
        reason: Reason::Manual,
    };
    let map = open(layout, map_name)?;
    map.update(&key, &pol.to_bytes(), MapFlags::ANY).context("insert block policy")?;
    refresh_check_bits(layout)?;
    let scope = if ip.is_ipv6() { " (/64)" } else { "" };
    match ttl_s {
        0 => println!("blocking {ip}{scope} until removed"),
        _ => println!("blocking {ip}{scope} for {ttl_s}s"),
    }
    Ok(())
}

pub fn unblock(layout: &PinLayout, ip: IpAddr) -> Result<()> {
    let (key, map_name) = match ip {
        IpAddr::V4(v4) => (policy::policy_key_v4(v4).to_vec(), MAP_POLICY_V4),
        IpAddr::V6(v6) => (policy::policy_key_v6(v6).to_vec(), MAP_POLICY_V6),
    };
    let map = open(layout, map_name)?;
    match map.delete(&key) {
        Ok(()) => println!("unblocked {ip}"),
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => println!("{ip} was not blocked"),
        Err(e) => return Err(e).context("delete block policy"),
    }
    refresh_check_bits(layout)?;
    Ok(())
}

pub fn allow(layout: &PinLayout, cidr: &str, trust: TrustArg, ttl_s: u64) -> Result<()> {
    let (ip, plen) = parse_cidr(cidr)?;
    let key = policy::lpm_key(ip, plen);
    let val = Allow {
        expires_ns: deadline(ttl_s),
        trust: match trust {
            TrustArg::Full => Trust::Full,
            TrustArg::DynamicExempt => Trust::DynamicExempt,
        },
    };
    let map_name = if ip.is_ipv4() { MAP_ALLOW_V4 } else { MAP_ALLOW_V6 };
    let map = open(layout, map_name)?;
    map.update(&key, &val.to_bytes(), MapFlags::ANY).context("insert allowlist entry")?;
    refresh_check_bits(layout)?;
    println!(
        "allowlisted {ip}/{plen} trust={}{}",
        val.trust.as_str(),
        if ttl_s == 0 { String::new() } else { format!(" for {ttl_s}s") }
    );
    Ok(())
}

pub fn unallow(layout: &PinLayout, cidr: &str) -> Result<()> {
    let (ip, plen) = parse_cidr(cidr)?;
    let key = policy::lpm_key(ip, plen);
    let map_name = if ip.is_ipv4() { MAP_ALLOW_V4 } else { MAP_ALLOW_V6 };
    let map = open(layout, map_name)?;
    match map.delete(&key) {
        Ok(()) => println!("removed allowlist entry {ip}/{plen}"),
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => {
            println!("{ip}/{plen} was not allowlisted")
        }
        Err(e) => return Err(e).context("delete allowlist entry"),
    }
    refresh_check_bits(layout)?;
    Ok(())
}

/// Remaining TTL as a human string, or "never"/"expired".
fn ttl_str(expires_ns: u64, now: u64) -> String {
    if expires_ns == 0 {
        "never".into()
    } else if expires_ns <= now {
        "expired".into()
    } else {
        format!("{}s", (expires_ns - now) / 1_000_000_000)
    }
}

pub fn list(layout: &PinLayout, json: bool) -> Result<()> {
    let now = now_monotonic_ns();
    let mut blocks: Vec<(IpAddr, Policy)> = Vec::new();
    let mut allows: Vec<(IpAddr, u8, Allow)> = Vec::new();

    for (name, is_v6) in [(MAP_POLICY_V4, false), (MAP_POLICY_V6, true)] {
        let map = open(layout, name)?;
        for key in map.keys() {
            if let Some(raw) = map.lookup(&key, MapFlags::ANY)? {
                if raw.len() != POLICY_SIZE {
                    continue;
                }
                let ip = if is_v6 {
                    let mut o = [0u8; 16];
                    o[..key.len().min(16)].copy_from_slice(&key[..key.len().min(16)]);
                    IpAddr::from(o)
                } else {
                    match policy::policy_addr_v4(&key) {
                        Some(a) => IpAddr::V4(a),
                        None => continue,
                    }
                };
                blocks.push((ip, Policy::from_bytes(&raw)?));
            }
        }
    }
    for name in [MAP_ALLOW_V4, MAP_ALLOW_V6] {
        let map = open(layout, name)?;
        for key in map.keys() {
            if key.len() != LPM_V4_SIZE && key.len() != LPM_V6_SIZE {
                continue;
            }
            if let (Some((ip, plen)), Some(raw)) =
                (policy::lpm_decode(&key), map.lookup(&key, MapFlags::ANY)?)
            {
                if raw.len() == ALLOW_SIZE {
                    allows.push((ip, plen, Allow::from_bytes(&raw)?));
                }
            }
        }
    }

    if json {
        print_json(layout.iface(), &blocks, &allows, now);
        return Ok(());
    }

    let cfg = read_config(&open(layout, MAP_CONFIG)?)?;
    println!("interface {}:", layout.iface());
    if cfg.flags.contains(ConfigFlags::RATELIMIT) && cfg.rl_pps() > 0 {
        println!("  rate limiter: {} pps/source, burst {} packets", cfg.rl_pps(), cfg.rl_burst);
    } else {
        println!("  rate limiter: off");
    }
    println!("  blocks: {}", blocks.len());
    for (ip, p) in &blocks {
        println!(
            "    {:<39} {:<5} {:<8} reason={} ttl={}",
            ip.to_string(),
            p.action.as_str(),
            "",
            p.reason.as_str(),
            ttl_str(p.expires_ns, now)
        );
    }
    println!("  allowlist: {}", allows.len());
    for (ip, plen, a) in &allows {
        println!(
            "    {:<39} trust={:<14} ttl={}",
            format!("{ip}/{plen}"),
            a.trust.as_str(),
            ttl_str(a.expires_ns, now)
        );
    }
    Ok(())
}

fn print_json(iface: &str, blocks: &[(IpAddr, Policy)], allows: &[(IpAddr, u8, Allow)], now: u64) {
    let b: Vec<String> = blocks
        .iter()
        .map(|(ip, p)| {
            format!(
                r#"{{"ip":"{ip}","action":"{}","reason":"{}","ttl":"{}"}}"#,
                p.action.as_str(),
                p.reason.as_str(),
                ttl_str(p.expires_ns, now)
            )
        })
        .collect();
    let a: Vec<String> = allows
        .iter()
        .map(|(ip, plen, al)| {
            format!(
                r#"{{"cidr":"{ip}/{plen}","trust":"{}","ttl":"{}"}}"#,
                al.trust.as_str(),
                ttl_str(al.expires_ns, now)
            )
        })
        .collect();
    println!(r#"{{"iface":"{iface}","blocks":[{}],"allowlist":[{}]}}"#, b.join(","), a.join(","));
}
