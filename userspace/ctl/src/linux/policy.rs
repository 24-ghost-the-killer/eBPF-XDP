//! Phase 2 block/allow/list commands: read and write the pinned policy and
//! allowlist maps, and keep the config's CHECK_* bits in step with whether
//! those maps are non-empty (so the dataplane only pays for the lookups when
//! there is something to find).
//!
//! Deadlines are computed against CLOCK_MONOTONIC, the clock the dataplane's
//! `bpf_ktime_get_ns()` reads, so a TTL means the same thing on both sides
//! and NTP steps cannot move it.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use xs_common::abi::ABI_VERSION;
use xs_common::pin::{
    PinLayout, MAP_ALLOW_V4, MAP_ALLOW_V6, MAP_CONFIG, MAP_POLICY_V4, MAP_POLICY_V6,
    MAP_PROTECTED_V4, MAP_SERVICE_V4,
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

    // SERVICE_ALLOW follows the protected-destination map. Tolerant if the map
    // is absent (a dataplane that predates the feature): treat as empty.
    let service = open(layout, MAP_PROTECTED_V4).map(|m| is_nonempty(&m)).unwrap_or(false);

    let cfg_map = open(layout, MAP_CONFIG)?;
    let mut cfg = read_config(&cfg_map)?;
    let before = cfg.flags;
    cfg.flags.set(ConfigFlags::CHECK_ALLOW, allow);
    cfg.flags.set(ConfigFlags::CHECK_POLICY, policy_);
    cfg.flags.set(ConfigFlags::SERVICE_ALLOW, service);
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

/// Build the 8-byte `struct xs_service_key`: daddr(be32) dport(be16) proto(u8) pad(u8).
fn service_key(v4: std::net::Ipv4Addr, proto: u8, port: u16) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0..4].copy_from_slice(&v4.octets());
    k[4..6].copy_from_slice(&port.to_be_bytes());
    k[6] = proto;
    k[7] = 0;
    k
}

/// Mark a destination as protected: default-deny everything to it except the
/// services added with `service`. IPv4 only (the maps are v4).
pub fn protect(layout: &PinLayout, ip: IpAddr) -> Result<()> {
    let IpAddr::V4(v4) = ip else { bail!("service allowlist is IPv4-only for now: {ip}") };
    let key = v4.octets();
    let map = open(layout, MAP_PROTECTED_V4)?;
    map.update(&key, &[1u8], MapFlags::ANY).context("insert protected destination")?;
    refresh_check_bits(layout)?;
    println!(
        "protecting {v4} (DEFAULT-DENY): only services added with `service` reach it; \
         all other traffic to it is dropped. Add your services now, e.g. \
         `sentinelctl service {v4} tcp 22`."
    );
    Ok(())
}

pub fn unprotect(layout: &PinLayout, ip: IpAddr) -> Result<()> {
    let IpAddr::V4(v4) = ip else { bail!("service allowlist is IPv4-only: {ip}") };
    let key = v4.octets();
    let map = open(layout, MAP_PROTECTED_V4)?;
    match map.delete(&key) {
        Ok(()) => println!("unprotected {v4}: default-deny lifted (its service entries are kept)"),
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => println!("{v4} was not protected"),
        Err(e) => return Err(e).context("delete protected destination"),
    }
    refresh_check_bits(layout)?;
    Ok(())
}

/// Add (or, with `remove`, delete) one permitted `{proto,dport}` service on a
/// destination. Use port 0 for portless protocols such as ICMP.
pub fn service(layout: &PinLayout, ip: IpAddr, proto: u8, port: u16, remove: bool) -> Result<()> {
    let IpAddr::V4(v4) = ip else { bail!("service allowlist is IPv4-only: {ip}") };
    let key = service_key(v4, proto, port);
    let map = open(layout, MAP_SERVICE_V4)?;
    if remove {
        match map.delete(&key) {
            Ok(()) => println!("removed service {v4} proto={proto} port={port}"),
            Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => {
                println!("{v4} proto={proto} port={port} was not a listed service")
            }
            Err(e) => return Err(e).context("delete service entry"),
        }
    } else {
        map.update(&key, &[1u8], MapFlags::ANY).context("insert service entry")?;
        let protected = open(layout, MAP_PROTECTED_V4).map(|m| is_nonempty(&m)).unwrap_or(false);
        println!("allowed service {v4} proto={proto} port={port}");
        if !protected {
            println!("note: {v4} is not protected yet, so this has no effect until you run `sentinelctl protect {v4}`");
        }
    }
    Ok(())
}

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn proto_name(p: u8) -> &'static str {
    match p {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        1 => "icmp",
        _ => "proto",
    }
}

/// Services parsed from `ufw status`, plus the rules we could not map.
struct UfwParse {
    services: Vec<(u8, u16)>,
    skipped: Vec<String>,
}

/// Turn one `ufw status` "To" port spec into `(proto, port)` pairs, or None if
/// it has no numeric port we can mirror (app profiles, "Anywhere", odd protos).
/// A bare port (no `/proto`) opens both TCP and UDP, matching ufw.
fn parse_port_spec(spec: &str) -> Option<Vec<(u8, u16)>> {
    if spec.is_empty() {
        return None;
    }
    let (ports, protos): (&str, Vec<u8>) = match spec.split_once('/') {
        Some((p, "tcp")) => (p, vec![PROTO_TCP]),
        Some((p, "udp")) => (p, vec![PROTO_UDP]),
        Some(_) => return None, // esp/ah/etc: no port concept in the allowlist
        None => (spec, vec![PROTO_TCP, PROTO_UDP]),
    };
    let (lo, hi) = match ports.split_once(':') {
        Some((a, b)) => (a.parse::<u16>().ok()?, b.parse::<u16>().ok()?),
        None => {
            let p = ports.parse::<u16>().ok()?;
            (p, p)
        }
    };
    if lo == 0 || hi < lo || (hi as u32 - lo as u32) > 1024 {
        return None; // 0, inverted, or a range too large to expand into the map
    }
    let mut out = Vec::new();
    for port in lo..=hi {
        for &pr in &protos {
            out.push((pr, port));
        }
    }
    Some(out)
}

/// Find the ALLOW/LIMIT action column, returning the "To" text before it and
/// the text after it (which begins with the direction, e.g. "" or "OUT").
/// DENY/REJECT lines and headers return None and are ignored.
fn find_action(line: &str) -> Option<(&str, &str)> {
    for kw in ["ALLOW", "LIMIT"] {
        if let Some(idx) = line.find(kw) {
            let at_column = idx == 0 || line.as_bytes()[idx - 1].is_ascii_whitespace();
            if at_column {
                return Some((&line[..idx], line[idx + kw.len()..].trim_start()));
            }
        }
    }
    None
}

/// Parse `ufw status` text into the IPv4 inbound services it opens.
fn parse_ufw_status(text: &str) -> UfwParse {
    let mut services = Vec::new();
    let mut skipped = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some((to, rest)) = find_action(line) else { continue };
        // Only inbound rules open a service; OUT/FWD do not.
        if rest.starts_with("OUT") || rest.starts_with("FWD") {
            continue;
        }
        let to = to.trim();
        if to.contains("(v6)") {
            continue; // the allowlist is IPv4-only
        }
        // The first whitespace token is the port spec; the rest ("on eth0",
        // trailing comments) does not change which port is opened.
        let spec = to.split_whitespace().next().unwrap_or("");
        match parse_port_spec(spec) {
            Some(list) => services.extend(list),
            None => skipped.push(to.to_string()),
        }
    }
    services.sort_unstable();
    services.dedup();
    UfwParse { services, skipped }
}

/// Run `ufw status` (needs root) and parse it. Refuses when ufw is inactive so
/// a sync never silently empties the allowlist.
fn ufw_services() -> Result<UfwParse> {
    let out = std::process::Command::new("ufw")
        .arg("status")
        .output()
        .context("run `ufw status` (is ufw installed, and are we root?)")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = if stderr.trim().is_empty() { &stdout } else { &stderr };
        bail!("`ufw status` failed: {}", msg.trim());
    }
    if stdout.contains("Status: inactive") {
        bail!("ufw is inactive; refusing to sync (it would empty the allowlist). Enable ufw or add services manually.");
    }
    Ok(parse_ufw_status(&stdout))
}

/// Mirror the box's ufw ALLOW rules into the service-allowlist for `ip`: add
/// ports ufw now opens, remove allowlist entries ufw no longer opens. With
/// `do_protect`, enable default-deny afterwards. With `dry_run`, only report.
pub fn service_sync(layout: &PinLayout, ip: IpAddr, do_protect: bool, dry_run: bool) -> Result<()> {
    let IpAddr::V4(v4) = ip else { bail!("service allowlist is IPv4-only: {ip}") };
    let parsed = ufw_services()?;
    let desired: HashSet<(u8, u16)> = parsed.services.iter().copied().collect();

    // The service map only exists once the new dataplane is loaded. A dry-run
    // should still preview the ufw parse before that, so tolerate a missing map
    // there (current set = empty); a real sync requires it.
    let map = match open(layout, MAP_SERVICE_V4) {
        Ok(m) => Some(m),
        Err(_) if dry_run => {
            println!("note: service map not present yet (new dataplane not loaded) -- previewing ufw parse only");
            None
        }
        Err(e) => return Err(e).context("open service allowlist map (is the new dataplane loaded?)"),
    };
    let mut current: HashSet<(u8, u16)> = HashSet::new();
    if let Some(ref m) = map {
        for key in m.keys() {
            if key.len() == 8 && key[..4] == v4.octets()[..] {
                current.insert((key[6], u16::from_be_bytes([key[4], key[5]])));
            }
        }
    }

    let mut to_add: Vec<(u8, u16)> = desired.difference(&current).copied().collect();
    let mut to_del: Vec<(u8, u16)> = current.difference(&desired).copied().collect();
    to_add.sort_unstable();
    to_del.sort_unstable();

    if !parsed.skipped.is_empty() {
        println!(
            "skipped {} ufw rule(s) with no numeric IPv4 port (add these manually if needed): {}",
            parsed.skipped.len(),
            parsed.skipped.join(", ")
        );
    }

    let tag = if dry_run { "(dry-run) " } else { "" };
    if to_add.is_empty() && to_del.is_empty() {
        println!("{v4}: allowlist already matches ufw ({} service(s))", desired.len());
    } else {
        for (p, port) in &to_add {
            println!("{tag}+ allow  {v4} {} {port}", proto_name(*p));
        }
        for (p, port) in &to_del {
            println!("{tag}- remove {v4} {} {port}", proto_name(*p));
        }
    }

    if dry_run {
        if do_protect {
            println!("{tag}would protect {v4} (default-deny)");
        }
        return Ok(());
    }

    let map = map.expect("service map is opened (non-dry-run returns Err above if absent)");
    for (p, port) in &to_add {
        map.update(&service_key(v4, *p, *port), &[1u8], MapFlags::ANY)
            .context("insert service entry")?;
    }
    for (p, port) in &to_del {
        if let Err(e) = map.delete(&service_key(v4, *p, *port)) {
            if e.kind() != libbpf_rs::ErrorKind::NotFound {
                return Err(e).context("delete stale service entry");
            }
        }
    }
    println!(
        "synced {v4} from ufw: {} service(s) allowed (+{} -{})",
        desired.len(),
        to_add.len(),
        to_del.len()
    );

    if do_protect {
        protect(layout, ip)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec_variants() {
        assert_eq!(parse_port_spec("22/tcp"), Some(vec![(PROTO_TCP, 22)]));
        assert_eq!(parse_port_spec("53/udp"), Some(vec![(PROTO_UDP, 53)]));
        // bare port = both transports
        assert_eq!(parse_port_spec("80"), Some(vec![(PROTO_TCP, 80), (PROTO_UDP, 80)]));
        // small range expands
        assert_eq!(
            parse_port_spec("6000:6001/tcp"),
            Some(vec![(PROTO_TCP, 6000), (PROTO_TCP, 6001)])
        );
        // unmappable specs
        assert_eq!(parse_port_spec("OpenSSH"), None);
        assert_eq!(parse_port_spec("Anywhere"), None);
        assert_eq!(parse_port_spec("500/esp"), None);
        assert_eq!(parse_port_spec("0/tcp"), None);
        // oversized range refused
        assert_eq!(parse_port_spec("1:5000/tcp"), None);
    }

    #[test]
    fn parses_ufw_status_table() {
        let text = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
3000                       ALLOW       Anywhere
8006/tcp                   LIMIT       Anywhere
8006/tcp on eth0           ALLOW       192.168.1.0/24
25/tcp                     DENY        Anywhere
1234/tcp                   ALLOW OUT   Anywhere
OpenSSH                    ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
";
        let p = parse_ufw_status(text);
        // DENY, OUT and v6 are excluded; LIMIT counts as allow; the
        // interface-bound 8006 dedups with the LIMIT 8006.
        assert!(p.services.contains(&(PROTO_TCP, 22)));
        assert!(p.services.contains(&(PROTO_TCP, 3000)));
        assert!(p.services.contains(&(PROTO_UDP, 3000)));
        assert!(p.services.contains(&(PROTO_TCP, 8006)));
        assert!(!p.services.contains(&(PROTO_TCP, 25))); // DENY
        assert!(!p.services.contains(&(PROTO_TCP, 1234))); // OUT
        // app profile reported as skipped
        assert!(p.skipped.iter().any(|s| s == "OpenSSH"));
    }
}
