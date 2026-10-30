//! Linux implementation of the agent: dataplane attach/adopt and the metrics
//! HTTP server.
//!
//! The HTTP server is a small, dependency-free blocking server (no async
//! runtime): `/metrics` is scraped every few seconds and the responses are
//! tiny, so a thread-per-accept loop is ample and keeps the agent's
//! dependency and attack surface minimal. tokio/axum arrive in a later phase
//! when genuinely asynchronous work (the inference client, the ClickHouse
//! writer, SSE) is added.

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle, ObjectBuilder, Program, Xdp, XdpFlags};
use xs_common::classifier::Classifier;
use xs_common::detect::{Detector, RobustBaseline};
use xs_common::features::{self, WindowInput};
use xs_common::iforest::Forest;
use xs_common::risk::{Evidence, RiskEngine};
use xs_common::metrics::prometheus;
use xs_common::pin::{
    PinLayout, MAP_ATTACKER_V4, MAP_CONFIG, MAP_POLICY_V4, MAP_POLICY_V6, MAP_PROTECTED_V4,
    MAP_SERVICE_V4, MAP_STATS, MAP_VICTIM_V4, PROG_NAME,
};
use xs_common::{Config as DpConfig, ConfigFlags, Snapshot};

use crate::config::{Config, Interface, Mode};

/// `BPF_FS_MAGIC` from `<linux/magic.h>`.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    STOP.store(true, Ordering::SeqCst);
}

/// CLOCK_MONOTONIC in ns — the same clock the dataplane's `bpf_ktime_get_ns()`
/// reads, so a policy's `expires_ns` means the same thing on both sides.
fn now_monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: CLOCK_MONOTONIC is a valid clock id and &mut ts is writable.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

/// Reclaim expired entries from one per-source policy map (plain HASH, so they
/// never auto-evict). Expiry is ALSO enforced in-kernel — an entry past its
/// deadline is already inert — so this only frees map slots; it never changes a
/// verdict. `expires_ns` is the first 8 bytes of `struct xs_policy` (native
/// endian); 0 means "never expires". Returns the number deleted.
fn gc_policy_map(path: &Path, now: u64) -> usize {
    let Ok(map) = MapHandle::from_pinned_path(path) else { return 0 };
    // Collect first, then delete, so we never delete the key the iterator is on.
    let mut expired: Vec<Vec<u8>> = Vec::new();
    for key in map.keys() {
        if let Ok(Some(val)) = map.lookup(&key, MapFlags::ANY) {
            if val.len() >= 8 {
                let exp = u64::from_ne_bytes(val[0..8].try_into().unwrap());
                if exp != 0 && exp < now {
                    expired.push(key);
                }
            }
        }
    }
    expired.iter().filter(|k| map.delete(k).is_ok()).count()
}

pub fn run(cfg: Config) -> Result<()> {
    // Best-effort libbpf log routing to stderr (journald).
    let _ = libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |lvl, msg| {
        eprint!("libbpf[{lvl:?}]: {msg}");
    })));

    // SAFETY: registering a trivial C signal handler that only sets an atomic.
    unsafe {
        let handler = on_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }

    for iface in &cfg.interfaces {
        let layout = PinLayout::new(&cfg.pin_root, &iface.name)?;
        match ensure_dataplane(&cfg, iface, &layout) {
            Ok(mode) => {
                eprintln!("interface {}: dataplane {mode}", iface.name);
                // Restore the operator's saved mitigation config (drop flags +
                // rate limiter), since a reboot wiped the pinned config map.
                if let Err(e) = restore_config(&layout) {
                    eprintln!("interface {}: restore config: {e:#}", iface.name);
                }
            }
            Err(e) => eprintln!("interface {}: {e:#}", iface.name),
        }
    }

    serve(&cfg)
}

/// Attach the program (reusing pinned maps) or adopt an existing attachment.
/// Never clobbers a foreign XDP program and never detaches anything.
fn ensure_dataplane(cfg: &Config, iface: &Interface, layout: &PinLayout) -> Result<&'static str> {
    let ifindex = ifindex(&iface.name)?;
    let attached = attached_prog_id(ifindex)?;
    let ours = pinned_prog_id(layout);

    if attached != 0 && Some(attached) == ours {
        return Ok("already attached (adopted)");
    }
    if !iface.attach {
        return Ok(if attached != 0 {
            "adopted (attach=false)"
        } else {
            "not attached (attach=false)"
        });
    }
    if attached != 0 {
        // Something else owns XDP on this interface; do not clobber it.
        bail!("a foreign XDP program (id {attached}) is attached; not replacing it");
    }

    ensure_bpffs(layout.dir())?;
    fs::create_dir_all(layout.dir())?;

    let mut open = ObjectBuilder::default()
        .open_file(&cfg.bpf_obj)
        .with_context(|| format!("open {}", cfg.bpf_obj.display()))?;
    for mut m in open.maps_mut() {
        let name = m.name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        m.set_pin_path(layout.map(&name))?;
    }
    let obj = open.load().context("load BPF object (verifier or incompatible pinned maps)")?;
    let mut prog = obj
        .progs_mut()
        .find(|p| p.name() == PROG_NAME)
        .ok_or_else(|| anyhow!("object has no program {PROG_NAME}"))?;

    let mode_flag = match iface.mode {
        Mode::Native => XdpFlags::DRV_MODE,
        Mode::Generic => XdpFlags::SKB_MODE,
    };
    Xdp::new(prog.as_fd())
        .attach(ifindex, mode_flag | XdpFlags::UPDATE_IF_NOEXIST)
        .with_context(|| format!("attach in {:?} mode", iface.mode))?;

    let prog_pin = layout.prog();
    let _ = fs::remove_file(&prog_pin);
    prog.pin(&prog_pin).with_context(|| format!("pin program at {prog_pin:?}"))?;
    Ok("attached")
}

/// Reapply the operator's saved config (drop flags + rate-limiter params) to
/// the freshly-attached dataplane. Auto-managed CHECK_* bits are taken from
/// the live map (0 on a fresh boot), not from the saved file, so policy
/// checking is never enabled without policies present.
fn restore_config(layout: &PinLayout) -> Result<()> {
    let Some(saved) = xs_common::state::load(layout.iface()) else {
        return Ok(());
    };
    let map = MapHandle::from_pinned_path(layout.map(MAP_CONFIG))
        .with_context(|| format!("open config map for {}", layout.iface()))?;
    let raw = map.lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?.unwrap_or_default();
    let current = DpConfig::from_bytes(&raw).unwrap_or_default();

    let managed = ConfigFlags::CHECK_ALLOW.bits() | ConfigFlags::CHECK_POLICY.bits()
            | ConfigFlags::SERVICE_ALLOW.bits() | ConfigFlags::LOCKDOWN.bits();
    let flags = ConfigFlags::from_bits_retain(
        (saved.flags.bits() & !managed) | (current.flags.bits() & managed),
    );
    let new = DpConfig {
        abi_version: xs_common::abi::ABI_VERSION,
        flags,
        rl_interval_ns: saved.rl_interval_ns,
        rl_burst: saved.rl_burst,
        // Phase 5 telemetry epoch/shift and the aggregate limiter are owned by
        // the collector/analysis loop at runtime; preserve the live values.
        hll_epoch: current.hll_epoch,
        sample_shift: current.sample_shift,
        global_rl_interval_ns: current.global_rl_interval_ns,
        global_rl_burst: current.global_rl_burst,
    };
    map.update(&0u32.to_ne_bytes(), &new.to_bytes(), MapFlags::ANY)?;
    eprintln!("interface {}: restored saved config {:?}", layout.iface(), flags);
    Ok(())
}

fn ifindex(iface: &str) -> Result<i32> {
    let name = CString::new(iface)?;
    // SAFETY: valid NUL-terminated string, not retained by the callee.
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("interface {iface}"));
    }
    Ok(idx as i32)
}

fn attached_prog_id(ifindex: i32) -> Result<u32> {
    let devnull = fs::File::open("/dev/null")?;
    Ok(Xdp::new(devnull.as_fd()).query_id(ifindex, XdpFlags::NONE).unwrap_or(0))
}

fn pinned_prog_id(layout: &PinLayout) -> Option<u32> {
    let fd = Program::fd_from_pinned_path(layout.prog()).ok()?;
    Program::id_from_fd(fd.as_fd()).ok()
}

fn ensure_bpffs(path: &Path) -> Result<()> {
    let mut probe = path;
    while !probe.exists() {
        probe = probe.parent().ok_or_else(|| anyhow!("no existing parent of {path:?}"))?;
    }
    let c = CString::new(probe.as_os_str().as_encoded_bytes())?;
    // SAFETY: zero-initialised statfs is valid; c is a valid C string.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid string and writable statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("statfs");
    }
    #[allow(clippy::unnecessary_cast)]
    if st.f_type as i64 != BPF_FS_MAGIC {
        bail!("{probe:?} is not a bpffs mount (mount -t bpf bpf /sys/fs/bpf)");
    }
    Ok(())
}

/// Attach mode string for one interface, matching what the program reports.
fn iface_mode(ifindex: i32, layout: &PinLayout) -> &'static str {
    let ours = match pinned_prog_id(layout) {
        Some(id) => id,
        None => return "none",
    };
    let Ok(devnull) = fs::File::open("/dev/null") else { return "none" };
    let Ok(info) = Xdp::new(devnull.as_fd()).query(ifindex, XdpFlags::NONE) else { return "none" };
    if info.prog_id != ours {
        return "none";
    }
    match info.attach_mode {
        1 => "native",
        2 => "generic",
        3 => "offload",
        _ => "none",
    }
}

/// Read one interface's counters + config and render its metrics block.
fn iface_metrics(iface: &str, layout: &PinLayout) -> Result<String> {
    let snap = read_snapshot(iface, layout)?;
    let flags = read_flags(layout);
    let flag_pairs: Vec<(&str, bool)> =
        ConfigFlags::NAMES.iter().map(|(f, n)| (*n, flags.contains(*f))).collect();
    let mode = iface_mode(ifindex(iface)?, layout);
    Ok(prometheus(iface, &snap, mode, &flag_pairs))
}

fn all_metrics(cfg: &Config, analyses: &[(String, Arc<Mutex<Analysis>>)]) -> String {
    let mut body = String::from(
        "# HELP xs_agent_up 1 while the agent process is running.\n# TYPE xs_agent_up gauge\nxs_agent_up 1\n",
    );
    for iface in &cfg.interfaces {
        match PinLayout::new(&cfg.pin_root, &iface.name) {
            Ok(layout) => {
                match iface_metrics(&iface.name, &layout) {
                    Ok(b) => body.push_str(&b),
                    Err(_) => body.push_str(&format!(
                        "xs_dataplane_attached{{iface=\"{}\",mode=\"none\"}} 0\n",
                        iface.name
                    )),
                }
                body.push_str(&render_victims(&iface.name, &layout));
            }
            Err(_) => body.push_str(&format!(
                "xs_dataplane_attached{{iface=\"{}\",mode=\"none\"}} 0\n",
                iface.name
            )),
        }
    }
    // Phase 6-13 analysis gauges (detector, models, risk) — one block per
    // interface, so each monitored interface reports its own threat/risk/class.
    for (_name, slot) in analyses {
        if let Ok(a) = slot.lock() {
            if a.valid {
                body.push_str(&render_analysis(&a));
            }
        }
    }
    body
}

/// Export the top entries of a drop-accounting LRU map (keyed by an IPv4
/// address) as `<metric>_packets_total` / `<metric>_bytes_total`, labelled by
/// `label` (dst for victims, src for attackers). The dataplane credits these
/// maps only on a drop, so when nothing is being mitigated they're empty and
/// no series is emitted (idle = silent). Cardinality is bounded to the top N.
fn render_drop_ips(iface: &str, layout: &PinLayout, map_name: &str, metric: &str, label: &str, count_metric: &str) -> String {
    // Export every source/dest the LRU map holds (its max_entries is the ceiling:
    // 8192 for attackers, 4096 for victims), so the dashboard can list ALL
    // attributable sources, not just the top few. For a distributed botnet this
    // surfaces every member; for a fully source-spoofed flood the map churns many
    // 1-packet sources (none dominant), which the UI already summarises instead of
    // listing. `xs_<count_metric>` still reports the true distinct total.
    const TOP_N: usize = 8192;
    let Ok(map) = MapHandle::from_pinned_path(layout.map(map_name)) else {
        return String::new();
    };
    let mut rows: Vec<([u8; 4], u64, u64)> = Vec::new();
    for key in map.keys() {
        if key.len() != 4 {
            continue;
        }
        let Ok(Some(val)) = map.lookup(&key, MapFlags::ANY) else {
            continue;
        };
        if val.len() < 16 {
            continue;
        }
        let pkts = u64::from_ne_bytes(val[0..8].try_into().unwrap());
        let bytes = u64::from_ne_bytes(val[8..16].try_into().unwrap());
        if pkts == 0 {
            continue;
        }
        rows.push(([key[0], key[1], key[2], key[3]], pkts, bytes));
    }
    if rows.is_empty() {
        return String::new();
    }
    // Total distinct addresses (up to the map's LRU cap) — the spoofed-vs-targeted
    // signal. A spoofed flood fills this into the thousands; a targeted one is few.
    let total_distinct = rows.len();
    rows.sort_by(|a, b| b.1.cmp(&a.1));
    rows.truncate(TOP_N);

    let mut s = String::new();
    s.push_str(&format!("# HELP {count_metric} Distinct addresses seen in the drop-accounting map (up to its LRU cap).\n"));
    s.push_str(&format!("# TYPE {count_metric} gauge\n"));
    s.push_str(&format!("{count_metric}{{iface=\"{iface}\"}} {total_distinct}\n"));
    s.push_str(&format!("# HELP {metric}_packets_total Dropped attack packets per {label} since attach.\n"));
    s.push_str(&format!("# TYPE {metric}_packets_total counter\n"));
    for (ip, pkts, _) in &rows {
        s.push_str(&format!(
            "{metric}_packets_total{{iface=\"{iface}\",{label}=\"{}.{}.{}.{}\"}} {pkts}\n",
            ip[0], ip[1], ip[2], ip[3]
        ));
    }
    s.push_str(&format!("# HELP {metric}_bytes_total Dropped attack bytes per {label} since attach.\n"));
    s.push_str(&format!("# TYPE {metric}_bytes_total counter\n"));
    for (ip, _, bytes) in &rows {
        s.push_str(&format!(
            "{metric}_bytes_total{{iface=\"{iface}\",{label}=\"{}.{}.{}.{}\"}} {bytes}\n",
            ip[0], ip[1], ip[2], ip[3]
        ));
    }
    s
}

/// Victim (dst) and attacker (src) drop-accounting for an interface.
fn render_victims(iface: &str, layout: &PinLayout) -> String {
    let mut s = render_drop_ips(iface, layout, MAP_VICTIM_V4, "xs_target", "dst", "xs_target_hosts");
    s.push_str(&render_drop_ips(iface, layout, MAP_ATTACKER_V4, "xs_attacker", "src", "xs_attacker_sources"));
    s
}

// ---- Phase 6/9 live state for the dashboard (/api/state.json) ----

/// Cross-request state for the JSON API: the previous counter snapshot (for
/// rate deltas), a warmed statistical detector, and an optional DDoS
/// classifier. One primary interface drives the dashboard view.
struct ApiState {
    prev: Option<(Instant, Snapshot)>,
    prev_pps: f64,
    detector: Detector,
    classifier: Option<Classifier>,
    host: String,
}

impl ApiState {
    fn new() -> Self {
        let classifier = fs::read("/usr/lib/xdp-sentinel/models/classifier/v1/model.json")
            .ok()
            .and_then(|b| Classifier::from_json(&b).ok())
            .filter(|c| c.schema_hash() == features::schema_hash());
        ApiState {
            prev: None,
            prev_pps: f64::NAN,
            detector: Detector::new(features::N),
            classifier,
            host: fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "host".into()),
        }
    }
}

/// Sum the packet counts of every counter whose name starts with `prefix`.
fn sum_prefix(snap: &Snapshot, prefix: &str) -> u64 {
    xs_common::abi::COUNTERS
        .iter()
        .filter(|d| d.name.starts_with(prefix))
        .map(|d| snap.get(d.slot).packets)
        .sum()
}

/// One counter's packet count, by stable name.
fn cval(snap: &Snapshot, name: &str) -> u64 {
    xs_common::abi::COUNTERS
        .iter()
        .find(|d| d.name == name)
        .map(|d| snap.get(d.slot).packets)
        .unwrap_or(0)
}

/// Build the `/api/services.json` body: the service allowlist (default-deny)
/// state per managed interface -- which destinations are protected and which
/// `{proto, port}` services are permitted on each. Read-only; the dashboard's
/// Protection page renders it. Reads the pinned maps the agent already owns.
fn api_services_json(cfg: &Config) -> String {
    use std::collections::BTreeMap;

    let proto_name = |p: u8| -> &'static str {
        match p {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            _ => "other",
        }
    };

    let mut ifaces = Vec::new();
    for iface in &cfg.interfaces {
        let name = iface.name.clone();
        let Ok(layout) = PinLayout::new(&cfg.pin_root, &name) else { continue };

        // Group service entries by destination IP.
        let mut by_ip: BTreeMap<[u8; 4], Vec<(u8, u16)>> = BTreeMap::new();
        if let Ok(m) = MapHandle::from_pinned_path(layout.map(MAP_SERVICE_V4)) {
            for key in m.keys() {
                if key.len() == 8 {
                    let ip = [key[0], key[1], key[2], key[3]];
                    let port = u16::from_be_bytes([key[4], key[5]]);
                    by_ip.entry(ip).or_default().push((key[6], port));
                }
            }
        }

        let mut protected = Vec::new();
        if let Ok(m) = MapHandle::from_pinned_path(layout.map(MAP_PROTECTED_V4)) {
            for key in m.keys() {
                if key.len() == 4 {
                    let ip = [key[0], key[1], key[2], key[3]];
                    let mut svcs = by_ip.get(&ip).cloned().unwrap_or_default();
                    svcs.sort_unstable();
                    let services: Vec<_> = svcs
                        .iter()
                        .map(|(p, port)| serde_json::json!({"proto": proto_name(*p), "port": port}))
                        .collect();
                    protected.push(serde_json::json!({
                        "ip": std::net::Ipv4Addr::from(ip).to_string(),
                        "services": services,
                    }));
                }
            }
        }
        protected.sort_by(|a, b| a["ip"].as_str().cmp(&b["ip"].as_str()));
        ifaces.push(serde_json::json!({"iface": name, "protected": protected}));
    }
    serde_json::json!({"interfaces": ifaces}).to_string()
}

/// Build the `/api/state.json` body: real rate deltas plus a live Phase 9
/// detection on the current window. Decisions require the per-source pipeline
/// (a follow-on), so that list is empty until it lands.
fn api_state_json(cfg: &Config, api: &mut ApiState) -> String {
    let Some(iface) = cfg.interfaces.first() else {
        return serde_json::json!({"attached": false, "host": api.host}).to_string();
    };
    let name = iface.name.clone();
    let layout = match PinLayout::new(&cfg.pin_root, &name) {
        Ok(l) => l,
        Err(_) => return serde_json::json!({"attached": false, "iface": name}).to_string(),
    };
    let snap = match read_snapshot(&name, &layout) {
        Ok(s) => s,
        Err(_) => {
            return serde_json::json!({"attached": false, "iface": name, "host": api.host})
                .to_string()
        }
    };
    let mode = ifindex(&name).map(|ix| iface_mode(ix, &layout)).unwrap_or("none");
    let flags = read_flags(&layout);
    let shadow = false;

    let now = Instant::now();
    // Rate deltas versus the previous request (~poll interval).
    let (dt, delta) = match &api.prev {
        Some((t0, prev)) => ((now - *t0).as_secs_f64().max(1e-3), snap.delta_since(prev)),
        None => (1.0, snap.delta_since(&snap)), // first call: zeros
    };

    let packets = cval(&delta, "rx");
    let bytes = delta.get(xs_common::abi::slot::RX).bytes;
    let dropped = cval(&delta, "verdict_drop");
    let udp = cval(&delta, "l4_udp");
    let tcp = cval(&delta, "l4_tcp");
    let icmp = cval(&delta, "l4_icmp") + cval(&delta, "l4_icmpv6");
    let wi = WindowInput {
        dt_s: dt,
        packets,
        bytes,
        dropped,
        tcp_syn: cval(&delta, "tcp_syn"),
        tcp_synack: cval(&delta, "tcp_synack"),
        tcp_ack: cval(&delta, "tcp_ack"),
        tcp_rst: cval(&delta, "tcp_rst"),
        tcp_fin: cval(&delta, "tcp_fin"),
        tcp_bad_flags: cval(&delta, "anom_tcp_bad_flags"),
        tcp_total: tcp,
        udp,
        udp_bytes: delta.get(25).bytes,
        udp_len_mismatch: cval(&delta, "anom_udp_len_mismatch"),
        icmp,
        frag: cval(&delta, "frag_first") + cval(&delta, "frag_later"),
        other_l4: cval(&delta, "l4_other"),
        malformed: sum_prefix(&delta, "parse_err_"),
        unsupported: sum_prefix(&delta, "parse_unsup_"),
        prev_pps: api.prev_pps,
        ..Default::default()
    };
    let vec = features::compute(&wi);
    let det = api.detector.detect(&vec);
    let pps = packets as f64 / dt;

    // Name the attack: prefer the trained classifier, else the rule set.
    let (atype, ddos) = if det.anomalous {
        if let Some(clf) = &api.classifier {
            let (class, p) = clf.predict(&vec);
            if class != "benign" {
                (class, p)
            } else {
                (det.suspected.map(|t| t.as_str().to_string()).unwrap_or_else(|| "anomaly".into()), 0.6)
            }
        } else {
            (det.suspected.map(|t| t.as_str().to_string()).unwrap_or_else(|| "anomaly".into()), 0.85)
        }
    } else {
        ("normal".into(), 0.0)
    };
    // Map the robust z-score into a 0..1 anomaly indicator for display.
    let anomaly = if det.score.is_finite() { 1.0 - (-det.score / 8.0).exp() } else { 0.9 };

    let drop_ratio = if pps > 0.0 { dropped as f64 / packets as f64 } else { 0.0 };
    let state = if det.anomalous {
        "under_attack"
    } else if drop_ratio > 0.2 || det.score > 4.0 {
        "suspect"
    } else {
        "normal"
    };

    let mut detections = Vec::new();
    if det.anomalous && api.prev.is_some() {
        detections.push(serde_json::json!({
            "ts": rfc3339_now(),
            "service": name,
            "type": atype,
            "anomaly": (anomaly * 100.0).round() / 100.0,
            "ddos": (ddos * 100.0).round() / 100.0,
            "confidence": 1.0,
            "reasons": det.reasons,
        }));
    }

    api.prev = Some((now, snap));
    api.prev_pps = pps;

    let share = |n: u64| if packets > 0 { n as f64 / packets as f64 } else { 0.0 };
    serde_json::json!({
        "host": api.host,
        "iface": name,
        "attached": mode != "none",
        "mode": mode,
        "schema_hash": features::schema_hash(),
        "window_ms": (dt * 1000.0) as u64,
        "state": state,
        "traffic": {
            "pps": pps,
            "bps": 8.0 * bytes as f64 / dt,
            "drop_pps": dropped as f64 / dt,
            "unique_src": 0,          // HLL estimate: follow-on
            "unique_flows": 0,
            "share_tcp": share(tcp),
            "share_udp": share(udp),
            "share_icmp": share(icmp),
        },
        "detections": detections,
        "decisions": [],              // per-source risk engine: follow-on
        "breaker_tripped": false,
        "shadow": shadow,
        "flags": ConfigFlags::NAMES.iter()
            .filter(|(f, _)| flags.contains(*f)).map(|(_, n)| *n).collect::<Vec<_>>(),
    })
    .to_string()
}

/// Minimal RFC3339 UTC timestamp without pulling in a time crate.
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // days since epoch -> Y/M/D (civil calendar, Howard Hinnant's algorithm)
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60
    )
}

/// Read one interface's per-CPU stats into a Snapshot.
fn read_snapshot(iface: &str, layout: &PinLayout) -> Result<Snapshot> {
    let stats = MapHandle::from_pinned_path(layout.map(MAP_STATS))
        .with_context(|| format!("open stats map for {iface}"))?;
    let vals = stats
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow!("stats map empty"))?;
    Ok(Snapshot::from_percpu(&vals)?)
}

/// Read the config flags for an interface (defaults if unreadable).
fn read_flags(layout: &PinLayout) -> ConfigFlags {
    match MapHandle::from_pinned_path(layout.map(MAP_CONFIG)) {
        Ok(m) => {
            let raw = m.lookup(&0u32.to_ne_bytes(), MapFlags::ANY).ok().flatten().unwrap_or_default();
            DpConfig::from_bytes(&raw).map(|c| c.flags).unwrap_or_default()
        }
        Err(_) => ConfigFlags::default(),
    }
}

// ---- Phase 6-13 analysis loop: features -> detector/models/risk -> gauges ----

/// Build the feature-window input from a counter delta over `dt` seconds.
fn window_input(delta: &Snapshot, dt: f64, prev_pps: f64) -> WindowInput {
    let cv = |n: &str| cval(delta, n);
    let tcp = cv("l4_tcp");
    let udp = cv("l4_udp");
    let icmp = cv("l4_icmp") + cv("l4_icmpv6");
    let icmpv6 = cv("l4_icmpv6");
    let ipv6 = cv("l3_ipv6");
    let ipv6_ext = cv("ipv6_ext");
    WindowInput {
        dt_s: dt,
        packets: cv("rx"),
        bytes: delta.get(xs_common::abi::slot::RX).bytes,
        dropped: cv("verdict_drop"),
        tcp_syn: cv("tcp_syn"),
        tcp_synack: cv("tcp_synack"),
        tcp_ack: cv("tcp_ack"),
        tcp_rst: cv("tcp_rst"),
        tcp_fin: cv("tcp_fin"),
        tcp_bad_flags: cv("anom_tcp_bad_flags"),
        tcp_total: tcp,
        udp,
        udp_bytes: delta.get(25).bytes,
        udp_len_mismatch: cv("anom_udp_len_mismatch"),
        icmp,
        icmpv6,
        ipv6,
        ipv6_ext,
        ct_untracked: cv("ct_untracked"),
        frag: cv("frag_first") + cv("frag_later"),
        other_l4: cv("l4_other"),
        malformed: sum_prefix(delta, "parse_err_"),
        unsupported: sum_prefix(delta, "parse_unsup_"),
        prev_pps,
        ..Default::default()
    }
}

/// Where the trained model artefacts live (override with XS_MODEL_DIR).
fn model_dir() -> PathBuf {
    if let Ok(d) = std::env::var("XS_MODEL_DIR") {
        return PathBuf::from(d);
    }
    for c in ["/usr/lib/xdp-sentinel/models", "/var/lib/xdp-sentinel/models"] {
        if Path::new(c).is_dir() {
            return PathBuf::from(c);
        }
    }
    PathBuf::from("/usr/lib/xdp-sentinel/models")
}

/// Per-layer traffic rates (packets/s) the multi-layer detector watches;
/// index order matches LAYER_DEF.
fn layer_rates(delta: &Snapshot, dt: f64) -> Vec<f64> {
    let r = |n: &str| cval(delta, n) as f64 / dt;
    let sum = |a: &str, b: &str| (cval(delta, a) + cval(delta, b)) as f64 / dt;
    vec![
        r("l3_arp"),                     // L2 ARP
        r("l3_other"),                   // L2 non-IP ethertype
        sum("l2_vlan1", "l2_vlan2"),     // L2 VLAN-tagged
        sum("l4_icmp", "l4_icmpv6"),     // L3 ICMP
        sum("frag_first", "frag_later"), // L3 fragments
        r("anom_land"),                  // L3 LAND
        r("tcp_syn"),                    // L4 SYN
        r("tcp_ack"),                    // L4 ACK
        r("tcp_rst"),                    // L4 RST
        r("l4_udp"),                     // L4 UDP
        r("anom_tcp_bad_flags"),         // L4 impossible TCP flags
        r("anom_udp_len_mismatch"),      // L4 malformed UDP
    ]
}

/// (layer, attack type, floor pps) for each rate in `layer_rates`.
const LAYER_DEF: &[(&str, &str, f64)] = &[
    ("l2", "arp_flood", 200.0),
    ("l2", "ethertype_flood", 200.0),
    ("l2", "vlan_flood", 500.0),
    ("l3", "icmp_flood", 500.0),
    ("l3", "frag_flood", 300.0),
    ("l3", "land_attack", 50.0),
    ("l4", "syn_flood", 2000.0),
    ("l4", "ack_flood", 2000.0),
    ("l4", "rst_flood", 1000.0),
    ("l4", "udp_flood", 2000.0),
    ("l4", "tcp_bad_flags", 500.0),
    ("l4", "udp_malformed", 200.0),
];

/// Layer label -> state array index (l2, l3, l4, l7).
fn layer_index(layer: &str) -> usize {
    match layer {
        "l2" => 0,
        "l3" => 1,
        "l4" => 2,
        _ => 3, // l7
    }
}

/// Latest analysis result, rendered into `/metrics` gauges.
#[derive(Clone, Default)]
struct Analysis {
    valid: bool,
    iface: String,
    pps: f64,
    drop_ratio: f64,
    anomaly_z: f64,
    anomaly01: f64,
    iforest: f64, // NaN if no anomaly model loaded
    ddos: f64,
    ddos_probs: Vec<(String, f64)>,
    detection_type: String, // "" when nothing detected
    risk: f64,
    risk_level: f64,
    state: u8, // 0 normal, 1 suspect, 2 under attack
    // auto-mitigation (Phase 13 enforcement)
    mit_active: bool,
    mit_pps: f64,      // per-source rate limit currently applied (0 = none)
    auto_actions: u64, // cumulative auto-mitigation changes applied
    // multi-layer detection: state per layer [l2, l3, l4, l7] (0/1/2)
    layer_state: [u8; 4],
    layer_dets: Vec<(String, String)>, // (layer, attack type) active this window
}

/// Persistent state owned by the analysis thread.
struct Analyzer {
    detector: Detector,
    classifier: Option<Classifier>,
    iforest: Option<Forest>,
    risk: RiskEngine,
    prev: Option<(Instant, Snapshot)>,
    prev_pps: f64,
    // auto-mitigation
    auto: bool,                     // enforce the ladder on the dataplane
    baseline: Option<DpConfig>,     // operator config to restore on de-escalation
    auto_actions: u64,
    global_cap: u32,                // aggregate pps cap at full escalation (tunable)
    ct_enforce: bool,               // actually drop untracked TCP (else conntrack is shadow-only)
    steady_drops: u32,              // drop flags kept on at all risk levels (auto-managed)
    // multi-layer detector baseline over the LAYER_DEF rates
    layer_base: RobustBaseline,
}

/// Drop flags the agent keeps enabled at steady state, from `XS_STEADY_DROPS`
/// (comma-separated flag names, or "safe" for the default set, or "" to
/// disable). Unset defaults to the always-safe, near-zero-false-positive
/// validity drops: malformed/LAND, bad TCP flag combinations, and "impossible"
/// spoofed packets. These are managed like CHECK_* -- re-applied every window --
/// so the appliance self-arms them and they survive restart, reattach and
/// de-escalation without a manual `sentinelctl config`.
fn parse_steady_drops() -> u32 {
    let safe: u32 = ConfigFlags::DROP_MALFORMED.bits()
        | ConfigFlags::DROP_BAD_TCP_FLAGS.bits()
        | ConfigFlags::DROP_SPOOFED.bits();
    match std::env::var("XS_STEADY_DROPS") {
        Err(_) => safe,
        Ok(s) => {
            let s = s.trim();
            if s.is_empty() {
                return 0;
            }
            if s.eq_ignore_ascii_case("safe") {
                return safe;
            }
            let mut bits = 0u32;
            for name in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                match ConfigFlags::NAMES.iter().find(|(_, n)| *n == name) {
                    Some((fl, _)) => bits |= fl.bits(),
                    None => eprintln!("XS_STEADY_DROPS: unknown flag '{name}' (ignored)"),
                }
            }
            bits
        }
    }
}

impl Analyzer {
    fn new() -> Self {
        let dir = model_dir();
        let want = features::schema_hash();
        let classifier = std::fs::read(dir.join("classifier/v1/model.json"))
            .ok()
            .and_then(|b| Classifier::from_json(&b).ok())
            .filter(|c| c.schema_hash() == want);
        let iforest = std::fs::read(dir.join("anomaly/v1/model.json"))
            .ok()
            .and_then(|b| Forest::from_json(&b).ok())
            .filter(|m| m.schema_hash() == want);
        let auto = std::env::var("XS_AUTO_MITIGATE").map(|v| v == "1" || v == "true").unwrap_or(false);
        let steady_drops = parse_steady_drops();
        let steady_names: Vec<&str> = ConfigFlags::NAMES
            .iter()
            .filter(|(fl, _)| steady_drops & fl.bits() != 0)
            .map(|(_, n)| *n)
            .collect();
        eprintln!(
            "analysis: detector on; classifier {}; anomaly model {}; auto-mitigate {}; steady-drops [{}]",
            if classifier.is_some() { "loaded" } else { "absent" },
            if iforest.is_some() { "loaded" } else { "absent" },
            if auto { "ON" } else { "off" },
            steady_names.join(","),
        );
        Analyzer {
            detector: Detector::new(features::N),
            classifier,
            iforest,
            // Faster escalation so a clear flood reaches an effective rung in a
            // few seconds, and a slightly slower de-escalation to avoid flapping.
            risk: RiskEngine::new(xs_common::risk::Config {
                escalate_windows: 2,
                deescalate_windows: 4,
                ..Default::default()
            }),
            prev: None,
            prev_pps: f64::NAN,
            auto,
            baseline: None,
            auto_actions: 0,
            // Aggregate cap at level 5 (pps). Default 2000 drops almost all of a
            // flood; lower it (XS_GLOBAL_RL_PPS=500) to pass even less, higher to
            // spare more legitimate traffic.
            global_cap: std::env::var("XS_GLOBAL_RL_PPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v| v > 0)
                .unwrap_or(2000),
            ct_enforce: std::env::var("XS_CONNTRACK_ENFORCE")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            steady_drops,
            layer_base: RobustBaseline::new(LAYER_DEF.len(), 256),
        }
    }

    /// Enforce the risk ladder on the dataplane: tighten the per-source rate
    /// limiter as risk climbs, and at the top rung enable the drop flag that
    /// matches the detected attack type. Restores the operator baseline when
    /// risk falls. Returns (applied_pps, active). The per-source limiter and
    /// the drop_udp ephemeral exemption keep the operator's own return traffic
    /// alive, so this cannot hard-lock the box.
    fn enforce(&mut self, layout: &PinLayout, level: u8, dtype: &str) -> (f64, bool) {
        let Ok(map) = MapHandle::from_pinned_path(layout.map(MAP_CONFIG)) else { return (0.0, false) };
        let raw = map.lookup(&0u32.to_ne_bytes(), MapFlags::ANY).ok().flatten().unwrap_or_default();
        let cur = DpConfig::from_bytes(&raw).unwrap_or_default();
        if self.baseline.is_none() {
            // Baseline = the saved OPERATOR config, not whatever is live now:
            // if the agent (re)starts mid-attack, the live config has mitigation
            // flags set, and capturing those as "baseline" would leave them on
            // forever. The saved state only reflects operator actions, so it is
            // clean. Preserve the live CHECK_* bits (allowlist/policy presence).
            let saved = xs_common::state::load(layout.iface()).unwrap_or(cur);
            let managed = ConfigFlags::CHECK_ALLOW.bits() | ConfigFlags::CHECK_POLICY.bits()
            | ConfigFlags::SERVICE_ALLOW.bits() | ConfigFlags::LOCKDOWN.bits();
            let mut b = saved;
            b.flags = ConfigFlags::from_bits_retain(
                (saved.flags.bits() & !managed) | (cur.flags.bits() & managed),
            );
            // Agent-only mitigation flags must never survive in the baseline. If a
            // `sentinelctl config` read-modify-write snapshotted the live config
            // while the risk engine had them armed (e.g. GLOBAL_RL + a level-5
            // per-source cap), state::save froze them into the "operator" state,
            // and restoring that would pin the aggregate limiter on forever at
            // idle. None of these is ever operator-set (there is no CLI for
            // GLOBAL_RL), so strip them -- and the aggregate-limiter params -- so
            // de-escalation always returns to a truly clean baseline.
            let auto_only = ConfigFlags::GLOBAL_RL.bits()
                | ConfigFlags::DROP_UNTRACKED.bits()
                | ConfigFlags::DROP_UDP_STRICT.bits();
            b.flags = ConfigFlags::from_bits_retain(b.flags.bits() & !auto_only);
            b.global_rl_interval_ns = 0;
            b.global_rl_burst = 0;
            self.baseline = Some(b);
        }
        let base = self.baseline.unwrap_or(cur);

        // Per-source pps ceiling by ladder level (0 = restore baseline).
        let auto_pps: u32 = match level {
            5 => 500,
            4 => 1000,
            3 => 5000,
            _ => 0,
        };
        let mut want = base;
        // Always track the LIVE allowlist/policy-presence bits, never the ones
        // frozen into the baseline at first capture. The baseline is captured
        // once; if `xs-baseline` arms CHECK_ALLOW *after* the agent started
        // (the boot-order race -- the agent attaches before xs-baseline loads
        // the LAN exemption), the frozen baseline has CHECK_ALLOW off, and every
        // config write here would clobber it back off, silently killing the
        // management-plane exemption. Re-applying the current bits each window
        // makes the exemption durable regardless of start order.
        let managed = ConfigFlags::CHECK_ALLOW.bits() | ConfigFlags::CHECK_POLICY.bits()
            | ConfigFlags::SERVICE_ALLOW.bits() | ConfigFlags::LOCKDOWN.bits();
        want.flags = ConfigFlags::from_bits_retain(
            (want.flags.bits() & !managed) | (cur.flags.bits() & managed),
        );
        // Steady-state drops the appliance keeps on at every risk level (default:
        // the always-safe malformed / bad-TCP-flags / spoofed set). Applied here,
        // before the level branches, so they hold even at level 0 -- the box
        // self-arms them and they survive restart, reattach and de-escalation.
        // Managed like CHECK_*: a manual `--drop-* off` is re-asserted next
        // window, so change the set via XS_STEADY_DROPS, not sentinelctl.
        want.flags = ConfigFlags::from_bits_retain(want.flags.bits() | self.steady_drops);
        // Connection tracking runs continuously (steady state) so legitimate
        // flows are already known before a flood hits -- it is harmless in
        // shadow (counts untracked TCP; only drops when DROP_UNTRACKED is set).
        want.flags = ConfigFlags::from_bits_retain(want.flags.bits() | ConfigFlags::CONNTRACK.bits());
        if auto_pps > 0 {
            want.flags = ConfigFlags::from_bits_retain(want.flags.bits() | ConfigFlags::RATELIMIT.bits());
            want.rl_interval_ns = 1_000_000_000 / auto_pps;
            want.rl_burst = (auto_pps / 10).max(20);
            // From level 4 up, also enable the validity drop flag that matches
            // the attack type. Unlike the per-source rate limiter, a validity
            // drop applies even to dynamic-exempt sources, so it stops a flood
            // coming from an allowlisted admin box too (drop_udp keeps the
            // admin's own ephemeral return traffic alive via its exemption).
            if level >= 4 {
                // NOTE: SYN and ACK floods are deliberately NOT met with
                // drop_syn/drop_ack here. Those drop *valid* TCP packets:
                // drop_ack kills the acknowledgements of every ESTABLISHED
                // connection (web + SSH die), and drop_syn blocks all new
                // connections. Blanket-dropping them breaks legitimate TCP, so
                // TCP floods are handled by the per-source + aggregate rate
                // limiters (below) instead, which cap the flood while keeping
                // sessions alive. drop_syn/drop_ack remain available for an
                // operator to set manually in an extreme, accepted-outage case.
                // ICMP/UDP/fragment/malformed drops are safe (they don't carry
                // established TCP state) and stay automatic.
                let mut extra = match dtype {
                    "udp_flood" | "udp_reflection" | "dns_amplification" => ConfigFlags::DROP_UDP.bits(),
                    "frag_flood" => ConfigFlags::DROP_FRAGMENTS.bits(),
                    // IPv6 fragment flood: dropping fragments is the safe, direct
                    // mitigation (atomic-fragment passthrough is handled upstream).
                    "ipv6_frag_flood" => ConfigFlags::DROP_FRAGMENTS.bits(),
                    "malformed_flood" => ConfigFlags::DROP_MALFORMED.bits(),
                    // DROP_ICMP covers both ICMP and ICMPv6 in the datapath.
                    "icmp_flood" | "icmpv6_flood" => ConfigFlags::DROP_ICMP.bits(),
                    // New defense: drop IPv6 packets carrying extension headers.
                    "ipv6_ext_flood" => ConfigFlags::DROP_IPV6_EXT.bits(),
                    // Generic IPv6 volumetric flood: no safe per-vector drop, rely on
                    // the per-source + aggregate rate limiters below.
                    "ipv6_flood" => 0,
                    // ACK/RST floods: the correct, safe tool is conntrack's
                    // drop_untracked (drops ACKs with no established flow). It is
                    // NOT drop_ack, which would kill every live connection.
                    // Conntrack runs continuously, so real connections are
                    // already tracked; the allowlisted admin is exempt.
                    // ACK/RST/FIN floods: non-handshake TCP with no established
                    // flow. The safe tool is conntrack's drop_untracked (drops only
                    // TCP that matches no tracked connection), NOT drop_syn/ack/fin
                    // which would kill live sessions. Real connections are already
                    // tracked; the allowlisted admin is exempt.
                    "ack_flood" | "rst_flood" | "fin_flood" => ConfigFlags::DROP_UNTRACKED.bits(),
                    _ => ConfigFlags::DROP_BAD_TCP_FLAGS.bits(),
                };
                // Always safe at this level: DROP_MALFORMED only ever drops
                // parse-error and LAND (src==dst) frames, never valid traffic.
                // Unlike the rate limiters it applies to allowlist-exempt sources,
                // so it closes the gap where a LAND flood spoofs an exempt address
                // (it classifies as syn_flood, which otherwise gets rate-limited
                // only -- and the spoofed source is exempt, so nothing dropped).
                extra |= ConfigFlags::DROP_MALFORMED.bits();
                // Also always safe: DROP_SPOOFED only ever drops "impossible"
                // packets (bogon/martian source, TTL/hop-limit 0, port 0) that no
                // conforming stack emits -- never legitimate RFC1918 or link-local
                // traffic. Like DROP_MALFORMED it applies to allowlist-exempt
                // sources, so it sheds a spoofed flood that forges an exempt IP.
                extra |= ConfigFlags::DROP_SPOOFED.bits();
                // Connection-tracking enforcement (opt-in via XS_CONNTRACK_ENFORCE
                // after validating the shadow counts): drop untracked TCP for any
                // TCP flood. It only affects TCP with no learned flow, so ACK/RST
                // floods are shed while real, tracked connections pass. It's the
                // zero-collateral complement to the aggregate cap.
                if self.ct_enforce {
                    extra |= ConfigFlags::DROP_UNTRACKED.bits();
                }
                // At level 5, close the ephemeral-port / reflection / fragment
                // gaps of drop_udp by dropping ALL UDP.
                if level >= 5
                    && matches!(dtype, "udp_flood" | "udp_reflection" | "dns_amplification")
                {
                    extra |= ConfigFlags::DROP_UDP_STRICT.bits();
                }
                want.flags = ConfigFlags::from_bits_retain(want.flags.bits() | extra);
                // Aggregate cap: the only thing that stops a fully source-spoofed
                // flood (e.g. hping3 --rand-source), which per-source limiting and
                // validity flags on valid SYNs cannot. Level 5 clamps hard to
                // global_cap; level 4 is 4x looser.
                let global_pps: u32 = if level >= 5 { self.global_cap } else { self.global_cap * 4 };
                want.flags = ConfigFlags::from_bits_retain(want.flags.bits() | ConfigFlags::GLOBAL_RL.bits());
                want.global_rl_interval_ns = 1_000_000_000 / global_pps;
                want.global_rl_burst = (global_pps / 10).max(50);
            }
        }
        if want != cur {
            if map.update(&0u32.to_ne_bytes(), &want.to_bytes(), MapFlags::ANY).is_ok() {
                self.auto_actions += 1;
                eprintln!(
                    "auto-mitigate: level {level} ({dtype}) -> per-source {} pps, flags {:?}",
                    if auto_pps > 0 { auto_pps.to_string() } else { "baseline".into() },
                    want.flags
                );
            }
        }
        (auto_pps as f64, auto_pps > 0)
    }

    /// Run one analysis window for `iface`; returns the latest scores.
    fn step(&mut self, iface: &str, pin_root: &Path) -> Analysis {
        let none = Analysis { iface: iface.into(), ..Default::default() };
        let Ok(layout) = PinLayout::new(pin_root, iface) else { return none };
        let Ok(snap) = read_snapshot(iface, &layout) else { return none };
        let now = Instant::now();
        let Some((t0, prev)) = self.prev.as_ref() else {
            self.prev = Some((now, snap));
            return none; // first tick: no delta yet
        };
        let dt = (now - *t0).as_secs_f64().max(1e-3);
        let delta = snap.delta_since(prev);
        let wi = window_input(&delta, dt, self.prev_pps);
        let vec = features::compute(&wi);
        log_feature_row(iface, &vec);
        let det = self.detector.detect(&vec);
        let pps = wi.packets as f64 / dt;
        let drop_ratio = if wi.packets > 0 { wi.dropped as f64 / wi.packets as f64 } else { 0.0 };
        self.prev = Some((now, snap));
        self.prev_pps = pps;

        let mut iforest = self.iforest.as_ref().map(|m| m.score(&vec)).unwrap_or(f64::NAN);
        let mut ddos = 0.0;
        let mut ddos_probs = Vec::new();
        // The deterministic rules (det.suspected) classify the attack from the
        // actual traffic shares and are reliable; the CART classifier is trained
        // on synthetic data and is noisy on real traffic, so it must NOT override
        // a rule match (that's what turned on drop_udp for an ICMP flood). Use
        // the classifier only to name the type when the rules found none, and for
        // the ddos score.
        let mut dtype = det.suspected.map(|t| t.as_str().to_string()).unwrap_or_default();
        // IPv6-specific refinement (raw-signal, outside the model vector): name an
        // ICMPv6 / ext-header / generic-IPv6 flood that would otherwise read as a
        // generic icmp_flood or go unnamed. Always override for the specific IPv6
        // types; for generic ipv6_flood only when nothing better was found, so a
        // real UDP/TCP-over-IPv6 flood keeps its (correct) udp/tcp class and its
        // matching drop. Never changes the model schema.
        if let Some(t) = xs_common::detect::classify_ipv6(&wi) {
            let name = t.as_str();
            if name == "icmpv6_flood" || name == "ipv6_ext_flood" || name == "ipv6_frag_flood" || dtype.is_empty() || dtype == "icmp_flood" || dtype == "frag_flood" {
                dtype = name.to_string();
            }
        }
        if let Some(clf) = &self.classifier {
            let probs = clf.predict_proba(&vec);
            for (c, p) in clf.classes().iter().zip(&probs) {
                ddos_probs.push((c.clone(), *p));
                if c != "benign" && *p > ddos {
                    ddos = *p;
                }
            }
            if dtype.is_empty() {
                let (top, _) = clf.predict(&vec);
                if top != "benign" {
                    dtype = top;
                }
            }
        }
        let mut anomaly01 = if det.score.is_finite() { 1.0 - (-det.score / 8.0).exp() } else { 0.0 };

        // An attack this dataplane cares about has real volume or causes drops.
        // Below that, idle traffic is never "under attack" -- no matter what the
        // (synthetic-trained) models say about its shape -- and the noisy
        // z-score at low packet counts is suppressed. This is the guard that
        // stops "UNDER ATTACK at 29 pps, 0 drops".
        let plausible = drop_ratio > 0.05 || pps > 500.0;
        // A legitimate bulk transfer (download/backup/replication) spikes pps/bps
        // like a flood but is TCP-dominant, conntrack-tracked, large-packet, and
        // not dropping -- no flood looks like that. Suppress the attack state for
        // it so curl/wget downloads are not mistaken for an attack and throttled.
        let benign_bulk = xs_common::detect::is_benign_bulk_transfer(&wi);
        let anomalous = det.anomalous && plausible && !benign_bulk;
        if !plausible || benign_bulk {
            ddos = 0.0;
            anomaly01 = 0.0;
            iforest = f64::NAN; // not meaningful without a real attack; hide it
            ddos_probs = vec![("benign".to_string(), 1.0)];
        }
        let anomaly_z = if plausible && det.score.is_finite() { det.score } else { 0.0 };
        let dtype = if anomalous { dtype } else { String::new() };

        let ev = Evidence {
            anomaly: anomaly01,
            ddos,
            bot: 0.0,
            rule: if anomalous { 1.0 } else { 0.0 },
            confidence: 1.0,
        };
        self.risk.begin_window(if anomalous { 1 } else { 0 });
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let decision = self.risk.decide(&format!("service:{iface}"), &ev, false, now_s);
        let state = if anomalous {
            2
        } else if plausible && !benign_bulk && (drop_ratio > 0.12 || det.score > 4.0) {
            1
        } else {
            0
        };

        let level = decision.level as u8;
        let (mit_pps, mit_active) =
            if self.auto { self.enforce(&layout, level, &dtype) } else { (0.0, false) };

        // Multi-layer detection: each layer's rates vs its robust baseline,
        // named by attack type. L7 (index 3) stays 0 here -- it needs
        // reverse-proxy / DNS visibility the dataplane does not have.
        let lrates = layer_rates(&delta, dt);
        let lz = self.layer_base.zscores(&lrates);
        let mut layer_state = [0u8; 4];
        let mut layer_dets: Vec<(String, String)> = Vec::new();
        for (i, (layer, typ, floor)) in LAYER_DEF.iter().enumerate() {
            let li = layer_index(layer);
            let rate = lrates[i];
            let z = lz[i];
            let attack = rate > *floor && ((z.is_finite() && z > 6.0) || rate > *floor * 10.0);
            if attack {
                layer_state[li] = 2;
                layer_dets.push((layer.to_string(), typ.to_string()));
            } else if rate > *floor && z.is_finite() && z > 3.0 && layer_state[li] < 1 {
                layer_state[li] = 1;
            }
        }
        if layer_dets.is_empty() {
            self.layer_base.learn(&lrates); // only learn from calm windows
        }

        Analysis {
            valid: true,
            iface: iface.into(),
            pps,
            drop_ratio,
            anomaly_z,
            anomaly01,
            iforest,
            ddos,
            ddos_probs,
            detection_type: dtype,
            risk: decision.risk,
            risk_level: level as f64,
            state,
            mit_active,
            mit_pps,
            auto_actions: self.auto_actions,
            layer_state,
            layer_dets,
        }
    }
}

/// Append one window's schema-ordered feature vector to the CSV named by
/// `XS_FEATURE_LOG` (unset = no logging). Columns: unix_ms, iface, then the
/// features in schema order; NaN is written blank, matching the training
/// pipeline's "missing = NaN" convention. Used to capture a real, labelled
/// dataset from live/attack traffic for retraining the models.
fn log_feature_row(iface: &str, vec: &[f64]) {
    let Ok(path) = std::env::var("XS_FEATURE_LOG") else { return };
    if path.is_empty() {
        return;
    }
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut line = format!("{ms},{iface}");
    for &v in vec {
        if v.is_finite() {
            line.push_str(&format!(",{v}"));
        } else {
            line.push(',');
        }
    }
    line.push('\n');
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Render the analysis scores as Prometheus gauges.
fn render_analysis(a: &Analysis) -> String {
    if !a.valid {
        return String::new();
    }
    fn gauge(s: &mut String, il: &str, name: &str, help: &str, val: f64) {
        s.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name}{{{il}}} {val}\n"));
    }
    let il = format!("iface=\"{}\"", a.iface);
    let mut s = String::new();
    gauge(&mut s, &il, "xs_analysis_pps", "Packets/s in the last analysis window.", a.pps);
    gauge(&mut s, &il, "xs_threat_state", "Threat state: 0 normal, 1 suspect, 2 under attack.", a.state as f64);
    gauge(&mut s, &il, "xs_anomaly_score", "Statistical detector robust z-score (0 normal, >8 anomalous).", a.anomaly_z);
    gauge(&mut s, &il, "xs_anomaly_score01", "Anomaly score normalised to 0..1.", a.anomaly01);
    if a.iforest.is_finite() {
        gauge(&mut s, &il, "xs_anomaly_iforest", "Isolation Forest anomaly score (0..1).", a.iforest);
    }
    gauge(&mut s, &il, "xs_ddos_score", "DDoS classifier top non-benign probability (0..1).", a.ddos);
    gauge(&mut s, &il, "xs_risk", "Fused risk for the service (0..1).", a.risk);
    gauge(&mut s, &il, "xs_risk_level", "Mitigation ladder level (0 pass .. 5 temporary block).", a.risk_level);
    gauge(&mut s, &il, "xs_detection_active", "1 while an attack is detected, else 0.",
          if a.detection_type.is_empty() { 0.0 } else { 1.0 });
    gauge(&mut s, &il, "xs_mitigation_active", "1 while auto-mitigation is applied, else 0.",
          if a.mit_active { 1.0 } else { 0.0 });
    gauge(&mut s, &il, "xs_mitigation_rate_pps",
          "Per-source rate limit the risk engine currently enforces (0 = none).", a.mit_pps);
    s.push_str("# HELP xs_auto_actions_total Auto-mitigation changes applied since start.\n");
    s.push_str("# TYPE xs_auto_actions_total counter\n");
    s.push_str(&format!("xs_auto_actions_total{{{il}}} {}\n", a.auto_actions));
    // Multi-layer detection state (l2/l3/l4/l7): 0 normal, 1 elevated, 2 attack.
    s.push_str("# HELP xs_layer_state Per-layer detection state (0 normal, 1 elevated, 2 attack).\n");
    s.push_str("# TYPE xs_layer_state gauge\n");
    for (i, layer) in ["l2", "l3", "l4", "l7"].iter().enumerate() {
        s.push_str(&format!("xs_layer_state{{{il},layer=\"{layer}\"}} {}\n", a.layer_state[i]));
    }
    if !a.layer_dets.is_empty() {
        s.push_str("# HELP xs_layer_detection Active per-layer attack (value 1).\n");
        s.push_str("# TYPE xs_layer_detection gauge\n");
        for (layer, typ) in &a.layer_dets {
            s.push_str(&format!("xs_layer_detection{{{il},layer=\"{layer}\",type=\"{typ}\"}} 1\n"));
        }
    }
    if !a.ddos_probs.is_empty() {
        s.push_str("# HELP xs_ddos_class_probability Per-class DDoS classifier probability.\n");
        s.push_str("# TYPE xs_ddos_class_probability gauge\n");
        for (c, p) in &a.ddos_probs {
            s.push_str(&format!("xs_ddos_class_probability{{{il},class=\"{c}\"}} {p}\n"));
        }
    }
    if !a.detection_type.is_empty() {
        s.push_str("# HELP xs_detection_info Active detection type (value 1).\n");
        s.push_str("# TYPE xs_detection_info gauge\n");
        s.push_str(&format!("xs_detection_info{{{il},type=\"{}\"}} 1\n", a.detection_type));
    }
    s
}

/// True when every interface configured with attach=true has our program on.
fn ready(cfg: &Config) -> bool {
    cfg.interfaces.iter().filter(|i| i.attach).all(|i| {
        PinLayout::new(&cfg.pin_root, &i.name)
            .ok()
            .and_then(|l| ifindex(&i.name).ok().map(|ix| iface_mode(ix, &l) != "none"))
            .unwrap_or(false)
    })
}

// ---- minimal HTTP server ----

fn serve(cfg: &Config) -> Result<()> {
    let listener = TcpListener::bind(cfg.metrics_addr)
        .with_context(|| format!("bind metrics address {}", cfg.metrics_addr))?;
    listener.set_nonblocking(true).context("set listener nonblocking")?;
    eprintln!("serving metrics on http://{}/metrics", cfg.metrics_addr);
    eprintln!("serving dashboard state on http://{}/api/state.json", cfg.metrics_addr);
    let api = Mutex::new(ApiState::new());

    // Phase 6-13 analysis loop, PER INTERFACE: one analyzer thread per configured
    // interface, each with its own baseline and risk engine, so EVERY monitored
    // interface (not just the first) gets real-time detection + auto-mitigation.
    // Previously only interfaces.first() was analyzed, so an attack on any other
    // attached interface was counted by the dataplane but never auto-blocked.
    let mut analyses: Vec<(String, Arc<Mutex<Analysis>>)> = Vec::new();
    for iface in &cfg.interfaces {
        let name = iface.name.clone();
        let slot = Arc::new(Mutex::new(Analysis::default()));
        analyses.push((name.clone(), slot.clone()));
        let pin_root = cfg.pin_root.clone();
        thread::spawn(move || {
            let mut az = Analyzer::new();
            while !STOP.load(Ordering::SeqCst) {
                let result = az.step(&name, &pin_root);
                if let Ok(mut g) = slot.lock() {
                    *g = result;
                }
                thread::sleep(Duration::from_secs(1));
            }
        });
    }

    // Background GC: every ~60s, reclaim expired per-source policy entries.
    // These maps are plain HASH (no LRU), so expired blocks would otherwise sit
    // until the map fills. Expiry is enforced in-kernel regardless; this only
    // frees slots. Best-effort — failures are logged and ignored.
    {
        let ifaces: Vec<String> = cfg.interfaces.iter().map(|i| i.name.clone()).collect();
        let pin_root = cfg.pin_root.clone();
        thread::spawn(move || {
            while !STOP.load(Ordering::SeqCst) {
                for _ in 0..60 {
                    if STOP.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                let now = now_monotonic_ns();
                for name in &ifaces {
                    let Ok(layout) = PinLayout::new(&pin_root, name) else { continue };
                    let n = gc_policy_map(&layout.map(MAP_POLICY_V4), now)
                        + gc_policy_map(&layout.map(MAP_POLICY_V6), now);
                    if n > 0 {
                        eprintln!("policy-gc {name}: removed {n} expired entrie(s)");
                    }
                }
            }
        });
    }

    while !STOP.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if let Err(e) = handle(stream, cfg, &api, &analyses) {
                    eprintln!("metrics request: {e:#}");
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    eprintln!("received stop signal; exiting (dataplane stays attached)");
    Ok(())
}

fn handle(
    mut stream: TcpStream,
    cfg: &Config,
    api: &Mutex<ApiState>,
    analyses: &[(String, Arc<Mutex<Analysis>>)],
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_nonblocking(false)?;

    // Read only enough to get the request line; cap the read hard.
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    let path = head.split_whitespace().nth(1).unwrap_or("/");
    let method = head.split_whitespace().next().unwrap_or("");

    let (status, ctype, body): (&str, &str, String) = if method == "OPTIONS" {
        ("204 No Content", "text/plain", String::new())
    } else if method != "GET" {
        ("405 Method Not Allowed", "text/plain", "method not allowed\n".into())
    } else {
        match path {
            "/metrics" => ("200 OK", "text/plain; version=0.0.4", all_metrics(cfg, analyses)),
            "/api/state.json" => {
                let json = match api.lock() {
                    Ok(mut g) => api_state_json(cfg, &mut g),
                    Err(_) => "{\"attached\":false}".into(),
                };
                ("200 OK", "application/json", json)
            }
            "/api/services.json" => ("200 OK", "application/json", api_services_json(cfg)),
            "/healthz" => ("200 OK", "text/plain", "ok\n".into()),
            "/readyz" => {
                if ready(cfg) {
                    ("200 OK", "text/plain", "ready\n".into())
                } else {
                    ("503 Service Unavailable", "text/plain", "not ready\n".into())
                }
            }
            _ => ("404 Not Found", "text/plain", "not found\n".into()),
        }
    };

    // CORS so the dashboard (any origin) can read the API directly.
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}
