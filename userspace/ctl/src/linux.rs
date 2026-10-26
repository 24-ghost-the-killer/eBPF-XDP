//! Linux implementation: libbpf-rs loader and map access.
//!
//! Attachment uses the netlink XDP API (`bpf_xdp_attach`) with an explicit
//! mode flag rather than a `bpf_link`:
//!   * the attachment is owned by the interface, so the dataplane keeps
//!     running when this process (or, later, the agent) exits or crashes;
//!   * the mode (driver vs generic) is explicit and a missing driver
//!     capability is an error instead of a silent generic fallback;
//!   * `XDP_FLAGS_UPDATE_IF_NOEXIST` refuses to clobber a foreign program
//!     and `XDP_FLAGS_REPLACE` gives an atomic upgrade.
//!
//! Maps are pinned per interface so they survive program replacement and
//! userspace restarts.

use std::ffi::CString;
use std::fs;
use std::os::fd::AsFd;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle, ObjectBuilder, PrintLevel, Program, Xdp, XdpFlags};
use xs_common::abi::{Config, ConfigFlags, ABI_VERSION, CONFIG_SIZE, STATS_SIZE};
use xs_common::pin::{PinLayout, MAP_CONFIG, MAP_STATS, PROG_NAME};
use xs_common::Snapshot;

use crate::{render, Cli, Cmd, Mode, Toggle};

mod policy;

/// `BPF_FS_MAGIC` from `<linux/magic.h>`.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

pub fn run(cli: Cli) -> Result<()> {
    configure_libbpf_logging(cli.verbose);
    match cli.cmd {
        Cmd::Attach { ref iface, ref obj, mode, replace } => {
            attach(&layout(&cli, iface)?, obj, mode, replace)
        }
        Cmd::Detach { ref iface, keep_maps, force } => {
            detach(&layout(&cli, iface)?, keep_maps, force)
        }
        Cmd::Status { ref iface } => status(&layout(&cli, iface)?),
        Cmd::Stats { ref iface, prometheus: true, .. } => prometheus(&layout(&cli, iface)?),
        Cmd::Stats { ref iface, interval, count, all, json, .. } => {
            stats(&layout(&cli, iface)?, interval, count, all, json)
        }
        Cmd::Config {
            ref iface,
            drop_malformed,
            drop_bad_tcp_flags,
            drop_fragments,
            drop_udp_dns,
            drop_udp,
            lockdown,
            drop_spoofed,
        } => config(
            &layout(&cli, iface)?,
            [
                (ConfigFlags::DROP_MALFORMED, drop_malformed),
                (ConfigFlags::DROP_BAD_TCP_FLAGS, drop_bad_tcp_flags),
                (ConfigFlags::DROP_FRAGMENTS, drop_fragments),
                (ConfigFlags::DROP_UDP_DNS, drop_udp_dns),
                (ConfigFlags::DROP_UDP, drop_udp),
                (ConfigFlags::LOCKDOWN, lockdown),
                (ConfigFlags::DROP_SPOOFED, drop_spoofed),
            ],
        ),
        Cmd::Block { ref iface, ip, ttl } => policy::block(&layout(&cli, iface)?, ip, ttl),
        Cmd::Unblock { ref iface, ip } => policy::unblock(&layout(&cli, iface)?, ip),
        Cmd::Allow { ref iface, ref cidr, trust, ttl } => {
            policy::allow(&layout(&cli, iface)?, cidr, trust, ttl)
        }
        Cmd::Unallow { ref iface, ref cidr } => policy::unallow(&layout(&cli, iface)?, cidr),
        Cmd::List { ref iface, json } => policy::list(&layout(&cli, iface)?, json),
        Cmd::Ratelimit { ref iface, pps, burst } => {
            policy::ratelimit(&layout(&cli, iface)?, pps, burst)
        }
        Cmd::Protect { ref iface, ip } => policy::protect(&layout(&cli, iface)?, ip),
        Cmd::Unprotect { ref iface, ip } => policy::unprotect(&layout(&cli, iface)?, ip),
        Cmd::Service { ref iface, ip, proto, port, remove } => {
            policy::service(&layout(&cli, iface)?, ip, proto.number(), port, remove)
        }
        Cmd::ServiceSync { ref iface, ip, protect, dry_run } => {
            policy::service_sync(&layout(&cli, iface)?, ip, protect, dry_run)
        }
    }
}

fn configure_libbpf_logging(verbose: bool) {
    fn print(level: PrintLevel, msg: String) {
        eprint!("libbpf[{level:?}]: {msg}");
    }
    let level = if verbose { PrintLevel::Debug } else { PrintLevel::Warn };
    let _ = libbpf_rs::set_print(Some((level, print)));
}

fn layout(cli: &Cli, iface: &str) -> Result<PinLayout> {
    Ok(PinLayout::new(&cli.pin_root, iface)?)
}

fn ifindex(iface: &str) -> Result<i32> {
    let name = CString::new(iface).context("interface name contains NUL")?;
    // SAFETY: `name` is a valid NUL-terminated C string that outlives the
    // call; if_nametoindex does not retain the pointer.
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("interface {iface} not found"));
    }
    i32::try_from(idx).context("ifindex out of range")
}

/// Refuse to create pins on something that is not bpffs (pins on tmpfs
/// would silently not persist anything).
fn ensure_bpffs(path: &Path) -> Result<()> {
    let mut probe = path;
    while !probe.exists() {
        probe = probe.parent().ok_or_else(|| anyhow!("no existing parent of {path:?}"))?;
    }
    let c = CString::new(probe.as_os_str().as_encoded_bytes())?;
    // SAFETY: statfs is plain-old-data; zero-initialisation is a valid value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `st` a valid, writable statfs.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("statfs");
    }
    #[allow(clippy::unnecessary_cast)] // f_type's integer type differs by libc target
    if st.f_type as i64 != BPF_FS_MAGIC {
        bail!(
            "{probe:?} is not on a bpffs mount; mount one with \
             `mount -t bpf bpf /sys/fs/bpf` (systemd does this by default)"
        );
    }
    Ok(())
}

fn attach(layout: &PinLayout, obj_path: &Path, mode: Mode, replace: bool) -> Result<()> {
    let ifindex = ifindex(layout.iface())?;
    ensure_bpffs(layout.dir())?;
    fs::create_dir_all(layout.dir())
        .with_context(|| format!("create pin directory {:?}", layout.dir()))?;

    let mut open = ObjectBuilder::default()
        .open_file(obj_path)
        .with_context(|| format!("open BPF object {obj_path:?}"))?;
    for mut map in open.maps_mut() {
        let name = map.name().to_string_lossy().into_owned();
        // .rodata/.bss style internal maps are per-object and never pinned.
        if name.starts_with('.') || name.contains(".rodata") || name.contains(".bss") {
            continue;
        }
        map.set_pin_path(layout.map(&name))?;
    }
    // Existing pins with the same definition are reused (counters and config
    // survive an upgrade); a pin whose key/value size changed makes load fail.
    let obj = open.load().with_context(|| {
        format!(
            "load {obj_path:?} (verifier rejection or incompatible pinned maps in {:?}; \
             `sentinelctl detach -i {}` removes stale pins; -v shows the verifier log)",
            layout.dir(),
            layout.iface()
        )
    })?;

    let mut prog = obj
        .progs_mut()
        .find(|p| p.name() == PROG_NAME)
        .ok_or_else(|| anyhow!("object has no program {PROG_NAME}"))?;
    let xdp = Xdp::new(prog.as_fd());
    let mode_flag = match mode {
        Mode::Native => XdpFlags::DRV_MODE,
        Mode::Generic => XdpFlags::SKB_MODE,
    };

    let current = xdp.query_id(ifindex, XdpFlags::NONE).unwrap_or(0);
    if current != 0 {
        if !replace {
            bail!(
                "{} already has XDP program id {current}; use --replace to upgrade \
                 xdp-sentinel atomically, or detach it first",
                layout.iface()
            );
        }
        let old = Program::fd_from_id(current).context("open currently attached program")?;
        // bpf_xdp_attach with XDP_FLAGS_REPLACE: fails if the attached program
        // changed in the meantime; never leaves the interface unprotected.
        xdp.replace(ifindex, old.as_fd()).context("atomic program replace")?;
    } else {
        xdp.attach(ifindex, mode_flag | XdpFlags::UPDATE_IF_NOEXIST).with_context(|| {
            format!(
                "attach to {} in {mode:?} mode{}",
                layout.iface(),
                if mode == Mode::Native {
                    " (driver may lack native XDP support, or MTU too large for single-buffer XDP)"
                } else {
                    ""
                }
            )
        })?;
    }

    let id = xdp.query_id(ifindex, XdpFlags::NONE)?;

    let prog_pin = layout.prog();
    if prog_pin.exists() {
        fs::remove_file(&prog_pin).with_context(|| format!("remove stale pin {prog_pin:?}"))?;
    }
    prog.pin(&prog_pin).with_context(|| format!("pin program at {prog_pin:?}"))?;

    // A freshly created config element is all zero = observe only. Record
    // the ABI version but never change flags an operator set earlier.
    let cfg_map = MapHandle::from_pinned_path(layout.map(MAP_CONFIG))?;
    let mut cfg = read_config(&cfg_map)?;
    if cfg.abi_version != ABI_VERSION {
        cfg.abi_version = ABI_VERSION;
        write_config(&cfg_map, cfg)?;
    }

    println!(
        "attached {PROG_NAME} (prog id {id}) to {} in {mode:?} mode; pins in {:?}; flags: {:?}",
        layout.iface(),
        layout.dir(),
        cfg.flags
    );
    Ok(())
}

fn detach(layout: &PinLayout, keep_maps: bool, force: bool) -> Result<()> {
    let ifindex = ifindex(layout.iface())?;
    let current = attached_prog_id(ifindex)?;

    let ours = match Program::fd_from_pinned_path(layout.prog()) {
        Ok(fd) => Some(Program::id_from_fd(fd.as_fd())?),
        Err(_) => None,
    };

    if current != 0 {
        if ours != Some(current) && !force {
            bail!(
                "attached program id {current} is not the xdp-sentinel program pinned in {:?}; \
                 refusing to detach it (use --force)",
                layout.dir()
            );
        }
        let fd = Program::fd_from_id(current)?;
        // Mode flags must match how it was attached; query tells us which.
        let info = Xdp::new(fd.as_fd()).query(ifindex, XdpFlags::NONE)?;
        let flags =
            if info.skb_prog_id == current { XdpFlags::SKB_MODE } else { XdpFlags::DRV_MODE };
        Xdp::new(fd.as_fd()).detach(ifindex, flags).context("detach XDP program")?;
        println!("detached program id {current} from {}", layout.iface());
    } else {
        println!("no XDP program attached to {}", layout.iface());
    }

    remove_pin(&layout.prog())?;
    if !keep_maps {
        // attach pins every map in the object, so remove the whole directory's
        // contents rather than a fixed list that drifts as maps are added.
        if let Ok(entries) = fs::read_dir(layout.dir()) {
            for entry in entries {
                remove_pin(&entry?.path())?;
            }
        }
        let _ = fs::remove_dir(layout.dir());
    }
    Ok(())
}

fn remove_pin(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {path:?}")),
    }
}

fn attached_prog_id(ifindex: i32) -> Result<u32> {
    // bpf_xdp_query_id ignores the program fd; any valid fd works for Xdp::new.
    let devnull = fs::File::open("/dev/null")?;
    Ok(Xdp::new(devnull.as_fd()).query_id(ifindex, XdpFlags::NONE).unwrap_or(0))
}

fn status(layout: &PinLayout) -> Result<()> {
    let ifindex = ifindex(layout.iface())?;
    let devnull = fs::File::open("/dev/null")?;
    let info = Xdp::new(devnull.as_fd()).query(ifindex, XdpFlags::NONE)?;
    // XDP_ATTACHED_* from <linux/if_link.h>
    let mode = match info.attach_mode {
        0 => "none",
        1 => "native (driver)",
        2 => "generic (skb)",
        3 => "offloaded (hw)",
        4 => "multiple",
        _ => "unknown",
    };
    println!("interface:   {} (ifindex {ifindex})", layout.iface());
    println!("attach mode: {mode}");
    println!("program id:  {}", info.prog_id);
    match Program::fd_from_pinned_path(layout.prog()) {
        Ok(fd) => {
            let pinned = Program::id_from_fd(fd.as_fd())?;
            let state = if pinned == info.prog_id { "attached" } else { "NOT attached" };
            println!("pinned prog: id {pinned} ({state})");
        }
        Err(_) => println!("pinned prog: none in {:?}", layout.dir()),
    }
    match MapHandle::from_pinned_path(layout.map(MAP_CONFIG)) {
        Ok(m) => {
            let cfg = read_config(&m)?;
            println!("config:      abi v{} flags {:?}", cfg.abi_version, cfg.flags);
        }
        Err(_) => println!("config:      no pinned config map"),
    }
    Ok(())
}

/// XDP attach mode of *our* pinned program on the interface: "none" if
/// nothing is attached or the attached program is not the pinned one.
fn our_attach_mode(layout: &PinLayout) -> Result<&'static str> {
    let ifindex = ifindex(layout.iface())?;
    let devnull = fs::File::open("/dev/null")?;
    let info = Xdp::new(devnull.as_fd()).query(ifindex, XdpFlags::NONE)?;
    let ours = match Program::fd_from_pinned_path(layout.prog()) {
        Ok(fd) => Program::id_from_fd(fd.as_fd())?,
        Err(_) => return Ok("none"),
    };
    if info.prog_id != ours {
        return Ok("none");
    }
    // XDP_ATTACHED_* from <linux/if_link.h>
    Ok(match info.attach_mode {
        1 => "native",
        2 => "generic",
        3 => "offload",
        _ => "none",
    })
}

fn prometheus(layout: &PinLayout) -> Result<()> {
    let snap = read_snapshot(&open_stats(layout)?)?;
    let mode = our_attach_mode(layout)?;
    let cfg = read_config(&MapHandle::from_pinned_path(layout.map(MAP_CONFIG))?)?;
    let flags: Vec<(&str, bool)> =
        ConfigFlags::NAMES.iter().map(|(f, n)| (*n, cfg.flags.contains(*f))).collect();
    print!("{}", render::prometheus(layout.iface(), &snap, mode, &flags));
    Ok(())
}

fn open_stats(layout: &PinLayout) -> Result<MapHandle> {
    let path = layout.map(MAP_STATS);
    let map = MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open {path:?} (is the program attached?)"))?;
    if map.value_size() as usize != STATS_SIZE {
        bail!("{path:?}: value size {} != {STATS_SIZE}: ABI mismatch", map.value_size());
    }
    Ok(map)
}

fn read_snapshot(map: &MapHandle) -> Result<Snapshot> {
    let vals = map
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow!("xs_stats has no element 0"))?;
    Ok(Snapshot::from_percpu(&vals)?)
}

fn unix_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn stats(
    layout: &PinLayout,
    interval: Option<f64>,
    count: Option<u64>,
    all: bool,
    json: bool,
) -> Result<()> {
    let map = open_stats(layout)?;
    let Some(interval) = interval else {
        let snap = read_snapshot(&map)?;
        if json {
            println!("{}", render::json(layout.iface(), &snap, None, unix_ms()));
        } else {
            print!("{}", render::table(layout.iface(), &snap, None, all));
        }
        return Ok(());
    };
    if !(0.05..=3600.0).contains(&interval) {
        bail!("--interval must be between 0.05 and 3600 seconds");
    }

    let mut prev = read_snapshot(&map)?;
    let mut prev_t = Instant::now();
    let mut n = 0u64;
    while count.is_none_or(|c| n < c) {
        thread::sleep(Duration::from_secs_f64(interval));
        let cur = read_snapshot(&map)?;
        let now = Instant::now();
        // Rates use the measured elapsed time, not the nominal interval.
        let dt = now.duration_since(prev_t).as_secs_f64();
        let delta = cur.delta_since(&prev);
        if json {
            println!("{}", render::json(layout.iface(), &delta, Some(dt), unix_ms()));
        } else {
            print!("{}", render::table(layout.iface(), &delta, Some(dt), all));
        }
        prev = cur;
        prev_t = now;
        n += 1;
    }
    Ok(())
}

fn read_config(map: &MapHandle) -> Result<Config> {
    if map.value_size() as usize != CONFIG_SIZE {
        bail!("xs_config value size {} != {CONFIG_SIZE}: ABI mismatch", map.value_size());
    }
    let raw = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow!("xs_config has no element 0"))?;
    Ok(Config::from_bytes(&raw)?)
}

fn write_config(map: &MapHandle, cfg: Config) -> Result<()> {
    map.update(&0u32.to_ne_bytes(), &cfg.to_bytes(), MapFlags::ANY)?;
    Ok(())
}

fn config(layout: &PinLayout, changes: [(ConfigFlags, Option<Toggle>); 7]) -> Result<()> {
    let path = layout.map(MAP_CONFIG);
    let map = MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open {path:?} (is the program attached?)"))?;
    let mut cfg = read_config(&map)?;
    let before = cfg.flags;
    for (flag, toggle) in changes {
        if let Some(t) = toggle {
            cfg.flags.set(flag, t.on());
        }
    }
    if cfg.flags != before {
        // Validate the known bits only: bits set by a newer writer are kept.
        ConfigFlags::from_bits(cfg.flags.bits() & ConfigFlags::KNOWN)?;
        cfg.abi_version = ABI_VERSION;
        write_config(&map, cfg)?;
        // Persist so the setting survives a reboot (best-effort).
        let _ = xs_common::state::save(layout.iface(), &cfg);
        println!("{}: flags {:?} -> {:?}", layout.iface(), before, cfg.flags);
    } else {
        println!("{}: flags {:?}", layout.iface(), cfg.flags);
    }
    Ok(())
}
