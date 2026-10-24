//! `sentinelctl`: operator CLI for the xdp-sentinel dataplane.
//!
//! Phase 1 scope: load/attach/detach the XDP program, show attachment
//! status, read counters, change the validity-mitigation config. From
//! Phase 4 the long-running `sentinel-agent` owns the dataplane and this
//! tool becomes a client of the agent API for everything except emergency
//! attach/detach.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[cfg(target_os = "linux")]
mod linux;
mod render;

#[derive(Debug, Parser)]
#[command(name = "sentinelctl", version, about = "xdp-sentinel dataplane control")]
pub struct Cli {
    /// bpffs directory under which per-interface pins are created.
    #[arg(long, global = true, default_value = xs_common::pin::DEFAULT_PIN_ROOT)]
    pub pin_root: PathBuf,

    /// Show libbpf debug output (including verifier logs on failure).
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Load the XDP object, pin its maps and attach it to an interface.
    Attach {
        #[arg(short, long)]
        iface: String,
        /// Compiled dataplane object.
        #[arg(long, env = "XS_BPF_OBJ", default_value = "/usr/lib/xdp-sentinel/xdp_main.bpf.o")]
        obj: PathBuf,
        /// XDP attach mode. There is deliberately no "auto": a silent
        /// fallback to generic mode runs XDP after skb allocation and loses
        /// most of the performance benefit.
        #[arg(long, value_enum, default_value_t = Mode::Native)]
        mode: Mode,
        /// Atomically replace an already attached xdp-sentinel program
        /// (upgrade without a window where no program is attached).
        #[arg(long)]
        replace: bool,
    },
    /// Detach the program and remove its pins.
    Detach {
        #[arg(short, long)]
        iface: String,
        /// Keep pinned maps (counters, config) for a later attach.
        #[arg(long)]
        keep_maps: bool,
        /// Detach whatever XDP program is attached, even if it is not ours.
        #[arg(long)]
        force: bool,
    },
    /// Show attachment mode, program id and config.
    Status {
        #[arg(short, long)]
        iface: String,
    },
    /// Print counters. Without --interval: cumulative totals. With it:
    /// per-interval deltas and rates.
    Stats {
        #[arg(short, long)]
        iface: String,
        /// Sampling interval in seconds.
        #[arg(long)]
        interval: Option<f64>,
        /// Number of intervals to print (default: until interrupted).
        #[arg(long)]
        count: Option<u64>,
        /// Include counters that are zero.
        #[arg(long)]
        all: bool,
        /// Emit one JSON object per sample instead of a table.
        #[arg(long, conflicts_with = "prometheus")]
        json: bool,
        /// Emit cumulative counters in the Prometheus text format (for the
        /// node_exporter textfile collector). Implies no --interval.
        #[arg(long, conflicts_with_all = ["interval", "count", "all"])]
        prometheus: bool,
    },
    /// Show or change the dataplane validity-mitigation flags.
    Config {
        #[arg(short, long)]
        iface: String,
        /// Drop frames the parser classifies as malformed.
        #[arg(long, value_enum)]
        drop_malformed: Option<Toggle>,
        /// Drop TCP flag combinations no conforming stack sends
        /// (NULL, XMAS, SYN+FIN, SYN+RST, FIN/PSH/URG without ACK).
        #[arg(long, value_enum)]
        drop_bad_tcp_flags: Option<Toggle>,
        /// Drop all IPv4/IPv6 fragments. Breaks legitimate fragmented
        /// traffic (e.g. large DNS/EDNS0 UDP responses); use only under attack.
        #[arg(long, value_enum)]
        drop_fragments: Option<Toggle>,
        /// Drop parsed incoming UDP packets addressed to destination port 53.
        #[arg(long, value_enum)]
        drop_udp_dns: Option<Toggle>,
        /// Drop UDP addressed to a service port (< 32768) under a UDP flood.
        /// Return traffic to ephemeral ports -- the box's own DNS/NTP replies
        /// and QUIC tunnels such as Twingate/WireGuard -- is always exempt, so
        /// this cannot sever the box's own connectivity or remote management.
        #[arg(long, value_enum)]
        drop_udp: Option<Toggle>,
        /// Lockdown: drop every IPv4 packet whose destination is not a protected
        /// host (protected hosts still follow their allowlist). Only the ingress
        /// interface should be armed; pair with an auto-revert timer.
        #[arg(long, value_enum)]
        lockdown: Option<Toggle>,
    },

    /// Block a source address (drop all its packets) until the TTL expires.
    /// IPv6 is blocked by its /64. The block survives agent restarts and
    /// lifts itself when the TTL passes, even with no userspace running.
    Block {
        #[arg(short, long)]
        iface: String,
        /// Source IP to block (v4 or v6).
        ip: IpAddr,
        /// Seconds until the block auto-expires. Omit or 0 = until removed.
        #[arg(long, default_value_t = 0)]
        ttl: u64,
    },
    /// Remove a source block.
    Unblock {
        #[arg(short, long)]
        iface: String,
        ip: IpAddr,
    },
    /// Allowlist a source network (or single IP). Allowlisted traffic is
    /// evaluated before any block. `full` trust bypasses all mitigation;
    /// `dynamic-exempt` only bypasses dynamic policies (still validity-checked).
    Allow {
        #[arg(short, long)]
        iface: String,
        /// CIDR (e.g. 10.0.0.0/8 or 2001:db8::/32) or a bare IP (= /32 or /128).
        cidr: String,
        #[arg(long, value_enum, default_value_t = TrustArg::Full)]
        trust: TrustArg,
        /// Seconds until the entry auto-expires. Omit or 0 = until removed.
        #[arg(long, default_value_t = 0)]
        ttl: u64,
    },
    /// Remove an allowlist entry (exact CIDR).
    Unallow {
        #[arg(short, long)]
        iface: String,
        cidr: String,
    },
    /// List active blocks and allowlist entries with their remaining TTL.
    List {
        #[arg(short, long)]
        iface: String,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Enable/update the automatic per-source rate limiter: any single source
    /// sending faster than <pps> packets/sec (beyond a burst allowance) has
    /// its excess dropped. Allowlisted sources are exempt. `--pps 0` disables it.
    Ratelimit {
        #[arg(short, long)]
        iface: String,
        /// Packets per second allowed per source. 0 disables the limiter.
        #[arg(long)]
        pps: u32,
        /// Burst allowance (bucket depth) in packets. 0 = auto (max(pps/10, 20)).
        #[arg(long, default_value_t = 0)]
        burst: u32,
    },

    /// Mark a destination as PROTECTED (positive security / default-deny): only
    /// the services added with `service` reach it; all other traffic to it is
    /// dropped. IPv4 only. Add your services BEFORE protecting to avoid an outage.
    Protect {
        #[arg(short, long)]
        iface: String,
        /// Destination IP to protect (IPv4).
        ip: IpAddr,
    },
    /// Remove a destination from default-deny (its service entries are kept).
    Unprotect {
        #[arg(short, long)]
        iface: String,
        ip: IpAddr,
    },
    /// Allow one service `{proto port}` on a protected destination. Use port 0
    /// for portless protocols (e.g. icmp). Remove it again with `--remove`.
    Service {
        #[arg(short, long)]
        iface: String,
        /// Protected destination IP (IPv4).
        ip: IpAddr,
        /// Transport protocol.
        #[arg(value_enum)]
        proto: ProtoArg,
        /// Destination port (0 for portless protocols such as ICMP).
        #[arg(default_value_t = 0)]
        port: u16,
        /// Remove this service instead of adding it.
        #[arg(long)]
        remove: bool,
    },
    /// Mirror the box's own `ufw` ALLOW rules into the service-allowlist for a
    /// destination (IPv4), so you manage open ports in ufw and the dataplane
    /// follows. Adds ports now open in ufw and removes allowlist entries no
    /// longer open there. Inbound ALLOW/LIMIT rules are mirrored by their port;
    /// a source- or interface-restricted rule is mirrored by port only (the
    /// allowlist has no source dimension, so it opens the port for all sources
    /// -- ufw itself still enforces the restriction behind the allowlist).
    /// App-profile, "Anywhere" and IPv6 rules have no numeric IPv4 port and are
    /// reported and skipped. Needs root (reads ufw).
    ServiceSync {
        #[arg(short, long)]
        iface: String,
        /// Destination IP the mirrored services apply to (IPv4).
        ip: IpAddr,
        /// Also mark the destination PROTECTED (default-deny) after syncing.
        #[arg(long)]
        protect: bool,
        /// Show what would change without touching the allowlist.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProtoArg {
    Tcp,
    Udp,
    Icmp,
}

impl ProtoArg {
    /// IANA IP protocol number used as the service key's `proto` field.
    pub fn number(self) -> u8 {
        match self {
            ProtoArg::Tcp => 6,
            ProtoArg::Udp => 17,
            ProtoArg::Icmp => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum TrustArg {
    /// Pass immediately, skip all mitigation.
    Full,
    /// Bypass dynamic policy only; still validity-checked.
    DynamicExempt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Driver (native) XDP.
    Native,
    /// Generic (skb) XDP: for testing on NICs without native support.
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Toggle {
    On,
    Off,
}

impl Toggle {
    pub fn on(self) -> bool {
        self == Toggle::On
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run(Cli::parse())
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    let _ = Cli::parse();
    anyhow::bail!("sentinelctl manages XDP programs and only runs on Linux")
}
