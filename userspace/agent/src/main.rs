//! `sentinel-agent` - the long-running xdp-sentinel service.
//!
//! Phase 4 scope: own the dataplane lifecycle (attach/adopt the XDP program on
//! the configured interfaces, reusing pinned maps) and serve a native
//! Prometheus `/metrics` endpoint, driven by a TOML config file. It replaces
//! the Phase 1 `xs-textfile-exporter` bridge. Later phases add flow
//! aggregation, feature extraction, the inference client, the risk engine and
//! the HTTP API inside this same process.
//!
//! Design invariants honoured here:
//!   * stopping the agent never detaches the dataplane (SIGTERM stops serving,
//!     the XDP program and its pinned maps stay in place);
//!   * a restart re-adopts the existing pins, so counters and policies are
//!     preserved and metrics are continuous.

use std::path::PathBuf;

use clap::Parser;

mod config;
#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug, Parser)]
#[command(name = "sentinel-agent", version, about = "xdp-sentinel agent")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/xdp-sentinel/config.toml")]
    config: PathBuf,

    /// Parse and validate the config, print a summary, and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let text = std::fs::read_to_string(&cli.config)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", cli.config.display()))?;
    let cfg = config::Config::from_toml(&text)?;

    if cli.check {
        println!(
            "config OK: metrics {}, pin_root {}, {} interface(s): {}",
            cfg.metrics_addr,
            cfg.pin_root.display(),
            cfg.interfaces.len(),
            cfg.interfaces.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join(", ")
        );
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        linux::run(cfg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        anyhow::bail!("sentinel-agent manages XDP and only runs on Linux")
    }
}
