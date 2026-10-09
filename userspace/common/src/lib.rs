//! Types shared by every xdp-sentinel userspace component.
//!
//! * [`abi`]: byte-exact mirror of `ebpf/src/abi.h` (map value layouts,
//!   counter slots, config flags). Decoding is done with explicit
//!   `from_ne_bytes` on fixed offsets: no `unsafe` transmutes of kernel
//!   buffers.
//! * [`pin`]: the bpffs layout under which the dataplane's maps and program
//!   are pinned, and validation of the interface names used to build it.
//! * [`stats`]: aggregation of per-CPU counter blocks into snapshots and
//!   wrap-safe deltas between snapshots.
//!
//! This crate has no Linux-specific dependencies so it builds and tests on
//! any development host.

pub mod abi;
pub mod classifier;
pub mod clickhouse;
pub mod detect;
pub mod features;
pub mod flow;
pub mod iforest;
pub mod logistic;
pub mod metrics;
pub mod pin;
pub mod policy;
pub mod risk;
pub mod sha256;
pub mod state;
pub mod stats;

pub use abi::{AbiError, Config, ConfigFlags, Counter};
pub use pin::PinLayout;
pub use policy::{Action, Allow, Policy, Trust};
pub use stats::Snapshot;
