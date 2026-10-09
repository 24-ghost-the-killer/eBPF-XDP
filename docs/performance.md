# P. Performance and benchmark methodology

No throughput claim is made anywhere in this project without a benchmark
run recorded under `benchmarks/results/` with its host metadata. The
figures in [hardware-tuning.md](hardware-tuning.md) are marked as
estimates for that reason.

## Two kinds of measurement

| | Program-cost microbenchmark | Line-rate benchmark |
|---|---|---|
| Tool | `BPF_PROG_TEST_RUN` with `repeat` (`benchmarks/xdp/bench_prog_run.c`) | real NIC + external traffic generator |
| Measures | ns per invocation of the BPF program, hot cache, 1 CPU | pps/Gbps sustained without loss, CPU per core, NIC drops, latency |
| Excludes | driver, DMA, cache misses from real traffic, cross-CPU effects | nothing |
| Runs | every CI build (container is fine) | Phase 16 on target hardware; after every dataplane change that the microbenchmark flags |
| Purpose | regression gate: catch a stage getting slower | the only valid evidence for "10 Gbps" |

An application-level benchmark (iperf3 TCP goodput, HTTP load) is **not**
evidence of XDP capacity: it measures the TCP stack and the application.
iperf3 is used only as a sanity check that *passed* legitimate traffic
still flows at full speed while mitigation is active.

## Phase 1 results

Environment: Docker Desktop linuxkit VM, kernel 6.12.76, aarch64 (Apple
Silicon host), clang 19, libbpf 1.5. **Not representative of an x86-64
server with a real NIC**; recorded as the regression baseline.

Verifier (`scripts/verifier-stats.sh`): 26 370 instructions processed
(limit 1 000 000), 2 001 states, ~75 ms verification; 792 BPF instructions,
4.1 KiB JIT image; stack 64 B.

Program cost (`make bench-prog`, repeat = 2 000 000, best of 5):

| Frame | Size (wire) | Empty program (ns) | xdp_main (ns) | Program cost (ns) |
|---|---|---|---|---|
| IPv4 TCP SYN | 64–1500 | 5 | 11–12 | **6–7** |
| IPv4 UDP | 64–1500 | 5 | 11 | **6** |
| QinQ IPv4 UDP | 64–1500 | 5 | 12 | **7** |
| IPv6 + 3 ext hdrs + TCP | 64–1500 | 5 | 15 | **10** |

Cost is independent of frame size, as expected: the program only touches
headers. The kernel reports whole nanoseconds, so ±1 ns is noise.

## Line-rate methodology

### Topology

```
┌────────────────────┐   10/25 GbE, direct cable    ┌──────────────────────────┐
│ traffic generator   │ ───────────────────────────▶ │ DUT (xdp-sentinel)        │
│ TRex (DPDK) or      │                              │ XDP on the ingress port   │
│ kernel pktgen       │ ◀─────────────────────────── │ (inline mode: egress port │
│ separate machine    │   return path (inline tests) │  back to generator)       │
└────────────────────┘                              └──────────────────────────┘
```

* Generator on a **separate** machine, directly cabled (no switch buffering
  in the measurement).
* Generator capacity is validated first (loopback or a trivially dropping
  DUT): a result is invalid if the generator could not produce the offered
  load.
* TRex (stateless mode, DPDK) is the primary generator: exact rates, IMIX,
  per-stream latency measurement. Kernel pktgen
  (`benchmarks/xdp/pktgen_tx.sh`) is the fallback when no DPDK-capable
  generator NIC is available; MoonGen is an acceptable alternative.

### Rungs (what is enabled in the program)

Each rung is built from the **same source** with compile-time stage
switches (added in Phase 15), so rungs measure the actual code, not a
separate toy.

| Rung | Program |
|---|---|
| R0 baseline | `return XDP_DROP` (driver + XDP floor) |
| R1 XDP + counters | parse + per-CPU counters (= Phase 1) |
| R2 XDP + policy | + allowlist + policy lookups (Phase 2) |
| R3 XDP + rate limiting | + GCRA + service budgets (Phase 3) |
| R4 XDP + telemetry | + HLL, heavy hitters, port histogram, sampling (Phase 5) |
| R5 full pipeline | R4 + agent, inference and policy engine running and writing policies |

For capacity measurements the DUT drops everything at the end of the
pipeline (a bench-only config bit), because `XDP_PASS` would otherwise
measure the kernel stack. `XDP_PASS` is measured separately as "passed
traffic throughput".

### Matrix

* **Packet sizes:** 64, 128, 256, 512, 1024, 1500 bytes (+ IMIX).
* **RX cores:** 1, 2, 4, 8, 16 (`ethtool -L <if> combined N`, IRQs pinned
  1:1, RSS uniform).
* **Traffic mixes:**
  1. single flow (worst case for RSS: one core),
  2. 1 024 flows (well spread, cache-friendly),
  3. random source addresses (2²⁴ sources) — cache-miss-heavy, exercises
     LRU admission,
  4. random-source SYN flood + 10% legitimate IMIX (realistic attack),
  5. UDP reflection pattern (fixed source ports 53/123, many sources, one
     destination).

### Procedure per cell

1. Apply `scripts/tune-nic.sh` settings; record them in metadata.
2. Warm up 10 s.
3. **Zero-loss throughput search** (RFC 2544 style): binary search on
   offered load; a trial (30 s) passes if NIC drops (`rx_missed`,
   `rx_dropped`, driver-specific `rx_out_of_buffer`/`rx_no_buffer`) stay
   ≤ 0.001% of offered packets. Resolution 1% of line rate.
4. At the found rate, record: XDP-seen pps/Gbps (`sentinelctl stats
   --json`), NIC drop counters (`ethtool -S` before/after), per-core
   softirq % (`mpstat`), program run time (`bpftool prog profile` or
   `kernel.bpf_stats_enabled=1` → `run_time_ns / run_cnt`).
   `benchmarks/xdp/measure_rx.sh` collects all of these for one trial.
5. Latency (inline mode, passed traffic only): TRex latency streams at
   10%, 50%, 90% of the zero-loss rate: min/avg/p99/p99.9/max.
6. Repeat the cell 3 times; report the median and spread.

### Recording

`benchmarks/results/<date>-<host>-<rung>.json`: host metadata (CPU model,
microcode, BIOS profile, kernel, NIC model, firmware, driver version,
queue/IRQ layout, ring sizes, offloads, BPF object SHA-256, git SHA), the
cell matrix, raw per-second samples, and the tuning script output. Results
are compared against the previous run of the same host; a > 5% regression
in any cell fails the benchmark job.

### Acceptance criterion for "10 Gbps"

The appliance is declared 10 Gbps-capable on a given hardware model only if
**rung R5, traffic mix 4, 64-byte frames, reaches 14.88 Mpps with zero loss
on ≤ 8 RX cores**, and a 30-minute soak at that load shows no NIC drops,
no ring-buffer loss above 1%, stable window-to-decision latency (p99 < 2 s)
and no memory growth in the agent.

## Userspace benchmarks

| Area | Benchmark | Target |
|---|---|---|
| collector | full tick (counters + HLL + service arrays + heavy-hitter batch) at 32 CPUs, 40 k heavy hitters (`benchmarks/collector/`, criterion) | p99 < 100 ms |
| ringbuf drain | consume rate, decoded samples/s on one core | ≥ 2 M samples/s |
| feature engine | window build with 160 k samples/s input | < 20% of one core |
| inference | 10 k-row batch per model (`benchmarks/inference/`) | p99 < 20 ms |
| end-to-end | attack start → first policy in map, from TRex timestamps and `policy_decisions` (`benchmarks/end-to-end/`) | < 3 s p95 |
