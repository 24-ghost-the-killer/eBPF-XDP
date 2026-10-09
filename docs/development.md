# Q. Development: roadmap, build, test

## Roadmap

Each phase ends with its tests green in CI and an exit criterion met. No
phase starts before the previous one's exit criterion, and the ML phases
(10–12) cannot start before the dataset exists (8) and the deterministic
baseline works (9).

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **1** ✅ | XDP parser + per-CPU counters; `sentinelctl` attach/detach/status/stats/config; host, in-kernel and veth tests; program-cost microbenchmark | all tests green; verifier budget < 5% of limit; microbenchmark recorded |
| **2** ✅ | BPF policy maps: allowlist LPM (v4/v6), per-source policy HASH (v4 /32, v6 /64), `expires_ns` enforcement, policy sub-counters; `sentinelctl block/unblock/allow/unallow/list`; `CHECK_*` config bits auto-managed | `tests/bpf/test_policy.c` verifies precedence (allowlist FULL > block > validity > pass), DYNAMIC_EXEMPT, TTL expiry against CLOCK_MONOTONIC, gating, and the verdict invariant; passes on kernels 6.12 and 7.0. CIDR-block LPM (block a whole network) and the ARRAY_OF_MAPS inner-map swap are deferred to a follow-on. |
| **3** ✅ | Rate limiting: automatic per-source GCRA limiter (shared TAT + compare-and-swap, LRU state map v4/v6), `sentinelctl ratelimit --pps --burst`, exempts allowlisted sources; `rate_limited`/`rate_tracked` counters | `tests/bpf/test_ratelimit.c`: GCRA conformance (burst bounded, sustained rate, idle reset), per-source independence, under-limit never dropped, allowlist exemption, invariant; verified live capping a 463k-pps flood to ~1000 pps. Per-class (SYN/UDP/ICMP) and byte-rate limits, named-source RATE_LIMIT policies, and per-service budgets are a follow-on. |
| **4** ✅ | `sentinel-agent`: owns attach/adopt of the dataplane, native Prometheus `/metrics` + `/healthz` + `/readyz` (dependency-free HTTP server), strict TOML config, systemd unit; retires `xs-textfile-exporter`; shared metrics rendering moved to `xs-common` | verified: agent restart leaves the dataplane attached and adopts pins (counters continuous), metrics match `sentinelctl`; deployed on the server with Prometheus scraping it directly. The in-process collector/feature/policy threads described in the design land in Phases 5–6/13. |
| 5 | Flow aggregation: HLL, heavy hitters (admission), port histogram, sampling + ring buffer, userspace flow table | cardinality within 3% on synthetic traffic, ring-buffer loss accounted exactly, admission bound verified with a random-source flood |
| 6 | Feature extraction: windows, all features in feature-schema.md, schema YAML + hash | property tests per feature; golden-file test (fixed pcap → fixed feature vectors) |
| 7 | Prometheus/Grafana dashboards, alert rules, ClickHouse schema + writer | dashboards provisioned; ClickHouse outage test (bounded buffer, drops counted) |
| 8 | Dataset generation: lab attack generator (TRex profiles), labelling, export tooling | ≥ 7 attack types × 3 intensities recorded with ground truth |
| 9 | Statistical baseline detector (robust z-score, CUSUM) + deterministic rules | detects all lab attacks with FPR < 10⁻⁴/window on a clean week |
| 10 | Anomaly model (Isolation Forest), training pipeline, ONNX export, `sentinel-inference` | pipeline reproducible from manifest; ONNX parity test; beats baseline on PR-AUC |
| 11 | DDoS classifier (LightGBM) | per-type recall ≥ 0.95 at target FPR on time-split test |
| 12 | Bot detector | precision ≥ 0.9 at operating point on held-out weeks |
| 13 | Risk engine: evidence fusion, ladder, hysteresis, TTLs, guard rails, service protection, shadow mode | simulation tests (replayed windows → decisions) including flapping, circuit breaker, budget limits |
| 14 | Dashboard | all views; e2e UI tests against a recorded agent stream |
| 15 | Performance optimisation: `tune-nic.sh`, rung builds, NUMA placement, profiling | microbenchmark regression gate in CI; per-stage cost documented |
| 16 | 10 Gbps benchmarking per performance.md | acceptance criterion met (or documented gap and remedy) |

## Build

Requirements on a Linux build host: clang ≥ 16, llvm-strip, libbpf-dev
≥ 1.0, bpftool, libelf-dev, zlib1g-dev, pkg-config, Rust ≥ 1.85 (for the
sanitizer tests: `libclang-rt-dev` on Debian/Ubuntu).

```sh
make                 # ebpf/build/xdp_main.bpf.o + target/release/sentinelctl
make -C ebpf dump    # annotated disassembly of the BPF object
```

`ebpf/vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` on first build
(`make -C ebpf vmlinux` to regenerate; `VMLINUX_BTF=<file>` to use another
kernel's BTF).

Any host with Docker (e.g. macOS):

```sh
make docker-image    # Debian trixie + Rust + clang 19 + libbpf 1.5 + bpftool
make docker-test     # everything below, in a --privileged container
make docker-shell    # interactive
```

The container uses the Docker VM's kernel, so verifier results reflect that
kernel (6.12 on current Docker Desktop). It cannot measure line rate.

## Tests

| Command | Needs | What it checks |
|---|---|---|
| `make test-host` | any host, clang | parser on the host with ASan + UBSan: 70-case corpus (every field), all prefixes of every frame (~5 k truncations), 200 k random bit-flip mutations |
| `make test-rust` | any host | ABI drift test (parses `abi.h`), config encoding/validation, pin-path validation (rejects `..`, `/`), snapshot summation and wrap-safe deltas, rendering |
| `make lint` | any host | `cargo fmt --check`, `clippy -D warnings` (incl. undocumented `unsafe`) |
| `make test-bpf` | root, BPF kernel | loads the object through the verifier (prints stats), runs the corpus with `BPF_PROG_TEST_RUN` under default and strict config, checks verdicts and exact counter deltas, and the invariants Σ parse outcomes = Σ verdicts = rx |
| `make verifier` | root | `bpftool prog loadall` + verifier statistics |
| `make test-integration` | root, iproute2, python3 | veth pair + netns, **native** XDP attach via `sentinelctl`, real ICMP, crafted malformed frames over AF_PACKET, config toggles, atomic replace preserving pins, refusal to clobber, clean detach |
| `make bench-prog` | root | program cost vs an empty XDP program, 4 frame types × 6 sizes |

Malformed-packet coverage (requirement 29), all in `tests/common/cases.h`:
truncated Ethernet, truncated IPv4, invalid IHL (< 5 and beyond frame),
invalid IPv4 total length (too big, < IHL), invalid TCP data offset (< 5
and beyond segment), truncated TCP/UDP/ICMP, invalid UDP length (< 8, >
payload, < payload), invalid TCP flags (NULL, XMAS, SYN+FIN, SYN+RST,
FIN-only), IPv4 fragments (first, later, tiny first), IPv6 fragments
(first, later, atomic, tiny), IPv6 extension headers (HBH, chain of 3, AH,
6 = limit, 7 = unsupported, truncated header, header beyond frame, header
beyond payload length), VLAN (802.1Q, 802.1ad QinQ, 0x9100 QinQ, 3 tags,
truncated tag, VLAN+ARP), IPv6 (TCP, UDP, ICMPv6, ESP, no-next-header,
ICMPv4-in-IPv6, bad version, payload length too big/zero, padding), LAND.

## Phase 1 report

### Code

| Path | Content |
|---|---|
| `ebpf/src/abi.h` | counter slots, parse outcomes, `xs_stats`, `xs_config` (ABI with userspace) |
| `ebpf/src/compat.h` | BPF/host shim; `xs_opaque`, `xs_ntohs_bounded` verifier helpers |
| `ebpf/src/parsers.h` | L2–L4 parser (pure functions) |
| `ebpf/src/maps.h`, `telemetry.h`, `xdp_main.c` | maps, accounting, entry point and validity verdict |
| `userspace/common` | ABI mirror, pin layout, snapshots |
| `userspace/ctl` | `sentinelctl` |
| `tests/…`, `benchmarks/xdp/…`, `scripts/…` | as above |

### Expected output

`make test-host`:

```
corpus: 70 cases
truncation fuzz: 4982 prefixes parsed
bitflip fuzz: 200000 mutated frames, outcomes: rc0=… rc1=… … rc23=…
parser tests: OK
```

`sudo make test-bpf`:

```
verifier: accepted, 792 BPF insns
verification time … usec
stack depth 64+0
processed 26370 insns (limit 1000000) max_states_per_insn 20 total_states 2001 …
default  config: 69 frames run, 1 skipped (shorter than ETH_HLEN)
strict   config: 69 frames run, 1 skipped (shorter than ETH_HLEN)
invariants: rx=138 == sum(parse outcomes) == sum(verdicts)
xdp tests: OK
```

(The 10-byte truncated-Ethernet frame is rejected by the kernel's test-run
harness itself, which requires ≥ 14 bytes; the host tests cover it. Exact
verifier numbers vary with kernel and clang versions.)

`sudo make test-integration` ends with `veth smoke: 18 passed, 0 failed`.

`sentinelctl stats -i <if> --interval 2 --count 1` (real capture from the
veth setup: 10 pings, 2 truncated-TCP and 3 XMAS frames, plus the kernel's
own ARP and IPv6 MLD traffic, whose Hop-by-Hop header shows up as
`ipv6_ext`):

```
interface xs0: last 2.01s
counter                               packets              bytes            pps       Mbit/s
rx                                         21               1748             10         0.01
verdict_pass                               21               1748             10         0.01
l3_ipv4                                    15               1280              7         0.01
l3_ipv6                                     5                426              2         0.00
l3_arp                                      1                 42              0         0.00
l4_tcp                                      3                180              1         0.00
l4_icmp                                    10                980              5         0.00
l4_icmpv6                                   5                426              2         0.00
ipv6_ext                                    3                270              1         0.00
tcp_fin                                     3                180              1         0.00
anom_tcp_bad_flags                          3                180              1         0.00
parse_ok                                   18               1586              9         0.01
parse_not_ip                                1                 42              0         0.00
parse_err_tcp_trunc                         2                120              1         0.00
```

### Engineering notes from Phase 1

* **Verifier and byte swaps:** the 6.12 verifier loses value bounds across
  `BPF_END`; `iph + ntohs(tot_len)` was rejected until the value was
  re-masked behind an optimisation barrier (`xs_ntohs_bounded`).
* **Verification cost:** fully inlined, the program needed 603 k verified
  instructions (60% of the limit) because every parser outcome multiplied
  through the accounting code. Making the parser a global BPF function cut
  it to 40 k; walking IPv6 extension headers with a re-masked scalar offset
  (so unrolled iterations share verifier state) cut it to 26 k. This
  headroom is what Phases 2–5 will spend.
* **Attach semantics:** netlink attachment with explicit `DRV_MODE`, not a
  `bpf_link`: the program must outlive the loader process (agent crash ≠
  unprotected interface), generic-mode fallback must be an error, and
  upgrades use `XDP_FLAGS_REPLACE`.
* **Per-packet cost:** one per-CPU lookup for all counters plus one inlined
  config lookup; 6–10 ns of program time on a hot cache.
* **Compiler vs verifier across global functions (found on Linux 7.0 /
  clang 21):** clang 21 propagates a global function's return range across
  the call and deleted the bounds check on the rc-indexed counter slot; the
  verifier, which treats global-function returns as unknown, then rejected
  the program ("R2 unbounded memory access"). Clang 19 did not do this.
  Fixed by passing the return value through `xs_opaque()`. Every value
  returned from a global BPF function and used for indexing must be
  treated this way.
* **Kernel ≥ 7.0 BTF:** such kernels are built with `-fms-extensions`, and
  `vmlinux.h` contains anonymous tagged members; the BPF build uses
  `-fms-extensions -Wno-microsoft-anon-tag`.
* **Tested kernels/toolchains:** 6.12 (arm64, clang 19, libbpf 1.5) and
  7.0 (x86-64, Ubuntu 26.04, clang 21, libbpf 1.6).
