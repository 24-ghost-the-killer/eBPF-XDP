<!-- Sprog: **Dansk** · [English](../EN/development.md) -->

# Q. Udvikling: roadmap, build, test

## Roadmap

Hver fase slutter med dens tests grønne i CI og et exit-kriterie opfyldt. Ingen
fase starter før den foregåendes exit-kriterie, og ML-faserne (10–12) kan ikke
starte før datasættet eksisterer (8) og den deterministiske baseline virker (9).

| Fase | Leverance | Exit-kriterie |
|---|---|---|
| **1** ✅ | XDP-parser + per-CPU-tællere; `sentinelctl` attach/detach/status/stats/config; host-, in-kernel- og veth-tests; program-omkostnings-mikrobenchmark | alle tests grønne; verifier-budget < 5% af grænsen; mikrobenchmark registreret |
| **2** ✅ | BPF policy-maps: allowlist LPM (v4/v6), per-source policy HASH (v4 /32, v6 /64), `expires_ns`-håndhævelse, policy-sub-tællere; `sentinelctl block/unblock/allow/unallow/list`; `CHECK_*`-konfig-bits auto-styret | `tests/bpf/test_policy.c` verificerer præcedens (allowlist FULL > block > validitet > pass), DYNAMIC_EXEMPT, TTL-udløb mod CLOCK_MONOTONIC, gating og verdict-invarianten; består på kerner 6.12 og 7.0. CIDR-block LPM (blokér et helt netværk) og ARRAY_OF_MAPS inner-map-swap er udskudt til en opfølgning. |
| **3** ✅ | Rate limiting: automatisk per-source GCRA-limiter (delt TAT + compare-and-swap, LRU-state-map v4/v6), `sentinelctl ratelimit --pps --burst`, undtager allowlistede kilder; `rate_limited`/`rate_tracked`-tællere | `tests/bpf/test_ratelimit.c`: GCRA-konformitet (burst afgrænset, vedvarende rate, idle-reset), per-source-uafhængighed, under-grænse aldrig droppet, allowlist-undtagelse, invariant; verificeret live ved at kappe en 463k-pps-flood til ~1000 pps. Per-klasse (SYN/UDP/ICMP) og byte-rate-grænser, navngivne-kilde-RATE_LIMIT-politikker og per-service-budgetter er en opfølgning. |
| **4** ✅ | `sentinel-agent`: ejer attach/adopt af dataplanet, native Prometheus `/metrics` + `/healthz` + `/readyz` (dependency-fri HTTP-server), streng TOML-konfig, systemd-unit; pensionerer `xs-textfile-exporter`; delt metrics-rendering flyttet til `xs-common` | verificeret: agent-genstart efterlader dataplanet tilkoblet og adopterer pins (tællere kontinuerlige), metrics matcher `sentinelctl`; udrullet på serveren med Prometheus der scraper den direkte. De in-process collector/feature/policy-tråde beskrevet i designet lander i Fase 5–6/13. |
| 5 | Flow-aggregering: HLL, heavy hitters (optagelse), port-histogram, sampling + ring buffer, userspace flow-tabel | kardinalitet inden for 3% på syntetisk trafik, ring-buffer-tab opgjort eksakt, optagelses-grænse verificeret med en random-source-flood |
| 6 | Feature-ekstraktion: vinduer, alle features i feature-schema.md, schema-YAML + hash | property-tests pr. feature; golden-file-test (fast pcap → faste feature-vektorer) |
| 7 | Prometheus/Grafana-dashboards, alarm-regler, ClickHouse-schema + writer | dashboards provisioneret; ClickHouse-nedbruds-test (afgrænset buffer, drops talt) |
| 8 | Datasæt-generering: lab-angrebsgenerator (TRex-profiler), labelling, eksport-værktøj | ≥ 7 angrebstyper × 3 intensiteter registreret med ground truth |
| 9 | Statistisk baseline-detektor (robust z-score, CUSUM) + deterministiske regler | detekterer alle lab-angreb med FPR < 10⁻⁴/vindue på en ren uge |
| 10 | Anomali-model (Isolation Forest), træningspipeline, ONNX-eksport, `sentinel-inference` | pipeline reproducerbar fra manifest; ONNX-paritetstest; slår baseline på PR-AUC |
| 11 | DDoS-klassifikator (LightGBM) | per-type recall ≥ 0,95 ved target-FPR på time-split-test |
| 12 | Bot-detektor | precision ≥ 0,9 ved driftspunkt på held-out-uger |
| 13 | Risiko-motor: evidence-fusion, stige, hysterese, TTL'er, guard rails, service-beskyttelse, shadow-mode | simulations-tests (afspillede vinduer → beslutninger) inkl. flapping, circuit breaker, budget-grænser |
| 14 | Dashboard | alle views; e2e-UI-tests mod en optaget agent-stream |
| 15 | Ydelses-optimering: `tune-nic.sh`, rung-builds, NUMA-placering, profilering | mikrobenchmark-regressions-gate i CI; per-trin-omkostning dokumenteret |
| 16 | 10 Gbps-benchmarking per performance.md | accept-kriterie opfyldt (eller dokumenteret hul og afhjælpning) |

## Build

Krav på en Linux-build-host: clang ≥ 16, llvm-strip, libbpf-dev ≥ 1.0, bpftool,
libelf-dev, zlib1g-dev, pkg-config, Rust ≥ 1.85 (til sanitizer-testene:
`libclang-rt-dev` på Debian/Ubuntu).

```sh
make                 # ebpf/build/xdp_main.bpf.o + target/release/sentinelctl
make -C ebpf dump    # annoteret disassembly af BPF-objektet
```

`ebpf/vmlinux.h` genereres fra `/sys/kernel/btf/vmlinux` ved første build
(`make -C ebpf vmlinux` for at regenerere; `VMLINUX_BTF=<file>` for at bruge en
anden kernes BTF).

Enhver host med Docker (f.eks. macOS):

```sh
make docker-image    # Debian trixie + Rust + clang 19 + libbpf 1.5 + bpftool
make docker-test     # alt nedenfor, i en --privileged container
make docker-shell    # interaktivt
```

Containeren bruger Docker-VM'ens kerne, så verifier-resultater afspejler den
kerne (6.12 på nuværende Docker Desktop). Den kan ikke måle line rate.

## Tests

| Kommando | Kræver | Hvad den tjekker |
|---|---|---|
| `make test-host` | enhver host, clang | parser på hosten med ASan + UBSan: 70-case corpus (hvert felt), alle præfikser af hvert frame (~5 k trunkeringer), 200 k tilfældige bit-flip-mutationer |
| `make test-rust` | enhver host | ABI-drift-test (parser `abi.h`), config-encoding/validering, pin-path-validering (afviser `..`, `/`), snapshot-summation og wrap-safe deltas, rendering |
| `make lint` | enhver host | `cargo fmt --check`, `clippy -D warnings` (inkl. udokumenteret `unsafe`) |
| `make test-bpf` | root, BPF-kerne | loader objektet gennem verifieren (printer stats), kører corpus'et med `BPF_PROG_TEST_RUN` under standard- og streng-konfig, tjekker verdicts og eksakte tæller-deltas, samt invarianterne Σ parse-udfald = Σ verdicts = rx |
| `make verifier` | root | `bpftool prog loadall` + verifier-statistik |
| `make test-integration` | root, iproute2, python3 | veth-par + netns, **native** XDP-attach via `sentinelctl`, ægte ICMP, fremstillede malformede frames over AF_PACKET, config-toggles, atomisk replace der bevarer pins, nægtelse af at overskrive, ren detach |
| `make bench-prog` | root | programomkostning vs et tomt XDP-program, 4 frame-typer × 6 størrelser |

Malformed-pakke-dækning (krav 29), alt i `tests/common/cases.h`: trunkeret
Ethernet, trunkeret IPv4, ugyldig IHL (< 5 og ud over frame), ugyldig IPv4
total-længde (for stor, < IHL), ugyldig TCP data offset (< 5 og ud over segment),
trunkeret TCP/UDP/ICMP, ugyldig UDP-længde (< 8, > payload, < payload), ugyldige
TCP-flags (NULL, XMAS, SYN+FIN, SYN+RST, FIN-only), IPv4-fragmenter (første,
senere, lille første), IPv6-fragmenter (første, senere, atomic, lille),
IPv6-extension-headers (HBH, kæde af 3, AH, 6 = grænse, 7 = ikke-understøttet,
trunkeret header, header ud over frame, header ud over payload-længde), VLAN
(802.1Q, 802.1ad QinQ, 0x9100 QinQ, 3 tags, trunkeret tag, VLAN+ARP), IPv6 (TCP,
UDP, ICMPv6, ESP, no-next-header, ICMPv4-in-IPv6, dårlig version, payload-længde
for stor/nul, padding), LAND.

## Fase 1-rapport

### Kode

| Sti | Indhold |
|---|---|
| `ebpf/src/abi.h` | tæller-slots, parse-udfald, `xs_stats`, `xs_config` (ABI med userspace) |
| `ebpf/src/compat.h` | BPF/host-shim; `xs_opaque`, `xs_ntohs_bounded` verifier-helpers |
| `ebpf/src/parsers.h` | L2–L4-parser (rene funktioner) |
| `ebpf/src/maps.h`, `telemetry.h`, `xdp_main.c` | maps, regnskab, entry point og validitets-verdict |
| `userspace/common` | ABI-spejl, pin-layout, snapshots |
| `userspace/ctl` | `sentinelctl` |
| `tests/…`, `benchmarks/xdp/…`, `scripts/…` | som ovenfor |

### Forventet output

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

(Det 10-byte trunkerede-Ethernet-frame afvises af kernens egen test-run-harness,
som kræver ≥ 14 bytes; host-testene dækker det. Eksakte verifier-tal varierer med
kerne- og clang-versioner.)

`sudo make test-integration` slutter med `veth smoke: 18 passed, 0 failed`.

`sentinelctl stats -i <if> --interval 2 --count 1` (ægte capture fra
veth-opsætningen: 10 pings, 2 trunkerede-TCP og 3 XMAS-frames, plus kernens egen
ARP- og IPv6-MLD-trafik, hvis Hop-by-Hop-header viser sig som `ipv6_ext`):

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

### Ingeniørnoter fra Fase 1

* **Verifier og byte-swaps:** 6.12-verifieren mister value-bounds på tværs af
  `BPF_END`; `iph + ntohs(tot_len)` blev afvist indtil værdien blev re-masket bag
  en optimerings-barriere (`xs_ntohs_bounded`).
* **Verifikations-omkostning:** fuldt inlinet krævede programmet 603 k verificerede
  instruktioner (60% af grænsen) fordi hvert parser-udfald multiplicerede gennem
  regnskabskoden. At gøre parseren til en global BPF-funktion skar det til 40 k;
  at gå IPv6-extension-headers igennem med en re-masket scalar offset (så
  unrollede iterationer deler verifier-state) skar det til 26 k. Denne headroom er
  hvad Fase 2–5 vil bruge.
* **Attach-semantik:** netlink-attachment med eksplicit `DRV_MODE`, ikke en
  `bpf_link`: programmet skal overleve loader-processen (agent-crash ≠ ubeskyttet
  interface), generic-mode-fallback skal være en fejl, og opgraderinger bruger
  `XDP_FLAGS_REPLACE`.
* **Per-pakke-omkostning:** ét per-CPU-opslag for alle tællere plus ét inlinet
  config-opslag; 6–10 ns programtid på en varm cache.
* **Compiler vs verifier på tværs af globale funktioner (fundet på Linux 7.0 /
  clang 21):** clang 21 propagerer en global funktions return-range på tværs af
  kaldet og slettede bounds-checket på den rc-indekserede tæller-slot;
  verifieren, som behandler global-funktions-returns som ukendte, afviste så
  programmet ("R2 unbounded memory access"). Clang 19 gjorde ikke dette. Rettet
  ved at sende return-værdien gennem `xs_opaque()`. Hver værdi returneret fra en
  global BPF-funktion og brugt til indeksering skal behandles sådan.
* **Kerne ≥ 7.0 BTF:** sådanne kerner bygges med `-fms-extensions`, og
  `vmlinux.h` indeholder anonyme taggede members; BPF-buildet bruger
  `-fms-extensions -Wno-microsoft-anon-tag`.
* **Testede kerner/toolchains:** 6.12 (arm64, clang 19, libbpf 1.5) og 7.0
  (x86-64, Ubuntu 26.04, clang 21, libbpf 1.6).
