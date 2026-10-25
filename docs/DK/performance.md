<!-- Sprog: **Dansk** · [English](../EN/performance.md) -->

# P. Ydelse og benchmark-metodik

Der fremsættes intet throughput-udsagn nogen steder i dette projekt uden en
benchmark-kørsel registreret under `benchmarks/results/` med dens
host-metadata. Tallene i [hardware-tuning.md](hardware-tuning.md) er af den
grund markeret som estimater.

## To slags måling

| | Program-omkostnings-mikrobenchmark | Line-rate-benchmark |
|---|---|---|
| Værktøj | `BPF_PROG_TEST_RUN` med `repeat` (`benchmarks/xdp/bench_prog_run.c`) | ægte NIC + ekstern trafikgenerator |
| Måler | ns pr. invokation af BPF-programmet, varm cache, 1 CPU | pps/Gbps vedvarende uden tab, CPU pr. core, NIC-drops, latency |
| Udelader | driver, DMA, cache-misses fra ægte trafik, cross-CPU-effekter | intet |
| Kører | hver CI-build (container er fint) | Fase 16 på target-hardware; efter hver dataplan-ændring mikrobenchmarken flagger |
| Formål | regressions-gate: fang et trin der bliver langsommere | det eneste gyldige bevis for "10 Gbps" |

Et applikationsniveau-benchmark (iperf3 TCP-goodput, HTTP-load) er **ikke**
bevis for XDP-kapacitet: det måler TCP-stakken og applikationen. iperf3 bruges
kun som en sanity-check for at *passeret* legitim trafik stadig flyder ved fuld
hastighed mens mitigering er aktiv.

## Fase 1-resultater

Miljø: Docker Desktop linuxkit-VM, kerne 6.12.76, aarch64 (Apple Silicon-host),
clang 19, libbpf 1.5. **Ikke repræsentativ for en x86-64-server med en ægte
NIC**; registreret som regressions-baseline.

Verifier (`scripts/verifier-stats.sh`): 26 370 instruktioner behandlet (grænse
1 000 000), 2 001 states, ~75 ms verifikation; 792 BPF-instruktioner, 4,1 KiB
JIT-image; stak 64 B.

Programomkostning (`make bench-prog`, repeat = 2 000 000, bedste af 5):

| Frame | Størrelse (wire) | Tomt program (ns) | xdp_main (ns) | Programomkostning (ns) |
|---|---|---|---|---|
| IPv4 TCP SYN | 64–1500 | 5 | 11–12 | **6–7** |
| IPv4 UDP | 64–1500 | 5 | 11 | **6** |
| QinQ IPv4 UDP | 64–1500 | 5 | 12 | **7** |
| IPv6 + 3 ext hdrs + TCP | 64–1500 | 5 | 15 | **10** |

Omkostningen er uafhængig af frame-størrelse, som forventet: programmet rører
kun headers. Kernen rapporterer hele nanosekunder, så ±1 ns er støj.

## Line-rate-metodik

### Topologi

```
┌────────────────────┐   10/25 GbE, direkte kabel    ┌──────────────────────────┐
│ trafikgenerator     │ ───────────────────────────▶ │ DUT (xdp-sentinel)        │
│ TRex (DPDK) eller   │                              │ XDP på ingress-porten     │
│ kernel pktgen       │ ◀─────────────────────────── │ (inline-mode: egress-port │
│ separat maskine     │   retursti (inline-tests)    │  tilbage til generator)   │
└────────────────────┘                              └──────────────────────────┘
```

* Generator på en **separat** maskine, direkte kablet (ingen switch-buffering i
  målingen).
* Generatorens kapacitet valideres først (loopback eller en trivielt droppende
  DUT): et resultat er ugyldigt hvis generatoren ikke kunne producere den tilbudte
  last.
* TRex (stateless mode, DPDK) er den primære generator: eksakte rates, IMIX,
  per-stream latency-måling. Kernel pktgen (`benchmarks/xdp/pktgen_tx.sh`) er
  fallback når ingen DPDK-kapabel generator-NIC er tilgængelig; MoonGen er et
  acceptabelt alternativ.

### Trin (hvad der er aktiveret i programmet)

Hvert trin bygges fra **samme kildekode** med compile-time stage-switches
(tilføjet i Fase 15), så trinnene måler den faktiske kode, ikke et separat
legetøj.

| Trin | Program |
|---|---|
| R0 baseline | `return XDP_DROP` (driver + XDP-gulv) |
| R1 XDP + tællere | parse + per-CPU-tællere (= Fase 1) |
| R2 XDP + politik | + allowlist + politik-opslag (Fase 2) |
| R3 XDP + rate limiting | + GCRA + service-budgetter (Fase 3) |
| R4 XDP + telemetri | + HLL, heavy hitters, port-histogram, sampling (Fase 5) |
| R5 fuld pipeline | R4 + agent, inferens og policy-motor kørende og skrivende politikker |

Til kapacitetsmålinger dropper DUT'en alt i enden af pipelinen (en bench-only
konfig-bit), fordi `XDP_PASS` ellers ville måle kernestakken. `XDP_PASS` måles
separat som "passeret trafik-throughput".

### Matrix

* **Pakkestørrelser:** 64, 128, 256, 512, 1024, 1500 bytes (+ IMIX).
* **RX-cores:** 1, 2, 4, 8, 16 (`ethtool -L <if> combined N`, IRQ'er pinnet 1:1,
  RSS uniform).
* **Trafik-blandinger:**
  1. enkelt flow (worst case for RSS: én core),
  2. 1 024 flows (godt spredt, cache-venligt),
  3. tilfældige kildeadresser (2²⁴ kilder) — cache-miss-tung, motionerer
     LRU-optagelse,
  4. random-source SYN-flood + 10% legitim IMIX (realistisk angreb),
  5. UDP-reflektionsmønster (faste kildeporte 53/123, mange kilder, én
     destination).

### Procedure pr. celle

1. Anvend `scripts/tune-nic.sh`-indstillinger; registrér dem i metadata.
2. Varm op 10 s.
3. **Nul-tabs-throughput-søgning** (RFC 2544-stil): binær søgning på tilbudt
   last; et forsøg (30 s) består hvis NIC-drops (`rx_missed`, `rx_dropped`,
   driver-specifik `rx_out_of_buffer`/`rx_no_buffer`) holder sig ≤ 0,001% af
   tilbudte pakker. Opløsning 1% af line rate.
4. Ved den fundne rate, registrér: XDP-sete pps/Gbps (`sentinelctl stats
   --json`), NIC-drop-tællere (`ethtool -S` før/efter), per-core softirq %
   (`mpstat`), program-køretid (`bpftool prog profile` eller
   `kernel.bpf_stats_enabled=1` → `run_time_ns / run_cnt`).
   `benchmarks/xdp/measure_rx.sh` samler alle disse for ét forsøg.
5. Latency (inline-mode, kun passeret trafik): TRex latency-streams ved 10%,
   50%, 90% af nul-tabs-raten: min/avg/p99/p99.9/max.
6. Gentag cellen 3 gange; rapportér medianen og spredningen.

### Registrering

`benchmarks/results/<dato>-<host>-<trin>.json`: host-metadata (CPU-model,
microcode, BIOS-profil, kerne, NIC-model, firmware, driver-version,
kø/IRQ-layout, ring-størrelser, offloads, BPF-objekt-SHA-256, git-SHA),
celle-matrixen, rå per-sekund-samples og tuning-scriptets output. Resultater
sammenlignes med den forrige kørsel af samme host; en > 5% regression i en
celle fejler benchmark-jobbet.

### Accept-kriterie for "10 Gbps"

Appliancen erklæres 10 Gbps-kapabel på en given hardware-model kun hvis **trin
R5, trafik-blanding 4, 64-byte frames, når 14,88 Mpps med nul tab på ≤ 8
RX-cores**, og et 30-minutters soak ved den last viser ingen NIC-drops, ingen
ring-buffer-tab over 1%, stabil window-to-decision-latency (p99 < 2 s) og ingen
hukommelsesvækst i agenten.

## Userspace-benchmarks

| Område | Benchmark | Mål |
|---|---|---|
| collector | fuldt tick (tællere + HLL + service-arrays + heavy-hitter-batch) ved 32 CPU'er, 40 k heavy hitters (`benchmarks/collector/`, criterion) | p99 < 100 ms |
| ringbuf-drain | forbrugsrate, dekodede samples/s på én core | ≥ 2 M samples/s |
| feature-engine | window-build med 160 k samples/s input | < 20% af én core |
| inferens | 10 k-række-batch pr. model (`benchmarks/inference/`) | p99 < 20 ms |
| end-to-end | angrebsstart → første politik i map, fra TRex-timestamps og `policy_decisions` (`benchmarks/end-to-end/`) | < 3 s p95 |
