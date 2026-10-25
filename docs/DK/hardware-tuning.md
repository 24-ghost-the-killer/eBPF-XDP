<!-- Sprog: **Dansk** · [English](../EN/hardware-tuning.md) -->

# C. Hardware til 10 Gbps og D. CPU / NUMA / RSS-strategi

Tal markeret *estimat* er planlægningstal fra publicerede XDP-resultater og
grundprincipper. De er hypoteser som Fase 16-benchmarkene
([performance.md](performance.md)) skal bekræfte, ikke udsagn.

## C. Anbefalet hardware

### Workload-aritmetik

| Frame-størrelse (på wire inkl. FCS) | Pakker/s ved 10 Gb/s line rate | ns mellem pakker (én core) |
|---|---|---|
| 64 B | 14,88 M | 67 |
| 128 B | 8,45 M | 118 |
| 256 B | 4,53 M | 221 |
| 512 B | 2,35 M | 426 |
| 1024 B | 1,20 M | 834 |
| 1518 B (1500 MTU) | 0,81 M | 1 230 |
| Simpel IMIX (7×64 : 4×570 : 1×1518) | ≈ 3,3 M | ≈ 300 |

(pps = 10¹⁰ / ((størrelse + 20 B preamble/IFG) × 8).)

Designpunktet er **64-byte line rate (14,88 Mpps)**: SYN-, UDP- og ICMP-floods
bruger minimum-størrelse frames, og en scrubbing-appliance der kollapser under
små pakker fejler præcis når der er brug for den.

*Estimat:* native XDP på nuværende NIC'er dropper 15–25 Mpps pr. core med et
trivielt program; driver-omkostning er ~40–60 ns/pakke. Fuld-pipeline-målet er
≤ 150 ns/pakke inkl. driveren under angrebstrafik (cache-misses på policy- og
heavy-hitter-opslag dominerer), omkring 6,5 Mpps pr. core → **3 cores til 14,88
Mpps, provisioneret som 8 RX-cores** (≥ 2,5× headroom til cache-miss-tunge
random-source-floods, ujævn RSS og fremtidige trin).

### Materialeliste

| Del | Anbefaling | Noter |
|---|---|---|
| CPU | **Enkelt socket**, 16–32 fysiske cores, høj vedvarende all-core-clock: AMD EPYC (Zen 4/Zen 5, 16–32-core-dele) eller Intel Xeon (Sapphire/Emerald/Granite Rapids, 16–32-core-dele) | Én socket fjerner cross-NUMA-trafik helt. Per-core-hastighed og cache-størrelse betyder mere end core-antal for XDP. |
| NIC | En af familierne nedenfor; et **dual-port 25 GbE-kort kørende på 10 GbE** foretrækkes (headroom, kø-antal, samme prisklasse) | Native XDP i mainline-driveren er obligatorisk. |
| Hukommelse | 64 GB minimum, 128 GB anbefalet, alle kanaler fyldt | BPF maps ≈ 0,4 GB ved standardvalg; agent < 4 GB. Fyld hver kanal: båndbredde, ikke størrelse, betyder noget. |
| Lager | 2 × NVMe (RAID1) til OS/logs | ClickHouse på en **separat** host i produktion. |
| PCIe | Gen3 x8 er rigeligt til 2×10G/2×25G | Verificér det forhandlede link: `lspci -vv -s <bdf> \| grep -E 'LnkCap\|LnkSta'`; et down-trained link begrænser stille throughput. |
| Management | Separat 1 GbE-NIC til SSH/API/metrics | Management skal forblive opnåelig mens data-NIC'en er under angreb. |

### NIC-familier

| Familie | Driver | Native XDP | AF_XDP zero-copy | Noter |
|---|---|---|---|---|
| Intel E810 (E810-XXVDA2/4; 10/25/100G) | `ice` | ja | ja | Store kø-antal, Flow Director; nyere kerner tilføjer XDP-metadata-kfuncs. Hold NVM/firmware og DDP-pakken opdateret. |
| Intel X710 / XL710 / XXV710 (10/25/40G) | `i40e` | ja | ja | Moden, bredt udrullet, 10G-native. Tjek standard-UDP-RSS-hashing (D.2). |
| Intel 82599 / X520 (10G) | `ixgbe` | ja | ja | Virker, men ældre, færre køer og historiske XDP-TX-kø-grænser på high-core-count-maskiner. Ikke til nye builds. |
| NVIDIA/Mellanox ConnectX-5, ConnectX-6 Dx/Lx, ConnectX-7 | `mlx5_core` | ja | ja | Blandt de hurtigste XDP-drivere; multi-buffer-XDP; ConnectX-6 Lx (25G) er det omkostningseffektive valg. |
| Broadcom NetXtreme-E | `bnxt_en` | ja | ja | Brugbar; validér den specifikke firmware. |
| virtio-net | `virtio_net` | ja (VM'er) | begrænset | Kun udvikling / cloud. |

Portabilitetsregel: koden afhænger kun af generiske features (native XDP, RSS,
standard `ethtool`-knapper). Vendor-features (Flow Director, DDP, hardware flow
steering, XDP-metadata-kfuncs) er valgfrie accelerationer bag feature-detection,
aldrig krav.

**Undgå** NIC'er uden native XDP i mainline-driveren: generic (skb) XDP kører
*efter* skb-allokering og mister størstedelen af gevinsten, hvilket er grunden til
at `sentinelctl attach` ikke har en stille "auto"-fallback.

---

## D. CPU / NUMA / RSS-strategi

### D.1 CPU-partition (24-core enkelt-socket-eksempel)

| Cores | Rolle | Hvordan |
|---|---|---|
| 0–1 | OS, sshd, journald, systemd | standard cpuset |
| 2–9 (8 cores) | **RX: NAPI + XDP**, én RX-kø pr. core, 1:1 | IRQ-affinitet; `ethtool -L <if> combined 8` |
| 10–13 | sentinel-agent pinnede tråde (collector, ringbuf-drain, window-builder, policy-motor) | tråd-affinitet, systemd `CPUAffinity=` |
| 14–15 | agent tokio-runtime, sentinel-inference | systemd `AllowedCPUs=` |
| 16–23 | reserve / headroom | |

Regler:
* **RX-cores på NIC'ens NUMA-node.** `cat /sys/class/net/<if>/device/numa_node`
  og `lscpu`; allokér store BPF maps på den node (loaderen sætter `numa_node`).
  På dual-socket-maskiner rører den anden socket aldrig RX-stien.
* **Én RX-kø pr. fysisk core, ikke pr. hyperthread.** SMT-søskende deler L1/L2 og
  eksekveringsenheder. Lad RX-cores' søskende være idle eller slå SMT fra, og
  benchmark så begge.
* **Control plane aldrig på RX-cores**, så feature-beregning ikke kan stjæle
  cyklusser fra pakkebehandling.

### D.2 RSS (Receive Side Scaling)

NIC'en hasher header-felter (Toeplitz) og bruger en indirection-tabel til at vælge
RX-køen; hver køs interrupt/NAPI-kontekst kører på sin egen core, så hver
XDP-instans kører uafhængigt på sin egen CPU.

* **Kø-antal** = antal RX-cores: `ethtool -L <if> combined 8`.
* **Hash-felter er en sikkerhedsbeslutning.** `ethtool -n <if> rx-flow-hash udp4`
  viser hvad der hashes. Flere drivere hasher kun IP-adresser for UDP som standard,
  så en single-source-UDP-flood lander på **én** core. Inkludér porte:
  `ethtool -N <if> rx-flow-hash udp4 sdfn` (og `udp6`, `tcp4`, `tcp6`). Fragmenter
  bærer ingen porte og hasher altid kun på adresser, så en single-source-fragment-flood
  koncentrerer stadig — én grund til at `drop_fragments` findes som en
  angrebstids-switch.
* **Indirection-tabel:** `ethtool -x <if>`; hold den uniform
  (`ethtool -X <if> equal 8`).
* **Symmetrisk hashing** betyder kun noget for inline-mode med XDP på begge
  NIC'er; vores per-retnings-state har ikke brug for det.

### D.3 IRQ-affinitet

* Hold irqbalance væk fra NIC-IRQ'er: slå det fra på appliancen, eller sæt
  `IRQBALANCE_BANNED_CPULIST=2-9` og pin manuelt.
* Pin kø *i*'s IRQ til RX-core *i*: `echo <cpu> > /proc/irq/<irq>/smp_affinity_list`
  for hver `<if>-TxRx-<i>`- (Intel) / `mlx5_comp<i>`- (NVIDIA) linje i
  `/proc/interrupts`. `scripts/tune-nic.sh` (Fase 15) automatiserer og verificerer
  dette.
* Interrupt-coalescing: hold adaptiv RX-coalescing tændt
  (`ethtool -C <if> adaptive-rx on`); under flood coalescer driveren kraftigt,
  hvilket er hvad vi vil have. Tune kun med benchmark-evidens.

### D.4 RPS / RFS / XPS

| Feature | Hvad den gør | Aktivér? |
|---|---|---|
| RPS (software-RSS) | re-styrer pakker til andre CPU'er *efter* driveren, via IPI'er | **Nej.** XDP kører i driveren før RPS; med hardware-RSS tilføjer RPS kun IPI'er og cache-misses til passeret trafik. Kun nyttigt på single-queue-NIC'er. |
| RFS | styrer passeret trafik til den core der kører den forbrugende applikation | **Nej** i `inline`-mode (ingen lokal forbruger). Måske i `host`-mode med en lokal tjeneste: benchmark. |
| XPS | mapper CPU'er til TX-køer for kernestakken | **Ja, 1:1 CPU → TX-kø** (de fleste drivere defaulter til det). Undgår TX-kø-lås-konkurrence for forwardet trafik. XDP_TX bruger driverens per-CPU-XDP-TX-rings og er upåvirket. |

### D.5 Aktivér ikke blindt

| Knap | Hvorfor ikke |
|---|---|
| `isolcpus=` | Fjerner cores fra scheduleren permanent og interagerer dårligt med irqbalance og systemd-cpusets; NAPI-softirq-arbejde er alligevel ikke scheduler-drevet. Brug cpusets / `AllowedCPUs`. |
| `nohz_full=` | Hjælper userspace busy-loops, ikke softirq-bundet NAPI; tilføjer housekeeping-kompleksitet. |
| Busy polling (`napi_defer_hard_irqs`, `gro_flush_timeout`, `SO_BUSY_POLL`) | Kan reducere IRQ-rate under last men brænder CPU når idle og ændrer latency. Evaluér i Fase 15. |
| Threaded NAPI (`/sys/class/net/<if>/threaded`) | Gør NAPI til en skedulerbar kthread (pinbar, men i konkurrence med userspace). Evaluér; ikke standard. |
| Store RX-rings (`ethtool -G rx 8192`) | Absorberer bursts men vokser cache-footprint og latency. Start ved 2048–4096 og benchmark. |
| At slå alle offloads fra | RX-checksum-offload er gratis. **LRO skal være slået fra** (drivere nægter XDP med LRO). GRO kører efter XDP og er irrelevant for det. |

### D.6 Aktivér

| Knap | Indstilling | Hvorfor |
|---|---|---|
| CPU-governor | `performance` | Frekvens-ramp-up-latency koster pakker ved burst-start. |
| C-states på RX-cores | begræns til C1 (`cpupower idle-set -D 2`, eller BIOS) | Dyb C-state-exit-latency (titusinder af µs) overfylder rings ved burst-start. |
| Turbo | til, hvis termisk headroom tillader | Per-core-hastighed er den primære XDP-skaleringsfaktor. |
| IOMMU | slået fra eller `iommu=pt` | Streng IOMMU-DMA-mapping koster en stor del af per-pakke-budgettet. |
| Ethernet flow control | `ethtool -A <if> rx off tx off` | Pause-frames under flood skubber congestion opstrøms og kan stalle linket. |
| BIOS | performance-profil, SMT per D.1, NPS1 / SNC slået fra med mindre NUMA-tunet, PCIe ASPM slået fra | Forudsigelighed. |

### Offloads

`rxvlan` (RX-VLAN-stripping) fjerner det ydre tag før XDP ser framet. Hvis
VLAN-bevidst policy eller per-VLAN-telemetri er nødvendig, sæt
`ethtool -K <if> rxvlan off`; ellers lad det være tændt og brug
`bpf_xdp_metadata_rx_vlan_tag`-kfuncet hvor driveren understøtter det (≥ 6.8).
Parseren håndterer tags til stede i framet uanset hvad.

### Verifikations-tjekliste (automatiseret i Fase 15)

```
ethtool -i <if>                   # driver, firmware-version
ethtool -l <if>                   # combined queues == RX-cores
ethtool -n <if> rx-flow-hash udp4 # inkluderer L4-porte
ethtool -x <if>                   # uniform indirection-tabel
ethtool -k <if> | grep -E 'large-receive-offload|rx-vlan-offload'
ethtool -a <if>                   # pause off
grep <if> /proc/interrupts        # IRQ'er; tjek så smp_affinity_list
cat /sys/class/net/<if>/device/numa_node
lspci -vv -s <bdf> | grep LnkSta  # fuld bredde og hastighed
cpupower frequency-info | grep governor
ip -d link show <if>              # "xdp" (native), ikke "xdpgeneric"
```
