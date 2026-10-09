# C. Hardware for 10 Gbps and D. CPU / NUMA / RSS strategy

Figures marked *estimate* are planning numbers from published XDP results
and first principles. They are hypotheses for the Phase 16 benchmarks
([performance.md](performance.md)) to confirm, not claims.

## C. Recommended hardware

### Workload arithmetic

| Frame size (on wire incl. FCS) | Packets/s at 10 Gb/s line rate | ns between packets (one core) |
|---|---|---|
| 64 B | 14.88 M | 67 |
| 128 B | 8.45 M | 118 |
| 256 B | 4.53 M | 221 |
| 512 B | 2.35 M | 426 |
| 1024 B | 1.20 M | 834 |
| 1518 B (1500 MTU) | 0.81 M | 1 230 |
| Simple IMIX (7×64 : 4×570 : 1×1518) | ≈ 3.3 M | ≈ 300 |

(pps = 10¹⁰ / ((size + 20 B preamble/IFG) × 8).)

The design point is **64-byte line rate (14.88 Mpps)**: SYN, UDP and ICMP
floods use minimum-size frames, and a scrubbing appliance that collapses
under small packets fails exactly when it is needed.

*Estimate:* native XDP on current NICs drops 15–25 Mpps per core with a
trivial program; driver cost is ~40–60 ns/packet. The full-pipeline target
is ≤ 150 ns/packet including the driver under attack traffic (cache misses
on policy and heavy-hitter lookups dominate), about 6.5 Mpps per core →
**3 cores for 14.88 Mpps, provisioned as 8 RX cores** (≥ 2.5× headroom for
cache-miss-heavy random-source floods, uneven RSS and future stages).

### Bill of materials

| Part | Recommendation | Notes |
|---|---|---|
| CPU | **Single socket**, 16–32 physical cores, high sustained all-core clock: AMD EPYC (Zen 4/Zen 5, 16–32-core parts) or Intel Xeon (Sapphire/Emerald/Granite Rapids, 16–32-core parts) | One socket removes cross-NUMA traffic entirely. Per-core speed and cache size matter more than core count for XDP. |
| NIC | One of the families below; a **dual-port 25 GbE card running at 10 GbE** is preferred (headroom, queue counts, same price class) | Native XDP in the mainline driver is mandatory. |
| Memory | 64 GB minimum, 128 GB recommended, all channels populated | BPF maps ≈ 0.4 GB at defaults; agent < 4 GB. Populate every channel: bandwidth, not size, matters. |
| Storage | 2 × NVMe (RAID1) for OS/logs | ClickHouse on a **separate** host in production. |
| PCIe | Gen3 x8 is ample for 2×10G/2×25G | Verify the negotiated link: `lspci -vv -s <bdf> \| grep -E 'LnkCap\|LnkSta'`; a downtrained link silently caps throughput. |
| Management | Separate 1 GbE NIC for SSH/API/metrics | Management must stay reachable while the data NIC is under attack. |

### NIC families

| Family | Driver | Native XDP | AF_XDP zero-copy | Notes |
|---|---|---|---|---|
| Intel E810 (E810-XXVDA2/4; 10/25/100G) | `ice` | yes | yes | Large queue counts, Flow Director; recent kernels add XDP metadata kfuncs. Keep NVM/firmware and the DDP package current. |
| Intel X710 / XL710 / XXV710 (10/25/40G) | `i40e` | yes | yes | Mature, widely deployed, 10G-native. Check default UDP RSS hashing (D.2). |
| Intel 82599 / X520 (10G) | `ixgbe` | yes | yes | Works, but older, fewer queues and historical XDP TX-queue limits on high-core-count machines. Not for new builds. |
| NVIDIA/Mellanox ConnectX-5, ConnectX-6 Dx/Lx, ConnectX-7 | `mlx5_core` | yes | yes | Among the fastest XDP drivers; multi-buffer XDP; ConnectX-6 Lx (25G) is the cost-effective choice. |
| Broadcom NetXtreme-E | `bnxt_en` | yes | yes | Viable; validate the specific firmware. |
| virtio-net | `virtio_net` | yes (VMs) | limited | Development / cloud only. |

Portability rule: the code relies only on generic features (native XDP,
RSS, standard `ethtool` knobs). Vendor features (Flow Director, DDP,
hardware flow steering, XDP metadata kfuncs) are optional accelerations
behind feature detection, never requirements.

**Avoid** NICs without native XDP in the mainline driver: generic (skb)
XDP runs *after* skb allocation and loses most of the benefit, which is why
`sentinelctl attach` has no silent "auto" fallback.

---

## D. CPU / NUMA / RSS strategy

### D.1 CPU partition (24-core single-socket example)

| Cores | Role | How |
|---|---|---|
| 0–1 | OS, sshd, journald, systemd | default cpuset |
| 2–9 (8 cores) | **RX: NAPI + XDP**, one RX queue per core, 1:1 | IRQ affinity; `ethtool -L <if> combined 8` |
| 10–13 | sentinel-agent pinned threads (collector, ringbuf drain, window builder, policy engine) | thread affinity, systemd `CPUAffinity=` |
| 14–15 | agent tokio runtime, sentinel-inference | systemd `AllowedCPUs=` |
| 16–23 | spare / headroom | |

Rules:
* **RX cores on the NIC's NUMA node.** `cat /sys/class/net/<if>/device/numa_node`
  and `lscpu`; allocate large BPF maps on that node (the loader sets
  `numa_node`). On dual-socket machines the other socket never touches the
  RX path.
* **One RX queue per physical core, not per hyperthread.** SMT siblings
  share L1/L2 and execution units. Leave RX cores' siblings idle or disable
  SMT, then benchmark both.
* **Control plane never on RX cores**, so feature computation cannot steal
  cycles from packet processing.

### D.2 RSS (Receive Side Scaling)

The NIC hashes header fields (Toeplitz) and uses an indirection table to
pick the RX queue; each queue's interrupt/NAPI context runs on its own core,
so every XDP instance runs independently on its own CPU.

* **Queue count** = number of RX cores: `ethtool -L <if> combined 8`.
* **Hash fields are a security decision.** `ethtool -n <if> rx-flow-hash udp4`
  shows what is hashed. Several drivers hash only IP addresses for UDP by
  default, so a single-source UDP flood lands on **one** core. Include
  ports: `ethtool -N <if> rx-flow-hash udp4 sdfn` (and `udp6`, `tcp4`,
  `tcp6`). Fragments carry no ports and always hash on addresses only, so a
  single-source fragment flood still concentrates — one reason
  `drop_fragments` exists as an attack-time switch.
* **Indirection table:** `ethtool -x <if>`; keep it uniform
  (`ethtool -X <if> equal 8`).
* **Symmetric hashing** matters only for inline mode with XDP on both NICs;
  our per-direction state does not need it.

### D.3 IRQ affinity

* Keep irqbalance away from NIC IRQs: disable it on the appliance, or set
  `IRQBALANCE_BANNED_CPULIST=2-9` and pin manually.
* Pin queue *i*'s IRQ to RX core *i*: `echo <cpu> >
  /proc/irq/<irq>/smp_affinity_list` for each `<if>-TxRx-<i>` (Intel) /
  `mlx5_comp<i>` (NVIDIA) line in `/proc/interrupts`. `scripts/tune-nic.sh`
  (Phase 15) automates and verifies this.
* Interrupt coalescing: keep adaptive RX coalescing on
  (`ethtool -C <if> adaptive-rx on`); under flood the driver coalesces
  heavily, which is what we want. Tune only with benchmark evidence.

### D.4 RPS / RFS / XPS

| Feature | What it does | Enable? |
|---|---|---|
| RPS (software RSS) | re-steers packets to other CPUs *after* the driver, via IPIs | **No.** XDP runs in the driver before RPS; with hardware RSS, RPS only adds IPIs and cache misses to passed traffic. Useful only on single-queue NICs. |
| RFS | steers passed traffic to the core running the consuming application | **No** in `inline` mode (no local consumer). Maybe in `host` mode with a local service: benchmark. |
| XPS | maps CPUs to TX queues for the kernel stack | **Yes, 1:1 CPU → TX queue** (most drivers default to it). Avoids TX-queue lock contention for forwarded traffic. XDP_TX uses the driver's per-CPU XDP TX rings and is unaffected. |

### D.5 Do not enable blindly

| Knob | Why not |
|---|---|
| `isolcpus=` | Removes cores from the scheduler permanently and interacts badly with irqbalance and systemd cpusets; NAPI softirq work is not scheduler-driven anyway. Use cpusets / `AllowedCPUs`. |
| `nohz_full=` | Helps userspace busy loops, not softirq-bound NAPI; adds housekeeping complexity. |
| Busy polling (`napi_defer_hard_irqs`, `gro_flush_timeout`, `SO_BUSY_POLL`) | May reduce IRQ rate under load but burns CPU when idle and changes latency. Evaluate in Phase 15. |
| Threaded NAPI (`/sys/class/net/<if>/threaded`) | Makes NAPI a schedulable kthread (pinnable, but competing with userspace). Evaluate; not default. |
| Huge RX rings (`ethtool -G rx 8192`) | Absorbs bursts but grows cache footprint and latency. Start at 2048–4096 and benchmark. |
| Disabling all offloads | RX checksum offload is free. **LRO must be off** (drivers refuse XDP with LRO). GRO runs after XDP and is irrelevant to it. |

### D.6 Enable

| Knob | Setting | Why |
|---|---|---|
| CPU governor | `performance` | Frequency ramp-up latency costs packets at burst start. |
| C-states on RX cores | limit to C1 (`cpupower idle-set -D 2`, or BIOS) | Deep C-state exit latency (tens of µs) overflows rings at burst start. |
| Turbo | on, thermal headroom permitting | Per-core speed is the main XDP scaling factor. |
| IOMMU | off or `iommu=pt` | Strict IOMMU DMA mapping costs a large share of the per-packet budget. |
| Ethernet flow control | `ethtool -A <if> rx off tx off` | Pause frames under flood push congestion upstream and can stall the link. |
| BIOS | performance profile, SMT per D.1, NPS1 / SNC off unless NUMA-tuned, PCIe ASPM off | Predictability. |

### Offloads

`rxvlan` (RX VLAN stripping) removes the outer tag before XDP sees the
frame. If VLAN-aware policy or per-VLAN telemetry is needed, set
`ethtool -K <if> rxvlan off`; otherwise leave it on and use the
`bpf_xdp_metadata_rx_vlan_tag` kfunc where the driver supports it (≥ 6.8).
The parser handles tags present in the frame either way.

### Verification checklist (automated in Phase 15)

```
ethtool -i <if>                   # driver, firmware version
ethtool -l <if>                   # combined queues == RX cores
ethtool -n <if> rx-flow-hash udp4 # includes L4 ports
ethtool -x <if>                   # uniform indirection table
ethtool -k <if> | grep -E 'large-receive-offload|rx-vlan-offload'
ethtool -a <if>                   # pause off
grep <if> /proc/interrupts        # IRQs; then check smp_affinity_list
cat /sys/class/net/<if>/device/numa_node
lspci -vv -s <bdf> | grep LnkSta  # full width and speed
cpupower frequency-info | grep governor
ip -d link show <if>              # "xdp" (native), not "xdpgeneric"
```
