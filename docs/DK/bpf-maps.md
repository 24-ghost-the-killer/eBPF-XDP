<!-- Sprog: **Dansk** · [English](../EN/bpf-maps.md) -->

# G. BPF-map-design

Alle maps er defineret i `ebpf/src/maps.h` (tilføjet fase for fase), pinnet pr.
interface under `/sys/fs/bpf/xdp-sentinel/<ifname>/`, og spejlet i
`userspace/common/src/abi.rs`. Hver value-struct har en fast størrelse med
reserveret padding, fordi libbpf nægter at genbruge et pinnet map hvis
key/value-størrelse ændrede sig, og en opgradering må ikke stille nulstille
politikker.

Status: `xs_stats` og `xs_config` er implementeret (Fase 1). Resten er designet
som senere faser implementerer.

## Map-type-evaluering

| Type | Opslags-omkostning fra XDP | Skrivninger fra mange CPU'er | Hukommelse | Brugt til | Afvist til |
|---|---|---|---|---|---|
| `ARRAY` | inlinet af verifieren (få instruktioner) | delte cache-linjer → kun read-mostly-data | `max_entries × value` | config, service-config | enhver per-pakke-tæller (false sharing) |
| `PERCPU_ARRAY` | helper-kald (inlinet på ≥ 6.10-kerner) | ingen: hver CPU ejer sin kopi | `× nr_possible_cpus` | tællere, per-service-state, HLL, port-histogram, sampling-state | store sparse key-rum |
| `HASH` | jhash + bucket-walk; ~20–50 ns, domineret af cache-misses | per-bucket-lås ved update; opslag lock-free (RCU) | preallokeret som standard | control-plane-ejede exact-match-tabeller (source-politikker) | angriber-nøglede tabeller (udtømning) |
| `LRU_HASH` | som HASH, plus LRU-vedligehold ved insert | eviction-lås (global LRU) eller per-CPU-lister (`BPF_F_NO_COMMON_LRU`) | preallokeret | — | politikker (ville stille evicte aktive mitigeringer) |
| `PERCPU_HASH` | som HASH | ingen for values | `entries × cpus × value` | — (ingen angriber-nøglet tabel må være non-LRU) | |
| `LRU_PERCPU_HASH` | som LRU_HASH | ingen for values | `entries × cpus × value` | per-source heavy-hitter-statistik | noget stort (hukommelse × CPU'er) |
| `LPM_TRIE` | trie-walk; titals ns for små tries, mere for store IPv6-tries | lås ved update | `BPF_F_NO_PREALLOC` obligatorisk | allowlists, CIDR-regler, destination → service | per-pakke exact-matches (HASH er hurtigere) |
| `RINGBUF` | `bpf_ringbuf_reserve/submit` (spinlock ved reserve, delt) | MPSC | fast power-of-two-størrelse | samplede headers, sjældne events | per-pakke-telemetri |
| `ARRAY_OF_MAPS` | +1 opslag | — | — | atomisk hele-sæt-udskiftning af allowlist/CIDR-tries | — |

Principper:

1. **Per-pakke-skrivninger går til per-CPU-hukommelse.** Den eneste delte
   skrivbare state på pakke-stien er GCRA-ordet for en *rate-limited* kilde, og de
   er sjældne ved konstruktion
   ([policy-engine.md](policy-engine.md#rate-limiting)).
2. **Angriber-nøglede tabeller er LRU og admission-kontrollerede**; tabeller
   angriberen ikke kan indsætte i (politikker, services) er almindelige
   HASH/ARRAY/LPM ejet af control plane.
3. **Exact match før prefix match**; LPM-tries konsulteres kun når de ikke er
   tomme (config-bits).
4. **Store maps lever på NIC'ens NUMA-node** (`numa_node`-map-attribut sat af
   loaderen fra `/sys/class/net/<if>/device/numa_node`).

## Map-inventar

Standardstørrelser (konfigurérbare); hukommelse for 32 mulige CPU'er.

| # | Navn | Type | Key → value | Entries | Hukommelse | Fase | Krav |
|---|---|---|---|---|---|---|---|
| 1 | `xs_stats` | PERCPU_ARRAY | `u32` → `struct xs_stats` (128 × {pkts, bytes}) | 1 | 64 KiB | **1 ✅** | per-CPU pakke- og byte-tællere |
| 2 | `xs_config` | ARRAY | `u32` → `struct xs_config` (64 B) | 1 | 64 B | **1 ✅** | konfiguration |
| 3 | `xs_allow_v4` / `xs_allow_v6` | LPM_TRIE (inner) via ARRAY_OF_MAPS | `{prefixlen, addr}` → `{trust, rule_id}` | 16 384 hver | ~2 MiB | 2 | allowlists |
| 4 | `xs_cidr_policy_v4/v6` | LPM_TRIE (inner) via ARRAY_OF_MAPS | `{prefixlen, addr}` → `struct xs_policy` | 65 536 hver | ~16 MiB | 2 | blokerede IPv4/IPv6-CIDR'er |
| 5 | `xs_src_policy_v4` | HASH | `__be32` → `struct xs_policy` | 1 048 576 | ~180 MiB | 2–3 | blokeret IPv4, midlertidige rate-limits, policy-state |
| 6 | `xs_src_policy_v6` | HASH | `u64` (/64-prefix) → `struct xs_policy` | 262 144 | ~48 MiB | 2–3 | blokeret IPv6, rate-limits |
| 7 | `xs_dst_service_v4/v6` | LPM_TRIE | `{prefixlen, addr}` → `u16 service_id` | 4 096 | < 1 MiB | 3 | destinations-politikker |
| 8 | `xs_service_cfg` | ARRAY | `u32 service_id` → `struct xs_service_cfg` | 4 096 | 512 KiB | 3 | destinations-politikker, angrebs-state |
| 9 | `xs_service_state` | PERCPU_ARRAY | `u32 service_id` → `struct xs_service_state` | 4 096 | 16 MiB | 3 | per-destination-statistik |
| 10 | `xs_src_stats_v4` / `_v6` | LRU_PERCPU_HASH, `BPF_F_NO_COMMON_LRU` | `__be32` / `u64` → `struct xs_src_stats` (64 B) | 32 768 / 8 192 | ~80 MiB | 5 | per-source-statistik |
| 11 | `xs_hll` | PERCPU_ARRAY | `u32 epoch` (0/1) → 4 × 4096 u8-registre | 2 | 1 MiB | 5 | unikke src/dst/port/flow-tællinger |
| 12 | `xs_dport_hist` | PERCPU_ARRAY | `u32 dport` → `{u32 tcp, u32 udp}` | 65 536 | 16 MiB | 5 | port-distribution / entropi |
| 13 | `xs_cpu_state` | PERCPU_ARRAY | `u32` → `struct xs_cpu_state` | 1 | 2 KiB | 5 | sampling-state |
| 14 | `xs_samples` | RINGBUF | 64-byte `struct xs_sample`-records | 16 MiB | 16 MiB | 5 | samplet telemetri |
| 15 | `xs_known_good_v4/v6` | BLOOM_FILTER (≥ 5.16) | kildeadresse (value-only-map) | 1 048 576 | ~1,2 MiB (10 bits/entry, ~1% FP) | 13 | known-good-first service-beskyttelse ([policy-engine.md](policy-engine.md#service-protection-distributed-attacks)) |

Total ved standardvalg, 32 CPU'er: **≈ 380 MiB**, domineret af den preallokerede
IPv4-policy-hash (dimensioneret til 1 M samtidige mitigeringer). Halvér den på
mindre bokse.

### 1. `xs_stats` (implementeret)

Ét element der holder alle 128 tæller-slots, så en pakke behøver præcis **ét**
opslag uanset hvor mange tællere den rører; increments er almindelige stores ind i
CPU'ens egen 2 KiB-blok. De ~80 ubrugte slots efterlader plads til nye tællere uden
at ændre value-størrelsen (pinned-map-kompatibilitet). Slot-numre er ABI:
dashboards og historik nøgler på dem.

### 2. `xs_config` (implementeret)

```c
struct xs_config {              /* 64 bytes */
	__u32 abi_version;
	__u32 flags;                /* P1: DROP_MALFORMED | DROP_BAD_TCP_FLAGS | DROP_FRAGMENTS
	                               P2: ALLOW_NONEMPTY | HAS_CIDR_POLICY
	                               P5: SAMPLING | HLL | DPORT_HIST */
	__u64 reserved[7];          /* P5: hll_epoch, sample_one_in, sample_cap_per_cpu,
	                               hh_admit_mask, ... */
};
```

Et almindeligt ARRAY fordi hver CPU læser det på hver pakke og userspace skriver
det sjældent: cache-linjen forbliver delt og ren overalt. Nul-værdien er den sikre
standard (kun observér), så et nyoprettet map behøver ingen initialisering for at
være sikkert.

### 3–4. Allowlists og CIDR-politikker

LPM-tries nøglet af `struct { __u32 prefixlen; __u8 addr[4|16]; }`. Hver er det
eneste inner-map af et `ARRAY_OF_MAPS`, så agenten bygger en komplet ny trie ved
siden af og bytter den ind med én update: en reload observeres aldrig
halvt-anvendt. Det ekstra ydre opslag betales kun når `ALLOW_NONEMPTY` /
`HAS_CIDR_POLICY` er sat.

Allowlist-`trust`-værdier:
* `full`: pass straks, spring al mitigering over (management-netværk opnåelige kun
  på betroede stier);
* `dynamic_exempt`: immun over for dynamiske (ML/heuristiske) politikker, stadig
  underlagt statiske sikkerheds-lofter (service-budgetter). Standard for alt
  opnåeligt fra internettet, fordi allowlistede kildeadresser kan spoofes.

### 5–6. Source-politikker

```c
struct xs_gcra {                /* 16 bytes, see policy-engine.md */
	__u64 tat_ns;               /* theoretical arrival time; CAS-updated by XDP */
	__u32 interval_ns;          /* 1e9 / rate; 0 = class not limited */
	__u32 tolerance_ns;         /* interval × (burst - 1) */
};

struct xs_policy {              /* 128 bytes */
	__u64 expires_ns;           /* CLOCK_MONOTONIC; XDP ignores the entry after it */
	__u32 policy_id;            /* joins to policy_decisions in ClickHouse */
	__u8  action[4];            /* per traffic class: ANY, TCP_SYN, UDP, ICMP */
	__u16 flags;                /* SAMPLE_ALL, COUNT_ONLY, ... */
	__u8  reason;               /* enum, for drop accounting */
	__u8  _pad[5];
	struct xs_gcra pkt[4];      /* per-class packet-rate limiters */
	struct xs_gcra byte_any;    /* bytes/s limiter for class ANY (increment = len) */
	__u8  reserved[16];
};
```

* **HASH, ikke LRU:** kun control plane indsætter; en LRU ville stille evicte en
  aktiv mitigering under pres. Policy-motoren holder et budget under `max_entries`
  og eskalerer til CIDR-/service-niveau-mitigering i stedet for at løbe over.
* **Preallokeret** (standard): deterministisk opslags-latency, ingen allokering
  ved update.
* **IPv6 nøglet efter /64:** et IPv6-slutsite får mindst et /64, så en
  /128-blokering omgås trivielt ved at rotere adresser. Finere eller grovere
  IPv6-blokke går gennem LPM-mappet.
* **Udløb håndhævet i XDP** (`now >= expires_ns` → entry ignoreret), så TTL'er
  holder selv hvis agenten er død. Agenten sletter udløbne entries i et 1 s-GC-sweep
  for at frigøre kapacitet. `bpf_ktime_get_ns()` kaldes kun når en entry blev fundet.

### 7-9. Destinations-services

En *service* er et beskyttet destinations-præfiks (en host /32 eller et subnet) med
sine egne tærskler og baselines. Destinationer kendes på forhånd og indsættes kun
af control plane, så trafik kan ikke udtømme disse maps.

```c
struct xs_service_cfg {         /* 128 bytes, ARRAY */
	__u32 flags;                /* PROTECT_ACTIVE, KNOWN_GOOD_ONLY, DROP_FRAGMENTS, ... */
	__u32 state;                /* NORMAL / SUSPECT / UNDER_ATTACK (attack state) */
	__u32 budget_pps[4];        /* ANY, TCP_SYN, UDP, ICMP: per-CPU share */
	__u32 burst[4];
	__u32 reserved[18];
};

struct xs_service_state {       /* 128 bytes, PERCPU_ARRAY */
	struct xs_counter total;    /* exact per-service pkts/bytes */
	__u64 syn, synack, rst, udp, icmp, frag, malformed, dropped;
	struct { __u64 tokens_x1024; __u64 last_ns; } tb[4]; /* per-CPU token buckets */
};
```

Budgetter er pr. CPU (`budget / n_rx_queues`): aggregeret trafik fra mange kilder
spredes jævnt af RSS, så per-CPU-buckets approksimerer én delt bucket tæt uden
delte skrivninger. Dette holder kun for mange-kilde-aggregater; per-source-grænser
bruger delt GCRA-state (5–6).

### 10. Per-source heavy-hitter-tabel

```c
struct xs_src_stats {           /* 64 bytes, per CPU */
	__u64 packets, bytes;
	__u32 syn, udp, icmp, rst, fin, bad, dropped, _pad;
	__u64 dport_bits;           /* bit (dport * 0x9E3779B1 >> 26): linear-counting sketch */
	__u64 last_ns;
};
```

LRU_PERCPU_HASH fordi key-rummet er angriber-kontrolleret (afgrænset, evictende) og
en enkelt tung kilde spredes af RSS på tværs af mange køer; per-CPU-values undgår
cache-linje-ping-pong mellem de CPU'er. Omkostning er hukommelse × CPU'er, derfor
den beskedne standardstørrelse (32 k IPv4, 8 k IPv6 → ~80 MiB ved 32 CPU'er).

**Probabilistisk optagelse.** En opslags-miss indsætter kun kilden hvis
`(bpf_get_prandom_u32() & hh_admit_mask) == 0` (standard 1/1024). En kilde der
sender N pakker optages efter ~1024 pakker i gennemsnit, mens en random-spoofed
flood (én pakke pr. adresse) skaber højst pps/1024 inserts pr. sekund (≤ 14,5 k/s
ved 64-byte line rate) i stedet for 14,88 M/s. Ægte heavy hitters røres konstant og
når aldrig LRU-halen. Undertællingen (~1/p pakker) korrigeres i userspace. Kilder
med en aktiv politik optages ubetinget, så drops pr. policet kilde er eksakte. En
count-min-sketch i XDP blev overvejet og afvist: d hash-beregninger pr. pakke plus
epoch-håndtering, for den samme heavy-hitter-garanti.

`BPF_F_NO_COMMON_LRU` giver hver CPU sin egen LRU og free-liste, hvilket fjerner den
globale LRU-lås der ville serialisere inserts under churn; opslag bruger stadig én
delt hash-tabel.

`dport_bits` er en 64-bit linear-counting-sketch af distinkte destinationsporte
(skelner 1, ~10 og 100+ porte: vertikale scans), opdateret med en almindelig OR og
merged på tværs af CPU'er med OR i userspace.

### 11. `xs_hll`

Fire HyperLogLog-sketches med præcision p = 12 (4096 en-byte-registre, standardfejl
1,04/√4096 ≈ 1,6%): distinkte kildeadresser, destinationsadresser,
destinationsporte og 5-tuples. Pr. pakke og sketch: én 64-bit mixing-hash (IPv4:
multiply–xorshift; IPv6 og 5-tuples: fold derefter mix), en branch-fri
leading-zero-count, ét compare-and-store ind i CPU'ens eget register. Registre er
**max-mergeable**: userspace merger CPU'er med en element-vis max.

HLL-registre kan ikke diffes som tællere, så mappet har to epochs. Hvert vindue
flipper collectoren `hll_epoch` i `xs_config`, venter en grace-periode (≥ 1 ms,
længere end enhver XDP-invokation), læser den nu-inaktive epoch fra alle CPU'er og
nulstiller den. En pakke der kapløber flippet lander i den gamle epoch og tælles i
næste vindue, en acceptabel fejl for kardinalitets-estimater.

### 12. `xs_dport_hist`

Eksakte per-destinationsport-pakke-tællinger (TCP og UDP) pr. CPU: 512 KiB pr. CPU.
Monotone u32-tællere; deltas er wrap-safe så længe læse-perioden er kortere end
2³² / (per-CPU per-port-rate), ≥ 200 s ved 20 Mpps. Læs med
`BPF_MAP_LOOKUP_BATCH` hvert 5 s. Fodrer port-entropi- og
port-koncentrations-features. En config-bit slår det fra hvis et benchmark viser at
det ekstra opslag betyder noget.

### 13. `xs_cpu_state`

Per-CPU sampling-state: en randomiseret nedtælling til næste sample (et geometrisk
skip trukket fra `bpf_get_prandom_u32()` ved hver sample, så periodisk trafik ikke
kan aliasere med sampleren), en token-bucket der lofter samples pr. CPU pr. sekund
(standard 20 k/s/CPU), og per-CPU ring-buffer-drop-regnskab.

### 14. `xs_samples` ring buffer

```c
struct xs_sample {              /* 64 bytes */
	__u64 ts_ns;
	union xs_addr saddr, daddr; /* 32 */
	__be16 sport, dport;
	__u16 pkt_len, ip_id;
	__u8  l4_proto, tcp_flags, ttl, verdict;
	__u8  rx_queue, parse_rc, reason, flags;
	__u16 tcp_window, _pad;
};
```

* **Én delt RINGBUF** (MPSC): reservation tager en spinlock, men ved den loftsatte
  sample-rate er contention ubetydelig. Per-CPU ring buffers (via `ARRAY_OF_MAPS`
  nøglet af CPU) er opgraderings-stien hvis profilering nogensinde viser
  contention.
* **Ingen per-record-wakeups:** records submittes med `BPF_RB_NO_WAKEUP` (hver
  wakeup er et irq_work); collectoren drainer med `ring_buffer__consume()` hvert
  5 ms. Over 50% fyld (`bpf_ringbuf_query(BPF_RB_AVAIL_DATA)`) tvinger XDP en
  wakeup.
* **Tab tælles, blokerer aldrig:** en fejlet reserve inkrementerer en per-CPU-tæller
  og pakken fortsætter.
* Dimensionering: 16 MiB = 262 k records ≈ 400 ms af samples ved det maksimale
  aggregerede loft (32 CPU'er × 20 k/s): collectoren må stalle 400 ms før noget tab.

## Userspace-adgangsmønstre

| Map | Læser | Periode | Metode |
|---|---|---|---|
| `xs_stats` | collector | 1 s (100 ms sub-ticks) | enkelt `lookup` (alle CPU'er) |
| `xs_service_state` | collector | 1 s | `lookup_batch` over aktive service-id'er |
| `xs_hll` | collector | 1 s | epoch-flip → lookup inaktiv → nulstil |
| `xs_src_stats_*` | collector | 5 s | `lookup_batch` over tabellen (≤ 40 k keys) |
| `xs_dport_hist` | collector | 5 s | `lookup_batch` |
| `xs_samples` | ringbuf-tråd | kontinuerligt (5 ms) | `ring_buffer__consume` |
| `xs_src_policy_*` | policy-motor | ved ændring / 1 s GC | `update_batch` / `delete_batch`; fuld læsning ved opstart |
| config, allowlists, services | agent | ved config-ændring | enkelt-updates / inner-map-swap |
