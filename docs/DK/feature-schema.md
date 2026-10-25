<!-- Sprog: **Dansk** · [English](../EN/feature-schema.md) -->

# I. Feature-schema

Dette dokument er den normative definition af hver feature control plane
beregner. I Fase 6 materialiseres det som `ml/feature_schema/v1.yaml`; SHA-256 af
den kanonicaliserede YAML er **schema-hashen** båret af hver feature-batch, hver
ClickHouse-række og hvert model-artefakt. En model fodres kun nogensinde med
vektorer hvis schema-hash matcher den, den blev trænet på.

## Konventioner

* **Vindue:** 1 s tumbling-vinduer justeret til den monotone klokke
  (`window_start` gemt i wall-clock-UTC). Per-source-tabeller læses hvert 5 s, så
  per-source-features bruger 5 s-vinduer.
* **Sub-vindue:** collectoren læser de (single-lookup) globale og
  service-tællere hvert 100 ms, hvilket giver 10 sub-samples pr. vindue til
  burstiness og periodicitet.
* **Scopes:** `global` (pr. interface), `service` (pr. beskyttet destination;
  [bpf-maps.md](bpf-maps.md#7-9-destination-services)), `source` (pr. optaget
  heavy hitter; IPv4 /32 eller IPv6 /64), `l7` (valgfrit, fra
  reverse-proxy-logs).
* **Proveniens:**
  * `C` eksakte per-CPU-tællere (XDP),
  * `H` HyperLogLog (XDP-registre, userspace-estimat, ~1,6% fejl),
  * `P` eksakt per-port-histogram (XDP),
  * `S` samplede headers (ring buffer, 1-af-N, loftsat): estimater,
  * `D` afledt i userspace fra andre features eller historik.
  `S`-features bærer en ledsagende `sample_coverage` (brugte samples / pakker i
  vinduet); modeller modtager den som input og risiko-motoren diskonterer
  konfidens når den er lav.
* **Rates** er pr. sekund over den *målte* vindue-varighed. **Ratios** bruger
  `x / (y + 1)` for at forblive endelige. **Entropier** er Shannon-entropi i bits
  normaliseret med `log2(k)` for k observerede symboler (0..1).
* **Manglende** (f.eks. ingen TCP i vinduet): `NaN`, aldrig 0; træ-modeller
  håndterer manglende værdier nativt og 0 er en meningsfuld værdi.

## Globale og service-features

### Trafikvolumen

| Feature | Prov | Definition |
|---|---|---|
| `packets` | C | pakker i vinduet |
| `bytes` | C | bytes i vinduet (L2-frame-længde, ingen FCS) |
| `pps` | C | `packets / dt` |
| `bps` | C | `8 · bytes / dt` |
| `drop_pps` | C | pakker droppet af en mitigering / dt |
| `pps_baseline_ratio` | D | `pps / baseline_pps(scope, hour_of_week)`; baseline = rullende median af samme hour-of-week over de seneste 4 uger |

### TCP

| Feature | Prov | Definition |
|---|---|---|
| `tcp_syn_rate` | C | SYN uden ACK pr. s |
| `tcp_synack_rate` | C | SYN+ACK pr. s |
| `tcp_ack_rate` | C | ren ACK (ingen SYN/FIN/RST) pr. s |
| `tcp_rst_rate` | C | RST pr. s |
| `tcp_fin_rate` | C | FIN pr. s |
| `tcp_syn_ack_ratio` | D | `syn / (ack + 1)`; SYN-flood-signatur: mange SYN'er, få handshake-fuldførende ACK'er |
| `tcp_syn_share` | D | `syn / (tcp + 1)` |
| `tcp_bad_flags_rate` | C | NULL/XMAS/SYN+FIN/... pr. s |

### UDP, ICMP, fragmenter

| Feature | Prov | Definition |
|---|---|---|
| `udp_pps`, `udp_bps` | C | |
| `udp_dport_top1_share` | P | andel af UDP-pakker til den mest-ramte destinationsport (destinationskoncentration) |
| `udp_sport_top1_share` | S | andel af UDP-pakker fra den mest almindelige kildeport (53, 123, 1900, 11211, 389… = reflektion) |
| `udp_len_mismatch_rate` | C | |
| `icmp_pps`, `icmp_share` | C | ICMP + ICMPv6 |
| `frag_rate`, `frag_share` | C | første + senere fragmenter |

### Adresser

| Feature | Prov | Definition |
|---|---|---|
| `unique_src` | H | distinkte kildeadresser |
| `unique_dst` | H | distinkte destinationsadresser |
| `new_src` | H+D | `|HLL(t) ∪ HLL(t-1..t-10)| − |HLL(t-1..t-10)|`: kilder ikke set i de forrige 10 s (HLL-union er et eksakt register-max) |
| `src_entropy` | S | normaliseret entropi af kildeadresser i samples |
| `dst_entropy` | S | samme for destinationer |
| `top1_src_share`, `top10_src_share` | C (heavy hitters) | andel af scope-pakker fra top 1 / top 10 kilder |
| `src_prefix24_diversity` | S | distinkte /24- (v4) eller /48- (v6) præfikser pr. distinkt kilde i samples: ~1 for tilfældig spoofing, ≪ 1 for botnets klyngede i providers |
| `src_ttl_stddev` | S | std-dev af TTL/hop limit; spoofede floods fra én generator viser usandsynlig uniformitet eller tilfældighed |

### Porte

| Feature | Prov | Definition |
|---|---|---|
| `unique_dport` | H | distinkte destinationsporte |
| `unique_sport` | S | distinkte kildeporte i samples |
| `dport_entropy` | P | normaliseret entropi af det eksakte destinationsport-histogram |
| `sport_entropy` | S | |

### Pakkestørrelser

| Feature | Prov | Definition |
|---|---|---|
| `mean_pkt_size` | C | `bytes / packets` |
| `pkt_size_stddev` | S | |
| `pkt_size_p05`, `pkt_size_p50`, `pkt_size_p95` | S | |
| `pkt_size_mode_share` | S | andel af den mest almindelige eksakte størrelse (generatorer gentager én størrelse) |

### Flows og forbindelser

| Feature | Prov | Definition |
|---|---|---|
| `unique_flows` | H | distinkte 5-tuples |
| `new_flow_rate` | H+D | nye 5-tuples pr. s (HLL-union-metode, som `new_src`) |
| `flows_per_src` | D | `unique_flows / unique_src` |
| `connection_rate` | C | = `tcp_syn_rate` (forbindelsesforsøg observerbare på L3/L4) |
| `handshake_completion` | D | `tcp_ack_rate / (tcp_syn_rate + 1)` over 5 s; kun meningsfuldt hvor retur-trafik er symmetrisk |
| `flow_duration_p50`, `flow_duration_p95` | S | fra userspace-rekonstruktion af samplede flows; skæv mod lange/tunge flows, så brugt som en relativ feature |

### Temporal

| Feature | Prov | Definition |
|---|---|---|
| `pps_accel` | D | `(pps_t − pps_{t−1}) / dt` |
| `pps_zscore` | D | `(pps − median) / (1.4826 · MAD)` mod samme hour-of-week-baseline (robust) |
| `burstiness_cv` | C (sub-vinduer) | variationskoefficient af de 10 × 100 ms pakke-tællinger |
| `fano_factor` | C (sub-vinduer) | varians / middel af sub-vindue-tællinger (≫ 1 bursty, ≈ 1 Poisson, ≪ 1 paced) |
| `periodicity_strength`, `periodicity_period` | D | maksimal autokorrelation (lags 200 ms – 30 s) af de seneste 60 s af 100 ms-tællinger, og dens lag |

### Protokol-distribution og validitet

`share_tcp`, `share_udp`, `share_icmp`, `share_other`, `share_ipv6` (C);
`malformed_rate` (C, sum af `parse_err_*`), `unsupported_rate` (C).

### Coordinated / distribuerede angrebs-features (`service`-scope)

Inputtene til [ml.md, distributed attack detection](ml.md#distributed-attack-detection-14):
mange kilder, ét mål, samme adfærd, samme tid.

| Feature | Prov | Definition |
|---|---|---|
| `sig_top1_share` | S | andel af servicens samplede pakker der bærer den mest almindelige *adfærds-signatur* `(proto, dport, tcp_flags, størrelses-bucket (32 B), ttl-bucket (8))` |
| `sig_top1_sources` | S | distinkte kilder der bidrager til den signatur |
| `onset_sync` | D | fraktion af dette vindues aktive kilder først set (userspace) inden for de seneste 10 s |
| `known_good_share` | S+D | andel af pakker fra servicens *known-good*-kilder (fuldførte handshakes / normal trafik i de 24 t før anomalien; Bloom-filter i userspace) |
| `src_cv_pps` | C (heavy hitters) | variationskoefficient af per-source pps blandt aktive heavy hitters; botnets under én controller er usædvanligt uniforme |

## Per-source-features (`source`-scope, 5 s-vinduer)

For optagede heavy hitters (afgrænset antal) og kilder under undersøgelse
(`SAMPLE`-handlingen hæver deres sampling-rate).

| Feature | Prov | Definition |
|---|---|---|
| `src_pps`, `src_bps` | C | per-CPU-summer, korrigeret for optagelse (+1/p) |
| `src_syn_rate`, `src_udp_pps`, `src_icmp_pps` | C | |
| `src_syn_share` | D | SYN / TCP |
| `src_distinct_dports` | C | linear-counting-estimat fra OR-merged 64-bit `dport_bits` (mætter ved ~250 = "mange") |
| `src_distinct_dsts` | S | |
| `src_bad_share` | C | malformede + bad-flag-pakker / pakker |
| `src_pkt_size_mode_share` | S | gentagne pakkestørrelser |
| `src_iat_cv` | S | variationskoefficient af kildens samplede inter-arrival-tider (≥ 20 samples; meget lav = maskine-paced) |
| `src_ttl_distinct` | S | distinkte TTL-værdier; > 2 fra én adresse antyder spoofing |
| `src_active_windows` | D | sammenhængende aktive vinduer (persistens) |
| `src_age_s` | D | tid siden først set (userspace-historik, loftsat ved 24 t) |
| `src_prefix_cohort` | D | aktive heavy hitters i samme /24 (/48) |
| `src_share_of_service` | D | denne kildes andel af dens top-destination-service |

## Valgfrie L7-features (`l7`-scope)

Kun når en reverse proxy (nginx/Envoy/HAProxy) sender access-logs til ClickHouse;
beregnet af agenten fra ClickHouse, aldrig i XDP: `req_rate`, `method_entropy`,
`path_entropy`, `path_top1_share`, `status_4xx_share`, `status_5xx_share`,
`ua_distinct`, `ua_entropy`, `tls_fp_distinct` (JA4/JA3 hvis eksporteret),
`req_iat_cv`, `session_duration_p50`, pr. klientadresse og pr. service.

## Hvad beregnes hvor

Se [architecture.md F.5](architecture.md#f5-what-is-computed-in-xdp-vs-userspace).
XDP vedligeholder tællere, registre, histogrammer og samples (fast omkostning,
merge-bare); alt med division, logaritmer, sortering, historik eller joins er
userspace.

## Flow-nøgle

### Definition

Userspace-flow-records nøgles af:

```rust
#[repr(C)]
struct FlowKey {            // 40 bytes, hashed with ahash
    src: [u8; 16],          // IPv4 as ::ffff:a.b.c.d
    dst: [u8; 16],
    sport: u16,             // 0 for port-less protocols / non-first fragments
    dport: u16,
    proto: u8,
    dir: u8,                // 0 = ingress on outside iface, 1 = egress / inside
    ifindex: u16,           // compressed interface id, not the raw ifindex
}
```

VLAN-id er **ikke** i standard-nøglen: med RX-VLAN-offload er det ikke pålideligt
synligt, og i de fleste deployments er adresser unikke på tværs af VLAN'er.
Deployments med overlappende adresserum pr. VLAN sætter
`flow_key.include_vlan = true`, hvilket erstatter `ifindex` med `(ifindex, vid)`.

### Hvorfor flows ikke trackes i XDP

En per-5-tuple-tabel i XDP gør per-pakke-omkostning og hukommelse til en funktion
af angriber-adfærd: en random-spoofed SYN-flood skaber et nyt "flow" pr. pakke
(14,88 M/s ved 64-byte line rate). En LRU af enhver praktisk størrelse ville blive
udskiftet hvert par millisekunder og beholde intet, mens den betaler en insert
(allokering + mulig eviction, ~100–200 ns) pr. pakke, mere end hele
per-pakke-budgettet. I stedet:

| Behov | Mekanisme | Omkostning |
|---|---|---|
| antal flows, new-flow-rate | per-CPU HLL over 5-tuple-hashen | ~5–10 ns/pakke, 4 KiB/CPU |
| per-source-adfærd | LRU_PERCPU_HASH med probabilistisk optagelse | ét opslag pr. pakke; inserts ≤ pps/1024 |
| flow-varigheder, per-flow-størrelser, IAT | userspace-rekonstruktion fra samples | afgrænset af sampling-loftet |

### Userspace-hukommelse og CPU

`hashbrown`-map `FlowKey → FlowRec` (FlowRec 88 B: first/last seen, samplede
pakker/bytes, flag-union, størrelse min/max, IAT-akkumulator), ~150 B/entry med
overhead. Input er afgrænset af sample-loftet (standard 20 k samples/s/CPU × 8
RX-CPU'er = 160 k/s); kapacitet 2 M flows (~300 MiB) med eviction efter
`last_seen` fra et timer-wheel. Én insert/update pr. sample ≈ 160 k ops/s, et godt
stykke under 5% af én core.
