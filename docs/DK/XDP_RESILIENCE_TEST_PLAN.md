<!-- Sprog: **Dansk** · [English](../EN/XDP_RESILIENCE_TEST_PLAN.md) -->

# Modstandsdygtigheds-test af XDP-firewall — Omfattende penetrations-plan

**Target:** 192.168.1.193  
**Test-framework:** xdp-sentinel (integreret i /pentest/xdp_pentest.py)  
**Metodik:** Kun-lab, autoriseret netværkslags-modstandsdygtigheds-test  
**Dato:** 2026-10-23

---

## Executive Summary

Dette dokument skitserer den **aggressive netværkslags-modstandsdygtigheds-test**
af et custom eBPF/XDP-firewall-/DDoS-mitigerings-system. Test-suiten fokuserer på:

1. **XDP-parsing-bypass-forsøg** — malformede headers, ekstrem fragmentering,
   non-standard protokol-felter
2. **XDP-map-udtømning** — høj-volumen stateless trafik for at stresse
   tracking-strukturer
3. **Kerne-drop-metrics** — indsamling og analyse af XDP_DROP-verdicts og
   systemiske bypasses

---

## Test-kategorier & angrebsvektorer

### A. Layer 3 (IP)-bypass-vektorer

#### 1. Malformede IP-headers
- **Malformet IHL** (Header Length): IHL=1-4 (burde være ≥5)
  - Tester om XDP-parseren validerer header-struktur strengt
  - Bypasses: Tillader trunkerede headers → ufuldstændig parsing
  - Forventet: DROP / MALFORMED-klassifikation
  
- **Nul-længde-payload**: IP Total Length = 20 (kun header, ingen L4)
  - Tester edge-case-pakke-håndtering
  - Bypasses: Kan omgå L4-state-tracking (ingen forbindelse at etablere)
  - Forventet: DROP / MALFORMED eller PASS (afhængigt af design)
  
- **Negativ payload-længde**: Fremstillede pakker med umulige størrelser
  - Tester integer-overflow-værn
  - Bypasses: Trigger negativ buffer-adgang → kerne-crash (utestet)
  - Forventet: DROP / fejl-håndtering

#### 2. IP-fragmenterings-stress
- **Ekstrem fragment-flood**: 8-byte-fragmenter med MF- (More Fragments) flag
  - Tvinger massiv reassembly-buffer-allokering
  - Tester: XDP-map-kapacitet (vs_victim / xs_attacker-maps)
  - Forventet: Reassembly-timeout → fragmenter droppet eller grænse armet
  
- **Fragment-offset-manipulation**: Ikke-sekventielle offsets
  - Reasm-engines kan køe out-of-order, stresser hukommelse
  - Forventet: Detektion → drop_fragments-flag
  
- **Overlappende fragmenter**: Samme offset, forskellige payloads
  - RFC 815-overlap-test; trigger reassembly-engine-parsing
  - Forventet: DROP eller reassembly-fejl-håndtering

#### 3. LAND- & anomali-angreb
- **LAND**: src_ip == dst_ip
  - Forvirrer state-machines der forventer asymmetriske ruter
  - Forventet: syn_flood + land_attack-klassifikation
  
- **Broadcast**: dst_ip = 255.255.255.255 eller netværks-broadcast
  - Kan omgå enkelt-offer-fokusering; tester aggregering
  - Forventet: icmp_flood eller pass (gyldigt i nogle kontekster)

---

### B. Layer 4 (TCP/UDP)-bypass-vektorer

#### 1. TCP-dårlige-flags
- **NULL**: Alle flags = 0
  - Ingen SYN/ACK/FIN/RST; tester state-machine-robusthed
  - Forventet: DROP / bad_tcp_flags
  
- **XMAS**: FIN+PSH+URG
  - Klassisk port-scanner-undvigelse; tester flag-validering
  - Forventet: bad_tcp_flags-klassifikation
  
- **SYN+FIN**: Både state-initierende og -terminerende flags
  - Udnytter samtidig opening/closing; forvirrer TCP-stakke
  - Forventet: bad_tcp_flags eller syn_flood (afhængigt af detektions-logik)
  
- **RST+SYN**: Modstridende flags
  - Tester gensidig-eksklusivitets-validering
  - Forventet: bad_tcp_flags

#### 2. TCP-state-udtømning
- **SYN-flood (høj rate)**: 50.000+ SYN/sek med spoofede kilder
  - Fylder connection-tracking / SYN-backlog
  - Tester: xs_attacker[src]-map-kapacitet → per-source-grænser
  - Forventet: drop_syn- eller ratelimit-flag armer; recovery-tid trackes
  
- **ACK-flood**: Uopfordrede ACK'er uden forudgående SYN
  - Tester untracked-forbindelses-håndtering
  - Forventet: drop_ack / drop_untracked
  
- **RST-flood**: Uopfordrede RST'er
  - Tester forbindelses-state-validering
  - Forventet: drop_untracked eller rst_flood-klassifikation

#### 3. UDP-volumetrisk
- **Standard UDP-flood**: 1500B-pakker ved max rate
  - Baseline-DDoS-vektor; tester UDP-drop-policy
  - Forventet: udp_flood-klassifikation → drop_udp-flag
  
- **Tiny UDP-flood**: 0-byte-UDP-pakker
  - Max PPS- (pakke-rate) test; kan overstige max BPS
  - Tester: Rate-limiting på tiny-pakker (ikke byte-baseret)
  - Forventet: udp_flood med høj pps observeret
  
- **Stor UDP-flood**: 1400B+-pakker
  - Max BPS- (båndbredde) test; lavere PPS men samme trussel
  - Forventet: udp_flood + udp_strict-flag
  
- **Spoofet UDP**: Tilfældige kilde-IP'er
  - Besejrer per-source rate-limits
  - Forventet: drop_udp_strict- eller global_rl-flags

---

### C. UDP-reflektions-/amplifikations-vektorer

Virkelighedens reflektor-tjenester misbrugt til amplifikations-angreb:

| Tjeneste | Port | Response-størrelse | Amplifikation | Klassifikation |
|---------|------|---------------|----------------|----------------|
| DNS | 53 | 1400B | 28-54× | dns_amplification |
| NTP | 123 | 468B | 556× | udp_reflection |
| SNMP | 161 | 1400B | 6× | udp_reflection |
| memcached | 11211 | 1400B | 10k-50k× | udp_reflection |
| CLDAP | 389 | 1200B | 56-70× | udp_reflection |
| Chargen | 19 | 1024B | 358× | udp_reflection |
| SSDP | 1900 | 360B | 30× | udp_reflection |

**Test-metode:** Injicér UDP-pakker *fra* disse tjeneste-porte (src-port) med stor
payload, destineret til offeret. XDP-klassifikatoren detekterer respons-*shapen*
og klassificerer uanset den faktiske tjeneste.

---

### D. Layer 3 ICMP-varianter

- **Echo Request (Type 8)**: Standard ping
  - Tester icmp_flood-detektion
  - Forventet: icmp_flood-klassifikation

- **Timestamp Request (Type 13)**: Mindre almindelig; gammel netværks-diagnostik
  - Forventet: icmp_flood (volumen-baseret, ikke type-specifik)

- **Unreachable (Type 3)**: ICMP-fejl; kan omgå hvis untracked
  - Forventet: icmp_flood

- **Redirect (Type 5)**: Rute-manipulation; udnytter tillidsfulde implementeringer
  - Forventet: icmp_flood

- **TTL Exceeded (Type 11)**: Traceroute-respons
  - Forventet: icmp_flood

---

### E. IPv6-extensions & -fragmentering

IPv6 tilføjer extension-headers (ulig IPv4 som bruger IP-flags til fragmentering):

- **Hop-by-Hop (Type 0)**: Tillader per-hop-options
  - Tester: Extension-header-parsing i XDP (notorisk skrøbeligt)
  - Forventet: ipv6_ext_flood → drop_ipv6_ext-flag

- **Destination Options (Type 60)**: End-to-end-options
  - Ligner hop-by-hop
  - Forventet: ipv6_ext_flood

- **IPv6-fragmenterings-header (Type 44)**: IPv6-version af IP-fragmentering
  - Kombineret med tiny-fragmenter (8 bytes hver)
  - Tester: IPv6-reassembly-pipeline (separat fra IPv4)
  - Forventet: ipv6_frag_flood eller drop_fragments + drop_ipv6_ext

- **IPv6 UDP-flood**: UDP-trafik over IPv6
  - Tester: IPv6-UDP-klassifikation (kan afvige fra IPv4)
  - Forventet: ipv6_flood + udp_flood eller ipv6_udp_flood

- **IPv6 TCP SYN**: SYN-flood over IPv6
  - Tester: TCP-state-tracking på IPv6
  - Forventet: ipv6_flood + syn_flood eller ipv6_syn_flood

---

### F. Multi-vektor- & kompositte angreb

- **Carpet Bomb**: Samtidig SYN + UDP + ICMP + Reflection
  - Tester: Multi-threaded klassifikation og prioritering
  - Forventet: Flere typer detekteret; global rate-limit engageret

- **Temporal Ramp**: Gradvis angrebs-onset (langsom ramp)
  - Tester: Detektions-latency under gradvis eskalering
  - Forventet: Detektoren bør fange truslen før fuld rate nås

- **Spoofet undvigelse**: Alle pakker fra randomiserede kilder
  - Tester: Aggregat-niveau-detektion (per-src-grænser omgået)
  - Forventet: drop_udp_strict- eller global_rl-flags (ikke per-src)

---

## Udførelses-trin

### Forudsætninger

SSH ind i target-appliancen:
```bash
ssh root@192.168.1.193
```

### Trin 1: Pre-test-validering

```bash
# Check XDP program is loaded
bpftool prog list | grep xdp

# Check maps are pinned
ls -la /sys/fs/bpf/xdp-sentinel/vlan10/

# Check metrics endpoint
curl http://127.0.0.1:9464/metrics | head -20

# Verify victim IP in config
cat /etc/xdp-sentinel/config.toml | grep victim
```

### Trin 2: Kør baseline-tests (kun-monitor)

Disse **må IKKE trigge** detektion:

```bash
cd /path/to/eBPF\ XDP
python3 pentest/xdp_pentest.py --coverage
python3 pentest/xdp_pentest.py --selftest
```

### Trin 3: Udfør angrebsvektor-suiten

Fuld 48-test-suite (inkluderer alle bypass, stress, reflection, IPv6):

```bash
sudo python3 pentest/xdp_pentest.py --run
```

Enkelt kategori (f.eks. reflektions-angreb):

```bash
sudo python3 pentest/xdp_pentest.py --run --filter reflection
```

Enkelt test (f.eks. DNS-amplifikation):

```bash
sudo python3 pentest/xdp_pentest.py --run --filter refl-dns
```

Gentag-kørsler for statistisk stabilitet (flakiness-detektion):

```bash
sudo python3 pentest/xdp_pentest.py --run --repeat 3
```

Tving spoofede kilder (besejrer per-src-grænser):

```bash
sudo python3 pentest/xdp_pentest.py --run --spoofed
```

### Trin 4: Realtids-monitorering under tests

I en anden terminal:

```bash
# Watch metrics (updates every ~1s)
watch 'curl -s http://127.0.0.1:9464/metrics | grep xs_'

# Watch kernel logs for drops
tail -f /var/log/kern.log | grep -E "DROP|xdp|sentinel"

# Monitor CPU & memory
top -d 1
```

### Trin 5: Rapport & analyse

```bash
# Automatic report generation (after --run)
cat pentest/results/latest.md

# Compare two runs for regressions
python3 pentest/xdp_pentest.py --compare results/run-A.json results/run-B.json

# JSON raw data (for custom analysis)
cat pentest/results/latest.json | jq '.aggregate'
```

---

## Forventede resultater & succeskriterier

### Detektions-ydelse

- **Precision**: ≥95% (ingen falske positiver på benign trafik)
- **Recall**: ≥98% (fanger alle ondsindede vektorer)
- **F1-score**: ≥0.96
- **Falsk-positiv-rate**: <1%

### Klassifikations-nøjagtighed

Hver angrebsvektor bør trigge den korrekte `xs_detection_info{type}`:
- Bypass-forsøg → malformed_flood
- TCP-floods → syn_flood / ack_flood / rst_flood / fin_flood
- UDP → udp_flood / udp_reflection / dns_amplification
- ICMP → icmp_flood
- Fragmenter → frag_flood
- IPv6-extensions → ipv6_ext_flood

### Mitigerings-respons

Forventede flags bør **nyligt arme** (ikke allerede tændt ved baseline):
- TCP-angreb → drop_syn / drop_ack / drop_untracked / ratelimit
- UDP → drop_udp / drop_udp_strict
- ICMP → drop_icmp
- Fragmenter → drop_fragments
- IPv6-ext → drop_ipv6_ext

### Latencies

- **Detektion**: <5 sekunder fra angrebsstart
- **Klassifikation**: <6 sekunder
- **Mitigering**: <6 sekunder (flags nyligt armet)
- **Recovery**: <30 sekunder (trussel vender tilbage til 0, flags lifter)

### System-effekt

- **Load average**: <0.5 stigning under angreb
- **Hukommelse**: Stabil (ingen OOM eller memory leaks)
- **Pakketab**: Kun tilsigtede drops (ingen collateral legitime drops)

---

## Kendte bypass-kandidater & edge-cases

Disse er **sikkerhedskritiske at teste** men kan afdække
implementerings-problemer:

1. **Fragmenterings-reassembly-udtømning**
   - At sende 10.000+ fragmenter samtidigt
   - XDP kan time-oute ufuldstændige reassemblies → hukommelse vokser uafgrænset
   - Forventet: Timeout-håndtering + drop_fragments-flag
   - Bypass-risiko: Hvis ingen grænse, memory-DoS mulig

2. **TCP-state-machine-edge-cases**
   - SYN+FIN, RST+SYN, ACK med seq=0
   - XDP validerer måske ikke alle RFC 793-constraints
   - Forventet: bad_tcp_flags-klassifikation
   - Bypass-risiko: Hvis accepteret, kan etablere ugyldige forbindelser

3. **IPv6-extension-header-chaining**
   - Flere extension-headers i sekvens
   - Kerne-parsing kan være ufuldstændig (eBPF-begrænsninger)
   - Forventet: drop_ipv6_ext-flag
   - Bypass-risiko: Komplekse kæder bliver måske ikke fuldt parset

4. **Map-udtømning via spoofede kilder**
   - 100.000+ unikke kilde-IP'er i SYN-flood
   - xs_attacker[src]-map har fast størrelse (typisk 64k entries)
   - Forventet: Per-source-grænser løber over → global_rl aktiveres
   - Bypass-risiko: Hvis mappet er fuldt, kan nye kilder passere igennem

5. **Reflektions-fejlklassifikation**
   - Tjeneste-port-heuristikker kan fejlklassificere
   - En stor-payload-UDP fra port 1234 læses som "dns_amplification"
   - Forventet: Konservativ klassifikation
   - Bypass-risiko: Custom-amplifikatorer på non-standard-porte kan omgå

---

## Opfangede metrics

### Per-test

| Metrik | Betydning |
|--------|---------|
| `peak_threat` | Højeste trussel-score observeret (0-100) |
| `peak_pps` | Pakker-pr-sekund-throughput observeret |
| `detected` | Boolean: trussel ≥ 2 (angrebs-tærskel) |
| `seen_types` | Liste af `xs_detection_info{type}`-labels |
| `armed_flags` | Liste af nyligt-armede risiko-flag |
| `detection_latency` | Tid fra angrebsstart til trussel ≥ 2 |
| `classification_latency` | Tid til første detektions-type |
| `mitigation_latency` | Tid til første risiko-flag (f.eks. drop_udp) |
| `recovery_time` | Tid fra sidste angrebspakke til trussel=0 + flags lifter |
| `drop_delta` | Pakker droppet (xs_verdict_packets_total{verdict="drop"}) |
| `pass_delta` | Pakker passeret (xs_verdict_packets_total{verdict="pass"}) |

### Aggregat

| Metrik | Betydning |
|--------|---------|
| `TP` | True Positives (angreb detekteret & korrekt) |
| `FN` | False Negatives (angreb misset) |
| `FP` | False Positives (benign fejlagtigt flagget) |
| `TN` | True Negatives (benign korrekt tilladt) |
| `precision` | TP / (TP + FP) — konfidens i detektioner |
| `recall` | TP / (TP + FN) — fuldstændighed af detektion |
| `F1` | 2×P×R / (P+R) — harmonisk middel |
| `FPR` | FP / (FP + TN) — falsk-alarm-rate |

---

## Regressions-detektion

Efter hver kørsel, sammenlign mod baseline for at fange regressioner:

```bash
python3 pentest/xdp_pentest.py --compare baseline.json latest.json
```

Dette identificerer:
- Tests der **bestod før men fejler nu** (regression)
- Tests der **fejlede før men består nu** (fix)

---

## Afhjælpning & hærdning

Hvis bypasses findes:

1. **Malformede headers**: Tilføj strenge BPF-bounds-checks på IHL, Total Length
2. **Fragmentering**: Implementér timeout for ufuldstændige reassemblies; begræns max udestående fragmenter
3. **TCP-flags**: Tilføj RFC 793-validering (gensidig eksklusivitet, sekvens-constraints)
4. **IPv6-extensions**: Implementér fuld extension-header-chain-parsing (kompleks i eBPF)
5. **Map-udtømning**: Monitorér map-brug; implementér LRU-eviction eller hash-kollisions-håndtering
6. **Spoofing-undvigelse**: Overgang fra per-source til aggregat-rate-limiting (gjort via global_rl-flag)

---

## Referencer

- **xdp-sentinel README**: pentest/README.md (dette projekt)
- **eBPF XDP-arkitektur**: docs/architecture.md
- **Policy-motor**: docs/policy-engine.md
- **Trusselsmodel**: docs/threat-model.md
- **RFC 791 (IPv4)**, **RFC 2463 (ICMPv4)**, **RFC 3986 (IPv6)**
- **NIST SP 800-83 (Threat Modeling)**
