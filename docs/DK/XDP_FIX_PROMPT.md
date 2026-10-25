<!-- Sprog: **Dansk** · [English](../EN/XDP_FIX_PROMPT.md) -->

# Prompt til fix af IPv6-fragmenterings-klassifikation i XDP-firewall

## Problemformulering

Din eBPF/XDP-firewall har **ÉT identificeret problem** (lav-alvorlighed, kosmetisk):

**IPv6-fragmenterings-angrebspakker detekteres og droppes korrekt, men labeles som `malformed_flood` i stedet for det forventede `ipv6_frag_flood`.**

### Nuværende adfærd
- **Angrebs-detektion**: ✅ VIRKER (pakker detekteret)
- **Angrebs-mitigering**: ✅ VIRKER (pakker droppet)
- **Risiko-flag**: ✅ VIRKER (global_rl, ratelimit armet)
- **Klassifikations-label**: ❌ FORKERT (siger malformed_flood, burde sige ipv6_frag_flood)

### Effekt
- Sikkerhed: **NUL** — pakker droppes stadig
- Brugeroplevelse: **NUL** — netværket virker korrekt
- Drift: **MINDRE** — alarm/telemetri viser forkert angrebstype
- Alvorlighed: **LAV** — kosmetisk klassifikations-nøjagtigheds-problem

---

## Root cause-analyse

IPv6-fragmenterings-detektions-logikken i din eBPF-klassifikator behandler
IPv6-fragment-headers på samme måde som andre malformede pakker, i stedet for at
skelne dem som en specifik `ipv6_frag_flood`-angrebstype.

### Hvad man skal finde

Kig i din eBPF-kildekode (sandsynligvis `ebpf/classify.rs` eller `ebpf/detect.rs`)
efter:

1. **Detektions-logikken der klassificerer IPv6-pakker**
   - Funktion/sektion der håndterer IPv6-next-header-felter
   - Kode der tjekker for IPv6-extension-headers
   - Specifikt: kode der behandler IPv6-fragment-header (next_header == 44)

2. **Den nuværende klassifikations-beslutning**
   - Hvor koden beslutter at udsende `malformed_flood`-label
   - Kig efter hardkodet streng eller enum-værdi som `AttackType::MalformedFlood`

3. **Den forventede klassifikations-konstant**
   - Kig efter `AttackType::Ipv6FragFlood` eller lignende enum-variant
   - Tjek om den allerede er defineret men aldrig brugt

### Eksempel på kode-mønstre at søge efter

```rust
// IPv6 next-header values
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;

// Detection code (pseudo-code, find the actual implementation)
fn classify_ipv6(...) {
    // ... code that reads IPv6 header ...
    let next_header = ipv6_header.next_header;
    
    if next_header == 44 {  // Fragment header
        // CURRENT: Returns AttackType::MalformedFlood
        // NEEDED:  Should return AttackType::Ipv6FragFlood
    }
}
```

---

## Løsningstilgang

### Trin 1: Lokalisér IPv6-klassifikations-koden

**Søg efter:**
```
grep -r "ipv6_frag\|IPv6.*frag\|next_header.*44" ebpf/*.rs
grep -r "ipv6_ext_flood\|ipv6_flood" ebpf/*.rs
grep -r "MalformedFlood" ebpf/*.rs | grep -i ipv6
```

**Forventede lokationer:**
- `ebpf/classify.rs` — pakke-klassifikations-logik
- `ebpf/detect.rs` — trussel-detektion
- `ebpf/headers.rs` — pakke-header-parsing
- Kig efter funktionsnavne som: `classify_ipv6()`, `detect_ipv6()`, `parse_ipv6_ext()`

### Trin 2: Forstå den nuværende logik

Find sektionen der ser nogenlunde sådan ud:

```rust
fn classify_packet(pkt: &PacketData) -> AttackType {
    // ... IP version check ...
    if ip_version == 6 {  // IPv6
        // ... parse IPv6 header ...
        let next_header = get_ipv6_next_header(pkt);
        
        match next_header {
            44 => {  // Fragment header
                // PROBLEM: This returns MalformedFlood
                return AttackType::MalformedFlood;  // ❌ WRONG
            }
            0 | 43 | 60 => {  // Hop-by-Hop, Routing, Destination Options
                return AttackType::Ipv6ExtFlood;  // ✅ Correct for these
            }
            _ => return AttackType::Ipv6Flood;  // Other IPv6
        }
    }
}
```

### Trin 3: Identificér tilgængelige angrebstyper

Søg efter enum-definitionen:

```rust
enum AttackType {
    SynFlood,
    AckFlood,
    UdpFlood,
    IcmpFlood,
    MalformedFlood,
    Ipv6ExtFlood,
    Ipv6Flood,
    IcmpV6Flood,
    // ... check if Ipv6FragFlood or similar exists ...
}
```

**Nøglespørgsmål:**
1. Eksisterer `Ipv6FragFlood` allerede som en enum-variant?
   - Hvis JA → brug den direkte
   - Hvis NEJ → tilføj den til enummen

2. Forventer pentest-frameworket `ipv6_frag_flood`-label?
   - Tjek `pentest/xdp_pentest.py` linje 170-173 for forventet klassifikation
   - Kig efter `KNOWN_TYPES`-liste

### Trin 4: Lav fixet

#### Mulighed A: Hvis `Ipv6FragFlood`-enum-varianten eksisterer

Ændr:
```rust
// BEFORE:
44 => return AttackType::MalformedFlood;

// AFTER:
44 => return AttackType::Ipv6FragFlood;
```

#### Mulighed B: Hvis angrebstypen ikke eksisterer

**Trin 1:** Tilføj enum-varianten:
```rust
enum AttackType {
    // ... existing variants ...
    Ipv6Flood,
    IcmpV6Flood,
    Ipv6FragFlood,  // ← ADD THIS
}
```

**Trin 2:** Implementér streng-repræsentationen:
```rust
impl AttackType {
    fn as_str(&self) -> &'static str {
        match self {
            // ... existing cases ...
            AttackType::Ipv6Flood => "ipv6_flood",
            AttackType::IcmpV6Flood => "icmpv6_flood",
            AttackType::Ipv6FragFlood => "ipv6_frag_flood",  // ← ADD THIS
        }
    }
}
```

**Trin 3:** Opdatér klassifikations-logikken:
```rust
44 => return AttackType::Ipv6FragFlood;
```

#### Mulighed C: Hvis flere IPv6-headers kræver fixes

Tjek pentest-frameworkets forventninger:
```bash
grep -A 5 "ipv6.*frag" pentest/xdp_pentest.py
grep "expected_classification" pentest/xdp_pentest.py | grep ipv6
```

Forventet fra test-frameworket (linje 550):
```python
("ipv6-frag","ipv6/ipv6_frag_flood",...,
 expected_classification=["ipv6_ext_flood","ipv6_flood","frag_flood"],
```

Dette betyder at testen accepterer flere labels (IPv6-extension, generisk IPv6
eller fragment). At tilføje `ipv6_frag_flood` ville gøre det mere specifikt.

### Trin 5: Genbyg og test

```bash
# 1. Rebuild the eBPF program
make clean
make build

# 2. Reload the XDP program
sudo ip link set dev vlan10 xdp off  # Detach old
sudo ip link set dev vlan10 xdp obj ebpf/xdp.o sec xdp  # Load new

# 3. Verify metrics endpoint still works
curl http://127.0.0.1:9464/metrics | head -20

# 4. Run the single failing test
cd pentest
sudo python3 xdp_pentest.py --run --filter ipv6-frag

# 5. Check result
grep "ipv6-frag" results/latest.md
```

### Trin 6: Regressions-test

```bash
# Run full 48-test suite to ensure no regressions
sudo python3 xdp_pentest.py --run

# Compare to baseline
python3 xdp_pentest.py --compare <baseline.json> results/latest.json
```

---

## Implementerings-tjekliste

- [ ] **Søg**: Lokalisér IPv6-klassifikations-kode i ebpf/*.rs
- [ ] **Forstå**: Spor flowet fra IPv6-pakke → AttackType-enum
- [ ] **Identificér**: Bekræft om Ipv6FragFlood-varianten eksisterer
- [ ] **Tilføj**: Hvis manglende, tilføj enum-variant og streng-repræsentation
- [ ] **Fix**: Ændr IPv6-fragment-header- (44) håndtering fra MalformedFlood → Ipv6FragFlood
- [ ] **Genbyg**: `make build` og reload XDP-programmet
- [ ] **Test enkelt**: Kør `xdp_pentest.py --run --filter ipv6-frag`
- [ ] **Test alt**: Kør fuld `xdp_pentest.py --run`-suite
- [ ] **Verificér**: Tjek at IPv6-fragmenterings-testen nu viser korrekt label
- [ ] **Commit**: `git add ebpf/ && git commit -m "Fix IPv6 fragmentation classification label"`

---

## Kode-søge-kommandoer

Brug disse til at finde den relevante kode:

```bash
# Find IPv6 classification logic
grep -rn "ipv6\|IPv6" ebpf/*.rs | grep -i "classify\|detect\|next.header"

# Find fragment header handling (value 44)
grep -rn "44\|0x2c\|fragment" ebpf/*.rs

# Find AttackType enum
grep -rn "enum AttackType\|as_str\|to_string" ebpf/*.rs

# Find the specific malformed_flood classification
grep -rn "MalformedFlood\|malformed_flood" ebpf/*.rs

# Check what the test expects
grep -A 5 "ipv6-frag\|ipv6_frag" pentest/xdp_pentest.py
```

---

## Forventet udfald efter fix

**Før:**
```
[ipv6-frag] ipv6/ipv6_frag_flood ... FAIL (TP, det=1.1s, 
  types=malformed_flood,  # ← WRONG LABEL
  armed=global_rl,ratelimit)
```

**Efter:**
```
[ipv6-frag] ipv6/ipv6_frag_flood ... PASS (TP, det=1.1s, 
  types=ipv6_frag_flood,  # ← CORRECT LABEL
  armed=global_rl,ratelimit)
```

Fuldt test-suite-resultat:
```
==== 48/48 passed | P=1.0 R=1.0 F1=1.0 FPR=0.0 ====
```

---

## Yderligere overvejelser

### Hvis du ikke kan finde koden
eBPF-kode-strukturen kan være anderledes:
1. Tjek `ebpf/`-mappe-listing: `ls -la ebpf/`
2. Søg efter Rust-filer: `find . -name "*.rs" | grep -E "ebpf|xdp"`
3. Tjek for en anden klassifikations-tilgang (bitmap-flags vs enum)
4. Kig efter makro-baseret klassifikation i stedet for funktion

### Hvis flere klassifikations-problemer eksisterer
Kør den fulde test-suite og notér alle FAILs:
```bash
sudo python3 pentest/xdp_pentest.py --run 2>&1 | grep "FAIL\|❌"
```

For hver FAIL:
- Notér testnavnet
- Notér forventet vs faktisk klassifikation
- Følg samme fix-proces

### Hvis fixet knækker andre tests
Brug git til at reverte:
```bash
git diff ebpf/
git checkout ebpf/  # Revert changes
```

Gennemgå derefter logikken mere omhyggeligt. Sandsynlige årsager:
1. IPv6-extension-headers (0, 43, 60) bliver fejlklassificeret
2. Fragment-offset-beregning påvirker detektion
3. Flere extension-headers i sekvens ikke håndteret

---

## Filer der skal modificeres

Baseret på typisk eBPF/XDP-projekt-struktur:

**Primære filer:**
- `ebpf/classify.rs` eller `ebpf/detect.rs` — klassifikations-logik
- `ebpf/headers.rs` — pakke-header-parsing (hvis separat)

**Kan også være nødvendigt:**
- `ebpf/lib.rs` eller `ebpf/main.rs` — enum-definitioner
- `userspace/agent.rs` — metric-label-mappings (kan kræve opdatering)

**Bør IKKE være nødvendigt:**
- `pentest/xdp_pentest.py` — accepterer allerede de korrekte labels
- `docs/` — dokumentation kan opdateres efter fixet
- `Makefile` — build bør virke som det er

---

## Succeskriterier

✅ **Test består**: `ipv6-frag`-testen skifter fra FAIL til PASS  
✅ **Korrekt label**: Klassifikation viser `ipv6_frag_flood` (eller accepteret variant)  
✅ **Ingen regressioner**: Fuld 48-test-suite består stadig  
✅ **Ydelse stabil**: Detektions-/mitigerings-latencies uændrede  
✅ **Metrics korrekte**: Telemetri viser korrekt angrebstype  

---

## Spørgsmål? Brug for hjælp?

Hvis kode-strukturen er markant anderledes:
1. Del outputtet af: `ls -la ebpf/` og `grep -l "AttackType\|classify" ebpf/*.rs`
2. Del de første 50 linjer af hoved-klassifikations-funktionen
3. Notér om eBPF-koden er i C, Rust eller et andet sprog

Fix-mønstret forbliver det samme: find hvor IPv6-fragment-headeren detekteres,
skift den udsendte label fra generisk/malformed til specifik `ipv6_frag_flood`.

---

**Estimeret indsats**: 15-30 minutter (søg + modificér + test)  
**Risikoniveau**: LAV (enkelt label-ændring, ingen ændring af logik-flow)  
**Rollback**: Simpel (revert fil med git)
