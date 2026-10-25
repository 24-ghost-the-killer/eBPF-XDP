<!-- Sprog: **Dansk** · [English](../EN/system-setup-and-vlan-security.md) -->

# xdp-sentinel — opsætning af hele systemet & VLAN-interceptions-analyse

Dette dokument gør tre ting:

1. **Inventar** — hvad systemet faktisk er: den managed switch, Linux-appliancen,
   routeren, og hver forbindelse mellem dem (med resultaterne af et live
   reachability-tjek).
2. **Opsætning** — hvordan man bygger og rejser *hele* systemet end-to-end:
   XDP-dataplanet, switchen, agenterne, ML-træningen og monitorering.
3. **Interception / VLAN-jumping** — hvordan en angriber kunne komme i midten af
   dette netværk, med hvert angreb mappet mod *netop denne* topologi og det
   konkrete forsvar mod det.

Det er et supplement til [architecture.md](architecture.md),
[inline-vlan-deployment.md](inline-vlan-deployment.md),
[deployment.md](deployment.md), [ml.md](ml.md) og
[threat-model.md](threat-model.md); det erstatter dem ikke, det binder dem sammen
for denne installation.

---

## 1. System-inventar

### 1.1 Fysisk topologi

```
                         ZyXEL GS1900-24HP  (managed L2 switch, mgmt 192.168.1.50)
                       ┌───────────────────────────────────────────────────────┐
  internet ── router ──┤ P1  VLAN10 untagged, PVID 10                            │
  (192.168.1.1)        │                                                         │
                       │ P3  VLAN10 + VLAN20 tagged  ─── enp1s0 ── xdp-sentinel  │
                       │     (the trunk)                         appliance       │
  LAN / machines ──────┤ P2  VLAN20 untagged, PVID 20          (br0 192.168.1.193)│
  (Proxmox etc.)       └───────────────────────────────────────────────────────┘
```

Appliancen har **én** fysisk NIC (`enp1s0`). Switchen leverer begge VLAN'er
taggede på det ene kabel (en "router-on-a-stick" / **VLAN-hairpin**). Inde i
appliancen:

```
enp1s0 ──┬── vlan10  (802.1Q id 10, router / internet side)   ──┐
         └── vlan20  (802.1Q id 20, machines / LAN side)      ──┤
                                                                ├── br0 (bridge)
                                   XDP attached to vlan10 and vlan20
                                   br0 holds the management IP 192.168.1.193/24
```

Fordi P1 (router) og P2 (maskiner) **deler ingen VLAN**, kan switchen fysisk ikke
forwarde et router↔maskine-frame på egen hånd. Den eneste port i begge VLAN'er er
P3, trunken til appliancen. Så hver pakke mellem internettet og maskinerne tvinges
op ad trunken, gennem `vlan10`/`vlan20`, over bridgen — **forbi XDP** — og ned
igen. Appliancen er uundgåelig *ved design*.

### 1.2 Adresser og roller (denne installation)

| Ting | Værdi | Noter |
|---|---|---|
| Appliance management-IP (`br0`) | `192.168.1.193/24`, gw `192.168.1.1` | SSH + Grafana lever her |
| Switch management-IP | `192.168.1.50`, **management-VLAN 10** | web-UI |
| Router / gateway | `192.168.1.1` | VLAN 10 (upstream)-siden |
| Grafana | `http://192.168.1.193:3001` | dashboards |
| Agent-metrics (Prometheus) | `127.0.0.1:9464` | kun localhost; `/metrics /healthz /readyz` |
| VLAN 10 | router / internet (upstream) | |
| VLAN 20 | maskiner der skal beskyttes (LAN) | |
| Trunk-NIC | `enp1s0` (Realtek r8169) | kun generic-mode XDP |

### 1.3 Software-planes

- **Dataplan (kerne):** `ebpf/build/xdp_main.bpf.o`, én XDP-program-instans pr.
  RX-kø/CPU, tilkoblet `vlan10` og `vlan20`. Parser L2–L4, tjekker allowlisten,
  anvender per-source-policy + rate-limits + per-service-budgetter, skriver
  tællere/sketches/samples til pinnede BPF maps, returnerer `PASS`/`DROP`.
  **Venter aldrig på userspace.**
- **Control plane (userspace, Rust):**
  - `sentinel-agent` — læser maps, aggregerer flows, bygger feature-vinduer,
    kører risiko/policy-motoren og skriver politikker *med TTL'er* tilbage i maps.
    Eksponerer Prometheus-metrics. Kører som bruger `xs` med kun
    `CAP_BPF CAP_PERFMON CAP_NET_ADMIN`.
  - `sentinel-inference` — loader ML-modellerne (ONNX/portabel JSON) i en separat,
    sandboxet, netværks-løs proces; agenten kalder den over en Unix-socket med en
    deadline.
  - `sentinelctl` / `xdp`-wrapperen — operatør-CLI (attach/detach, status, stats,
    block, allow, ratelimit, flags, reset).
- **ML (offline):** `ml/` Python-pipeline — syntetisk datasæt-generator og tre
  trænere (anomaly / classifier / bot) der udsender portable JSON-modeller som
  Rust-scorerne loader byte-identisk.
- **Observability:** Prometheus scraper agenten; Grafana renderer; ClickHouse
  (valgfrit, `deploy/clickhouse/`) gemmer telemetri til træning.

### 1.4 Live reachability-tjek (udført read-only fra dev-maskinen over VPN'en)

| Target | Resultat |
|---|---|
| `192.168.1.193` (appliance `br0`) | **oppe** — ICMP-svar |
| `192.168.1.50` (switch) | **oppe** — ICMP-svar |
| `192.168.1.1` (router) | intet ICMP-svar (forventet: VLAN‑10-siden / ping filtreret) |
| SSH til appliance | opnåelig men **kræver en nøgle der ikke er på denne maskine** |

"Ser XDP trafik, forwarder bridgen, er allowlisten loadet"-tjekkene kan kun
besvares fra on-box; kør kommandoerne i §2.11 over SSH.

---

## 2. Opsætning — at rejse hele systemet

Rækkefølge betyder noget. Byg og stage alt på appliancen **mens den stadig er en
flad boks på LAN'et**, og omkonfigurér kun switchen (som splitter netværket) som
sidste trin, med auto-rollback-cutover armet.

### 2.1 Byggeafhængigheder (appliance, Debian 12/13 eller Ubuntu 24.04)

```sh
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                        pkg-config bpftool make
# Rust ≥ 1.85
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rustfmt
```

Kernen skal være ≥ 6.1 med `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_SYSCALL=y`,
`CONFIG_BPF_JIT=y`, og bpffs monteret på `/sys/fs/bpf` (systemd-standard).

### 2.2 Byg og test

```sh
make all                                   # BPF object + sentinelctl + agent + inference
make test                                  # unprivileged: parser + Rust tests
sudo make test-bpf                         # verifier + in-kernel corpus
sudo make test-integration                 # veth end-to-end, native XDP
```

Alt skal bestå **på target-kernen** før du går videre.

### 2.3 Installér binaries, objekt og modeller

```sh
sudo install -D -m0755 target/release/sentinelctl        /usr/local/bin/sentinelctl
sudo install -D -m0755 target/release/sentinel-agent     /usr/local/bin/sentinel-agent
sudo install -D -m0755 target/release/sentinel-inference /usr/local/bin/sentinel-inference
sudo install -D -m0644 ebpf/build/xdp_main.bpf.o         /usr/lib/xdp-sentinel/xdp_main.bpf.o
for m in anomaly bot classifier; do
  sudo install -D -m0644 -t /usr/lib/xdp-sentinel/models/$m/v1 \
       ml/models/$m/v1/model.json ml/models/$m/v1/manifest.json
done
```

### 2.4 Switchen (ZyXEL GS1900-24HP)

Web-UI på `http://192.168.1.50`, `Configuration → VLAN → VLAN`. Samme logik gælder
enhver 802.1Q managed switch.

1. **Opret VLAN'er** — `VLAN`-fane → Add → VLAN List `10,20`.
2. **Port-medlemskab** (`VLAN Port`-fane, pr. VLAN):

   | VLAN | P1 (router) | P2 (LAN) | P3 (trunk) | alle andre porte |
   |---|---|---|---|---|
   | **10** | Untagged | Excluded | **Tagged** | Excluded |
   | **20** | Excluded | Untagged | **Tagged** | Excluded |

3. **PVID** (`Port`-fane → Edit): P1 → `10`, P2 → `20`, P3 → behold standard
   (dens trafik er tagget). *(Se §3.2 — dette PVID-valg er også en
   sikkerhedsbeslutning; overvej at sætte P3's PVID til et ubrugt, tomt VLAN.)*
4. **Management-VLAN** — `Configuration → System → IP` → Management VLAN = `10` så
   switchens admin-side forbliver opnåelig fra admin-siden efter splittet.
5. **Gem ikke endnu** — indtil du trykker Save, reverterer en switch-power-cycle
   alt. Det er dit sikkerhedsnet mens du konfigurerer.

**Golden check'et:** efter konfiguration må P1 og P2 dele **ingen** VLAN; den
eneste port i både 10 og 20 er P3. Hvis P1 og P2 nogensinde deler et VLAN, omgår
trafik appliancen helt (se §3.8).

### 2.5 Appliance-netværk — VLAN-bridgen (netplan)

Stage, anvend ikke live endnu. Skabelon:
[../configs/netplan-vlan-bridge.yaml](../../configs/netplan-vlan-bridge.yaml) →
`/etc/netplan/01-xdp-vlan-bridge.yaml`:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0: {}                         # trunk NIC, no IP of its own
  vlans:
    vlan10: { id: 10, link: enp1s0 }   # router side (from the internet)
    vlan20: { id: 20, link: enp1s0 }   # machines side (from the LAN)
  bridges:
    br0:
      interfaces: [vlan10, vlan20]
      addresses: [192.168.1.193/24]
      routes: [{to: default, via: 192.168.1.1}]
      nameservers: {addresses: [192.168.1.1]}
      parameters: { stp: false, forward-delay: 0 }
```

Validér før noget går live: `sudo netplan generate --root-dir <tmp>`.

### 2.6 Agent — tilkobl XDP til begge VLAN'er

Skabelon [../configs/agent-vlan.toml](../../configs/agent-vlan.toml) →
`/etc/xdp-sentinel/config.toml`:

```toml
metrics_addr = "127.0.0.1:9464"
pin_root = "/sys/fs/bpf/xdp-sentinel"
bpf_obj  = "/usr/lib/xdp-sentinel/xdp_main.bpf.o"

[[interface]]
name = "vlan10"   # from the internet
mode = "generic"
attach = true

[[interface]]
name = "vlan20"   # from the machines
mode = "generic"
attach = true
```

`generic`-mode fordi VLAN-subinterfaces og r8169-NIC'en ikke har native XDP. Fint
bag en SOHO-router (routeren er flaskehalsen, ~1 Gbps), ikke et line-rate-10G-udsagn.

### 2.7 Operatør-allowlist (lås aldrig dig selv ude)

Skabelon [../configs/allowlist.conf](../../configs/allowlist.conf) →
`/etc/xdp-sentinel/allowlist.conf`, genanvendt ved hver boot af
`xs-baseline.service`. LAN-præfikset er `dynamic-exempt` så auto-mitigering aldrig
kan rate-limitte eller blokere admin-netværket:

```
192.168.1.0/24          dynamic-exempt   # LAN (admin SSH, Grafana)
fe80::/10               dynamic-exempt   # IPv6 link-local
2001:6c8:ff15:2633::/64 dynamic-exempt   # LAN IPv6 prefix (update if ISP changes)
```

`dynamic-exempt` = aldrig auto-blokeret/begrænset men stadig validitets-tjekket.
`full` = omgår hvert tjek — brug sparsomt (se §3.7).

### 2.8 Aktivér tjenester

```sh
sudo systemctl enable --now xs-baseline.service       # applies allowlist on boot
sudo systemctl enable      xs-cutover-auto.timer       # arms the safe cutover (§2.9)
sudo systemctl enable --now sentinel-agent             # (after cutover, see §2.9)
```

Valgfri **auto-mitigering**: drop-in'et `sentinel-agent.service.d/auto-mitigate.conf`
sætter `XS_AUTO_MITIGATE=1`, hvilket lader risiko-motoren stramme rate-limits /
drop-flag under et detekteret angreb og genoprette baselinen bagefter. Fjern
drop-in'et for at vende tilbage til kun-observér. Dataplanets standard er
**kun-observér**; validitets-dropping er opt-in:
`sentinelctl config -i vlan10 --drop-malformed on`.

### 2.9 Cutover'et (det farlige trin) — gjort sikkert

En én-NIC-hairpin har et bootstrap-problem: appliancen kan kun bridge når switchen
sender den taggede frames, men i det øjeblik switchen splitter netværket er den
stadig-flade appliance kortvarigt afskåret. To mekanismer håndterer det:

- **`scripts/xs-cutover`** vipper mellem plain- og bridge-mode, kører detached
  (overlever en droppet SSH-session), **pinger gatewayen efter skift og ruller
  automatisk tilbage hvis uopnåelig**. Manuelt: `sudo xs-cutover` /
  `sudo xs-cutover --rollback`.
- **`scripts/xs-cutover --auto`** på `xs-cutover-auto.timer` tjekker hvert 30 s og
  skifter til bridge-mode i det øjeblik den ser indkommende VLAN-taggede frames på
  trunken *og* mister den flade gateway — dvs. i det øjeblik du afslutter
  switch-konfigurationen. Den lægger derefter `/etc/xdp-sentinel/.cutover-done` og
  slår sin timer fra.

**Sekvens:** konfigurér switch-port **2 og 3 først** (forstyrrer ikke en
management-session ankommende på P1), derefter **port 1 sidst** — det fuldfører
hairpinnet og trigger auto-cutover'et. Se det med `journalctl -t xs-cutover -f`.
**Gem** derefter switch-konfigurationen.

### 2.10 ML-træning

ML er en control-plane-*rådgiver* — den rører aldrig pakke-stien. De leverede
modeller er trænet på **syntetiske** data; den statistiske baseline-detektor er hvad
der faktisk driver mitigering indtil du gentræner på capturet ægte trafik.

```sh
# 1. generate / regenerate a labelled synthetic dataset (feature-vector windows)
python3 ml/dataset/generate.py -o ml/dataset/synthetic.csv -n 500

# 2. train each model → portable JSON + manifest (schema_hash pinned)
python3 ml/train/train_anomaly.py    --data ml/dataset/synthetic.csv --version v1 --trees 128 --sample 256
python3 ml/train/train_classifier.py --data ml/dataset/synthetic.csv --version v1
python3 ml/train/train_bot.py        --version v1

# 3. the trainers write ml/models/<name>/v1/{model.json,manifest.json}
#    install them (same as §2.3) and restart the agent to pick them up
```

Exit-kriterier indbygget i trænerne: anomaly slår en pps-tærskel-baseline på
PR-AUC; classifier ≥ 0,95 per-type recall; bot ≥ 0,9 precision ved driftspunktet.
For produktionsgrad-detektion, erstat det syntetiske sæt med capturede
real-trafik-feature-vinduer (se [ml.md](ml.md) §23) — kritisk, **udeluk vinduer
under aktiv mitigering** fra træning så modellen ikke kan forgiftes til at lære
angreb som normalt (trussel #10).

### 2.11 Monitorering

```sh
# agent metrics (localhost): scrape via Prometheus in deploy/monitoring/
cd deploy/monitoring && cp .env.example .env && docker compose up -d   # Prometheus + Grafana
# optional telemetry store for training data
cd deploy/clickhouse && docker compose up -d && \
  docker compose exec clickhouse clickhouse-client --multiquery < schema.sql
```

Grafana på `http://192.168.1.193:3001` (dashboards provisioneret fra
`deploy/monitoring/grafana/`). Prometheus-alarm-regler i
`deploy/monitoring/prometheus/rules/`.

### 2.12 Verifikation (kør on-box)

```sh
# On the appliance
ip -br addr show br0                        # br0 UP with 192.168.1.193
bridge link show | grep -E 'vlan10|vlan20'  # both forwarding
ping -c1 1.1.1.1                            # appliance has internet via the router
sudo sentinelctl status -i vlan10           # XDP attached
sudo sentinelctl status -i vlan20           # XDP attached
sudo sentinelctl stats  -i vlan10 --interval 1   # rx climbs with internet traffic
sudo sentinelctl stats  -i vlan20 --interval 1   # rx climbs with LAN traffic
sudo sentinelctl list   -i vlan10           # allowlist present
sudo tcpdump -eni enp1s0 -c 20              # should show BOTH 'vlan 10' and 'vlan 20' frames

# From an admin box on VLAN 10
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.50/            # switch admin
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.193:3001/login # Grafana
```

At en LAN-maskine på VLAN 20 når internettet beviser at hairpinnet forwarder
end-to-end.

### 2.13 Nød-off-switch / rollback

- Detach XDP: `sudo sentinelctl detach -i vlan10` (og `vlan20`), eller
  `ip link set dev vlan10 xdpgeneric off`.
- Tilbage til et fladt netværk: `sudo xs-cutover --rollback`, **og** flyt
  router-kablet fra switch P1 direkte til LAN-switchen (eller revertér
  switch-VLAN'erne). Hurtigste nødudgang: tag appliancen ud og patch routeren til
  LAN-switchen direkte. **Appliancen er in-path — hvis den er nede, mister LAN'et
  internet. Hold et bypass-kabel.**

---

## 3. Interception & VLAN-jumping — hvordan en angriber kommer i midten

> Denne sektion er en defensiv trusselsmodel af **dit eget** netværk. Hvert punkt
> siger hvordan angrebet virker, om *denne* topologi er eksponeret, og det
> konkrete fix. Målet er at gøre appliancen til et uundgåeligt chokepoint og holde
> enhver fra at træde udenom den eller gøre switchen til en hub.

Hele sikkerhedsværdien af dette design hviler på én antagelse:
**router↔maskine-trafik har ingen sti undtagen gennem appliancens bridge.** Hvert
angreb nedenfor er i sidste ende et forsøg på at bryde den antagelse — at nå et
andet VLAN direkte, at få switchen til at lække frames, eller at sidde mellem to
hosts inde i et VLAN appliancen ikke kan se.

### 3.1 VLAN-hopping ved double tagging (802.1Q double-encapsulation) — det klassiske "VLAN jump"

**Hvordan det virker.** Angriberen, der sidder på en *access*-port, sender et
frame med **to** stakkede 802.1Q-tags: et ydre tag der matcher trunkens
**native (untagged / PVID) VLAN**, og et indre tag der navngiver **target**-VLAN'et.
Den første switch ser at det ydre tag er lig native-VLAN'et, stripper det (native
VLAN-frames forlader en trunk untagged), og forwarder framet på trunken. Det
*næste* hop læser så det indre tag og leverer framet ind i target-VLAN'et — envejs,
men nok til at injicere ind i et VLAN du aldrig var medlem af.

**Eksponering her.** Dette er *det* angreb navnet "VLAN jumping" refererer til, og
denne topologi har ingrediensen den kræver: en trunk (P3) der bærer taggede
VLAN'er. De afbødende fakta:

- Double tagging virker kun når trunkens **native VLAN er lig med et VLAN en
  angribers access-port kan injicere untagged ind i**. På P3 er både 10 og 20
  **taggede**, og P3's PVID er efterladt som standard (VLAN 1), som ikke bruges til
  data. En angriber på P2 (access VLAN 20, PVID 20) udsender untaggede frames;
  switchen tagger dem 20 ved ingress. For at double-tagge skal angriberens
  injicerede *ydre* tag overleve til trunken som native VLAN — men trunkens native
  VLAN (1) er tomt og ingen access-port bruger det.
- Det er strengt envejs (ingen retursti), så det er en injektions-/spoofing-primitiv,
  ikke en fuld session-MITM, på en L2-hairpin som denne.

**Fix / hærd.**
- **Sæt trunkens native VLAN til et dedikeret, tomt, ubrugt VLAN** (f.eks. 999) der
  ikke eksisterer på nogen access-port, og lad det ikke være VLAN 1. På GS1900, gør
  P3's PVID til et ellers-ubrugt VLAN og sørg for at det VLAN er `Excluded` overalt
  ellers. Et ydre tag angriberen kan producere matcher så aldrig trunkens
  native VLAN, så first-hop-strippet sker aldrig.
- Hold **hvert data-VLAN tagget på trunken** (allerede tilfældet) og gør aldrig en
  access-port til medlem af VLAN 1.
- XDP-backstop: begge retninger krydser allerede `vlan10`/`vlan20` gennem bridgen,
  så et injiceret frame der *faktisk* når et VLAN passerer stadig dataplanets
  validitets- og policy-tjek — men stol ikke på det til VLAN-segmentering; fix det
  ved switchen.

### 3.2 Switch-spoofing / rogue trunk-negotiation (DTP)

**Hvordan det virker.** På Cisco-stil-switches kan en port efterladt i
dynamic/auto-trunk-mode tvinges til at danne en trunk af en angriber der taler DTP,
hvilket øjeblikkeligt giver dem hvert VLAN.

**Eksponering her.** GS1900-24HP er en smart/web-managed switch med **ingen DTP** —
trunking er statisk per-port VLAN-medlemskab, ikke forhandlet. Så klassisk
DTP-switch-spoofing gælder ikke. Restrisikoen er *fejlkonfiguration*: en access-port
ved et uheld gjort til tagget medlem af begge VLAN'er bliver en utilsigtet trunk.

**Fix.** Audit `VLAN Port`-medlemskab: kun **P3** må være tagget i både 10 og 20.
Alt andet: hver access-port i præcis ét VLAN, untagged, med en matchende PVID; alle
andre porte `Excluded` fra 10 og 20. "Golden check'et" (§2.4) er præcis denne audit.

### 3.3 At plugge ind i recovery-porten (nødudgangen er også et indgangspunkt)

**Hvordan det virker.** [inline-vlan-deployment.md](inline-vlan-deployment.md)
beholder "en ubrugt switch-port på management-VLAN'et" til recovery. Enhver med
fysisk adgang kan plugge ind i den port og lande direkte på **management-VLAN 10**,
og nå switchens admin-UI (`192.168.1.50`) og appliancens `br0` (`192.168.1.193`) —
*ved siden af* hairpinnet, ikke gennem det.

**Eksponering her.** Reel og ofte overset. Management-VLAN'et er kronjuvel-VLAN'et
(det styrer switchen og appliancen).

**Fix.**
- Hold ubrugte porte **administrativt lukket / `Excluded` fra alle VLAN'er** indtil
  nødvendigt; aktivér recovery-porten kun når du fysisk er ved den.
- Sæt switch- + appliance-management bag stærk auth og, ideelt, et dedikeret
  management-VLAN der *ikke* er et data-VLAN (i dag deler management VLAN 10 med
  router/internet-siden — se §3.6).
- Fysisk sikkerhed af switch-skabet er en del af kontrollen.

### 3.4 CAM-tabel- (MAC-) flooding → switch degraderer til en hub

**Hvordan det virker.** Angriberen flooder switchen med tusinder af falske
kilde-MAC'er. Når MAC/CAM-tabellen løber over, **fejler mange switches åbent**:
unknown-unicast-frames floodes ud af alle porte i VLAN'et, så angriberen på samme
VLAN sniffer nu trafik beregnet til andre.

**Eksponering her.** Kun intra-VLAN — det ville lade en angriber på VLAN 20 sniffe
anden VLAN‑20-trafik, eller på VLAN 10 sniffe router-segmentet. Det krydser
**ikke** VLAN'er. Appliancen ser inter-VLAN-trafik men ikke intra-VLAN-flooding på
en downstream LAN-switch.

**Fix.**
- Aktivér GS1900's **port security / MAC-limit** pr. access-port (begræns antallet
  af lærte MAC'er; luk eller alarmér ved overtrædelse).
- Aktivér **storm control** (broadcast/multicast/unknown-unicast rate-limits).
- Segmentér yderligere: færre hosts pr. VLAN begrænser blast-radiussen.

### 3.5 ARP-spoofing / intra-VLAN-MITM (og appliancens blinde vinkel)

**Hvordan det virker.** Inden for ét VLAN sender en angriber forfalskede ARP- (eller
IPv6-ND-) svar for at forgifte naboers tabeller og indsætte sig selv mellem to
hosts (eller mellem en host og dens gateway) — en fuld bidirektionel MITM, intet
VLAN-hop nødvendigt.

**Eksponering her.** Dette er det største praktiske hul. Designet ser eksplicit
**ikke trafik mellem to maskiner der deler P2-LAN-switchen** — LAN-switchen
forwarder det lokalt og det når aldrig trunken. Så en angriber der *allerede er en
maskine på VLAN 20* kan ARP-spoofe sine VLAN‑20-naboer og MITM'e dem, og appliancen
ser det aldrig. Appliancen inspicerer kun trafik der krydser mellem VLAN 20 og VLAN
10 (dvs. til/fra internettet).

**Fix.**
- **Dynamic ARP Inspection (DAI)** + **DHCP snooping**, og **IPv6 RA-Guard / ND
  inspection**, på downstream LAN-switchen hvis den understøtter dem (GS1900 har
  DHCP snooping og nogle L2-beskyttelser; tjek feature-sættet).
- For ægte per-maskine-inspektion ville du have brug for **ét VLAN pr. maskine**
  (private VLANs / port-isolering) så selv intra-LAN-trafik hairpinner gennem
  appliancen — dette er den dokumenterede sti til at lukke den
  intra-LAN-blinde-vinkel, til prisen af flere VLAN'er.
- Statiske ARP-entries for kritiske hosts; monitorér for ARP-anomalier.

### 3.6 Management-plane på et data-VLAN

**Hvordan det virker.** Management-VLAN 10 er **også** det router/internet-vendte
VLAN. Alt der når VLAN 10 (en kompromitteret router, en double-tag-injektion per
§3.1, recovery-porten per §3.3) er nabo til switchens admin-UI og appliancens
management-IP. Hvis switchens admin-UI er plain **HTTP**, krydser credentials og
sessioner wiren i klartekst.

**Eksponering her.** Switch-UI'et er opnåeligt på `http://192.168.1.50` og
appliancen på `192.168.1.193` på VLAN 10. Trusselsmodel-punkt #15 ("management
plane") anbefaler en *separat* management-NIC/netværk; denne én-NIC-hairpin
kollapser management ned på et data-VLAN af nødvendighed.

**Fix.**
- Foretræk **HTTPS** til switch-UI'et hvis firmwaren understøtter det; ellers
  begræns admin-UI'et til en enkelt admin-host og stærke credentials, og aldrig fra
  internet-siden.
- Hvis en anden NIC eller et dedikeret management-VLAN (adskilt fra både 10 og 20)
  er muligt, flyt management derhen og allowlist det `full` **kun på det interface**
  (trusselsmodel #15).
- Hold `metrics_addr` på `127.0.0.1` (allerede tilfældet) og nå Grafana/Prometheus
  over SSH-tunnel eller VPN'en, ikke en eksponeret port.

### 3.7 Allowlist- / tillids-misbrug

**Hvordan det virker.** En angriber der kan spoofe en kilde inde i en allowlistet
CIDR, eller som kompromitterer en host i en, arver den tillid. En `full`
allowlist-entry **omgår hvert tjek** i dataplanet — spoof den kilde og du er
usynlig for mitigering.

**Eksponering her.** `192.168.1.0/24` og IPv6-præfikserne er `dynamic-exempt`,
hvilket er det sikre valg: aldrig auto-blokeret, men **stadig validitets-tjekket**.
Ingen `full`-entries leveres som standard.

**Fix.** Hold LAN/admin-præfikser `dynamic-exempt`, ikke `full`. Reservér `full`
til et dedikeret management-interface kun. Fordi appliancen er en L2-bridge, husk
også at kilde-IP'er fra internet-siden er trivielt spoofbare — designet læner sig op
ad destinations-/service-centrisk mitigering og korte TTL'er for netop dette
(trusselsmodel #12).

### 3.8 At omgå chokepointet helt (det reelle worst case)

**Hvordan det virker.** Glem smarte tags — hvis en sti lader router↔maskine-trafik
undgå trunken, inspicerer appliancen intet. Måder det sker: P1 og P2 ved et uheld
deler et VLAN; nogen patcher routeren direkte ind i LAN-switchen; et andet uplink;
Wi-Fi der bridger de to segmenter.

**Eksponering her.** Udelukkende en kablings-/konfig-risiko, og den enkeltvigtigste
— den gør stille appliancen til en no-op.

**Fix.**
- **Golden check'et** efter hver switch-ændring: P1 og P2 deler ingen VLAN; P3 er
  den eneste port i begge.
- Verificér med switchens MAC-tabel at hver enhed er på sin forventede port, og med
  `tcpdump -eni enp1s0` på appliancen at du ser **begge** `vlan 10`- og
  `vlan 20`-frames (§2.12).
- Kontrollér kabling fysisk; ingen sekundære router↔LAN-links eller bridgende AP'er.

### 3.9 At angribe / udsulte selve appliancen

**Hvordan det virker.** Appliancen er et bevidst enkelt punkt i den kablede sti. En
DoS der mætter den ~1 Gbps generic-XDP-sti, udtømmer CPU, eller crasher agenten
kunne blinde detektion eller (hvis den kunne tvinge drops) afskære LAN'et.

**Eksponering her.** Afgrænset ved design: dataplanet udfører **fast per-pakke-arbejde**,
politikker bærer TTL'er håndhævet *inde i* XDP, og **en knækket control plane
stopper med at mitigere i stedet for at begynde at droppe** (fail-open for
tilgængelighed). Generic XDP + r8169 lofter throughput ved ~1 Gbps — fint bag en
SOHO-router, men det er loftet. Telemetri-flooding er afgrænset af per-CPU
sample-token-buckets (trusselsmodel #6).

**Fix.** Hold bypass-kablet (§2.13); hold øje med Prometheus-alarmerne for NIC-drops
og CPU-headroom; aktivér ikke `--drop-*`-validitets-regler uden at forstå trafikken;
hold auto-mitigeringens collateral circuit breaker tændt.

### 3.10 Opsummering — eksponering ved et overblik

| Angreb | Krydser VLAN'er? | Eksponeret her? | Primært fix |
|---|---|---|---|
| Double tagging (§3.1) | ja (1-vejs) | lav, hvis native VLAN hærdet | dedikeret tomt native VLAN på P3 |
| DTP-switch-spoofing (§3.2) | ja | **nej** (GS1900 har ingen DTP) | statisk medlemskabs-audit |
| Recovery-port-adgang (§3.3) | lander på mgmt | ja (fysisk) | luk ubrugte porte; lås skabet |
| CAM-flooding (§3.4) | nej (intra-VLAN) | ja, begrænset | port security + storm control |
| ARP/ND-MITM (§3.5) | nej (intra-VLAN) | **ja — blind vinkel** | DAI/ND-guard; VLAN-pr-host |
| Mgmt på data-VLAN (§3.6) | — | ja | HTTPS/separat mgmt-VLAN |
| Allowlist/spoof-misbrug (§3.7) | — | lav (kun dynamic-exempt) | ingen `full` på data-ifaces |
| Chokepoint-bypass (§3.8) | — | konfig-risiko, **kritisk** | golden check + tcpdump |
| Appliance-DoS (§3.9) | — | afgrænset ved design | bypass-kabel; alarmer |

### 3.11 Hærdnings-tjekliste

- [ ] Trunk P3 native/PVID-VLAN = et dedikeret **tomt** VLAN, excluded overalt ellers.
- [ ] Golden check består: P1 og P2 deler ingen VLAN; P3 er den eneste port i både 10 og 20.
- [ ] Ubrugte switch-porte `Excluded` / lukket; recovery-port aktiveret kun når i brug.
- [ ] Port security (MAC-limit) + storm control på access-porte.
- [ ] DHCP snooping + Dynamic ARP Inspection + IPv6 RA-Guard på LAN-switchen.
- [ ] Switch-admin over HTTPS, stærke creds, begrænset til én admin-host; aldrig fra internet-siden.
- [ ] Management opnåelig kun via VPN/SSH-tunnel; `metrics_addr` bliver på localhost.
- [ ] Allowlist bruger `dynamic-exempt` (ikke `full`) for LAN/admin-præfikser.
- [ ] `tcpdump -eni enp1s0` viser både VLAN 10- og VLAN 20-frames (trafik hairpinner reelt).
- [ ] Gentræn ML på capturet ægte trafik, ekskludér mitigerings-vinduer.
- [ ] Bypass-kabel staget; Prometheus-alarmer for NIC-drops / CPU-headroom koblet op.
- [ ] Overvej VLAN-pr-maskine (private VLANs) for at lukke intra-LAN-MITM-blinde-vinklen.
```
