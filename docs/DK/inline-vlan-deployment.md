<!-- Sprog: **Dansk** · [English](../EN/inline-vlan-deployment.md) -->

# Inline VLAN-bridge-deployment (én-NIC-hairpin)

Hvordan xdp-sentinel-appliancen blev placeret **i stien** for et netværk med en
enkelt managed switch og en én-NIC-server, så al trafik mellem maskinerne og
internettet inspiceres af XDP før den når noget andet.

Dette er `inline`-topologien fra [architecture.md](architecture.md), realiseret
som en **router-on-a-stick / VLAN-hairpin** fordi appliancen kun har én
Ethernet-port.

---

## 1. Hvad der blev bygget

```
                         ZyXEL GS1900-24HP (managed switch)
   internet router ──[ P1  VLAN10 untagged, PVID10 ]
                                                      P3  VLAN10+VLAN20 tagged ── enp1s0  xdp-sentinel
   LAN switch / machines ─[ P2  VLAN20 untagged, PVID20 ]        (trunk)          (bridges vlan10 <-> vlan20)
```

- **Routeren** (WAN/upstream-siden) sidder alene på **VLAN 10**.
- **Maskinerne der skal beskyttes** (en anden switch med Proxmox-VM'er osv.) sidder
  på **VLAN 20**.
- P1 og P2 **deler ingen VLAN**, så switchen kan ikke forwarde
  router<->maskine-trafik direkte. Den eneste port i begge VLAN'er er **P3**,
  trunken til appliancen.
- Appliancen modtager begge VLAN'er tagget på ét kabel, splitter dem i `vlan10`-
  og `vlan20`-subinterfaces og **bridger** dem (`br0`). Hver pakke der krydser
  mellem internettet og maskinerne traverserer derfor bridgen, hvor **XDP er
  tilkoblet både `vlan10` og `vlan20`** og inspicerer hver retning.

### Hvorfor hairpinnet er tvunget

En managed switch forwarder kun et frame mellem to porte hvis de deler et VLAN.
Med routeren på VLAN 10 og maskinerne på VLAN 20 har en pakke fra en maskine til
internettet ingen steder at gå på switchen undtagen op ad trunken til appliancen
(tagget VLAN 20), gennem bridgen, og ned ad trunken igen (tagget VLAN 10) til
routeren. Appliancen er fysisk uundgåelig.

### Hvad den ser og ikke ser

- **Ser:** al trafik mellem maskinerne (VLAN 20) og internettet (VLAN 10).
- **Ser ikke:** trafik mellem to maskiner der deler LAN-switchen på P2 —
  LAN-switchen forwarder det lokalt og det når aldrig trunken. At inspicere
  intra-LAN-trafik ville kræve ét VLAN pr. maskine.

### Adresser og roller (denne installation)

| Ting | Værdi |
|---|---|
| Appliance management-IP (`br0`) | `192.168.1.193/24`, gw `192.168.1.1` |
| Switch management-IP | `192.168.1.50`, **management-VLAN 10** |
| Router / gateway | `192.168.1.1` (VLAN 10-siden) |
| Grafana | `http://192.168.1.193:3001` |
| VLAN 10 | router / internet (upstream) |
| VLAN 20 | maskiner der skal beskyttes (LAN) |
| Trunk-NIC | `enp1s0` (Realtek r8169 → generic-mode XDP) |

---

## 2. Switch-konfiguration (ZyXEL GS1900-24HP)

Gjort i web-UI'et (`Configuration → VLAN → VLAN`). Samme logik gælder enhver
802.1Q managed switch; kun menuerne adskiller sig.

### 2.1 Opret VLAN'erne
`VLAN`-fanen → **Add** → VLAN List `10,20`.

### 2.2 Port-medlemskab (`VLAN Port`-fane, pr. VLAN)

| VLAN | P1 (router) | P2 (LAN) | P3 (trunk) | alle andre porte |
|---|---|---|---|---|
| **10** | Untagged | Excluded | **Tagged** | Excluded |
| **20** | Excluded | Untagged | **Tagged** | Excluded |

### 2.3 PVID (`Port`-fane → vælg port → Edit)

| Port | PVID |
|---|---|
| P1 | 10 |
| P2 | 20 |
| P3 | 1 (behold standard; dens trafik er tagget) |

### 2.4 Management-VLAN
`Configuration → System → IP` → **Management VLAN = 10** (så switchens
admin-side forbliver opnåelig fra VLAN-10- / admin-siden efter splittet).

### 2.5 Gem
Øverst til højre **Save** (skriver running config til flash). **Indtil du
gemmer, reverterer en power-cycle alt** — hvilket i sig selv er sikkerhedsnettet
mens du konfigurerer.

### Golden check'et
Efter konfiguration **må P1 og P2 ikke dele nogen VLAN**. Den eneste port i både
10 og 20 er P3. Hvis P1 og P2 deler et VLAN, omgår trafik appliancen.

---

## 3. Appliance- (server-) konfiguration

### 3.1 Base-installation
Se [deployment.md](deployment.md). Kort sagt, på Linux-boksen:

```sh
# build deps: clang, llvm, libbpf-dev, libelf-dev, zlib1g-dev, pkg-config, rustc, cargo, rustfmt
make all                       # BPF object + sentinelctl + sentinel-agent + sentinel-inference
sudo make test test-bpf test-integration   # all must pass on the target kernel
sudo install -D -m0755 target/release/sentinelctl      /usr/local/bin/sentinelctl
sudo install -D -m0755 target/release/sentinel-agent   /usr/local/bin/sentinel-agent
sudo install -D -m0755 target/release/sentinel-inference /usr/local/bin/sentinel-inference
sudo install -D -m0644 ebpf/build/xdp_main.bpf.o       /usr/lib/xdp-sentinel/xdp_main.bpf.o
# trained ML models used by the agent
for m in anomaly bot classifier; do
  sudo install -D -m0644 -t /usr/lib/xdp-sentinel/models/$m/v1 ml/models/$m/v1/model.json ml/models/$m/v1/manifest.json
done
```

### 3.2 Netværk: VLAN-bridgen (netplan)
Installeret som `/etc/netplan/01-xdp-vlan-bridge.yaml` (skabelon i
[../configs/netplan-vlan-bridge.yaml](../../configs/netplan-vlan-bridge.yaml)):

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

`br0` beholder appliancens management-IP, så SSH og Grafana forbliver på samme
adresse. STP slået fra + nul forward-delay = bridgen forwarder straks.

### 3.3 Agent: tilkobl XDP til begge VLAN'er
`/etc/xdp-sentinel/config.toml` (skabelon i
[../configs/agent-vlan.toml](../../configs/agent-vlan.toml)):

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

`generic`-mode fordi VLAN-subinterfaces (og r8169-NIC'en) ikke understøtter native
XDP. Det er fint bag en home/SOHO-router, som er flaskehalsen.

Aktivér agenten: `sudo systemctl enable --now sentinel-agent`.

### 3.4 Operatør-allowlist (lås aldrig dig selv ude)
`/etc/xdp-sentinel/allowlist.conf` ([../configs/allowlist.conf](../../configs/allowlist.conf)),
genanvendt ved hver boot af `xs-baseline.service` (script
[../scripts/xs-baseline](../../scripts/xs-baseline)). Den markerer LAN-præfikserne
`dynamic-exempt`, så auto-mitigering aldrig kan rate-limitte eller blokere
admin-netværket.

### 3.5 Auto-mitigering (valgfri)
Drop-in `sentinel-agent.service.d/auto-mitigate.conf` sætter `XS_AUTO_MITIGATE=1`,
hvilket lader risiko-motoren stramme rate-limits / drop-flag under et detekteret
angreb og genoprette baselinen bagefter. Fjern drop-in'et for at vende tilbage til
kun-observér.

---

## 4. Cutover'et (den farlige del) og hvordan det blev gjort sikkert

En én-NIC-hairpin har et bootstrap-problem: appliancen kan kun bridge når switchen
sender den taggede frames, men i det øjeblik switchen splitter netværket er
appliancen (stadig i plain/flat-mode) kortvarigt afskåret. At gøre dette fjernt kan
strande boksen.

To mekanismer håndterer det:

1. **`scripts/xs-cutover`** — vipper boksen mellem plain-mode og bridge-mode. Den
   kører detached (overlever en droppet SSH-session) og **pinger gatewayen efter
   skift; hvis uopnåelig ruller den automatisk tilbage**. Manuel brug:
   `sudo xs-cutover` / `sudo xs-cutover --rollback`.

2. **`scripts/xs-cutover --auto`** på en timer (`xs-cutover-auto.timer`) — tjekker
   hvert 30 s og skifter til bridge-mode automatisk **når den ser indkommende
   VLAN-taggede frames på trunken og mister den flade gateway**, dvs. i det øjeblik
   switchen omkonfigureres. Dette er hvad der fyrede i denne installation:

   ```
   xs-cutover: gateway lost and VLAN-tagged frames seen on enp1s0: switch reconfigured
   xs-cutover: switching enp1s0 to VLAN bridge mode
   xs-cutover: bridge mode active: XDP on vlan10 (from internet) and vlan20 (from LAN)
   ```
   Efter et succesfuldt cutover lægger den et `/etc/xdp-sentinel/.cutover-done`-flag
   og slår sin egen timer fra.

Fordi intet gemmes på switchen før det sidste trin, **reverterer en switch-power-cycle
til det flade netværk** på ethvert tidspunkt under switch-konfigurationen —
nødudgangen hvis noget går galt.

---

## 5. Reproducér fra bunden (tjekliste)

1. **Klargør appliancen i plain-mode**, opnåelig på LAN'et (statisk eller DHCP på
   `enp1s0`). Byg, installér og stage filerne (§3). Aktivér
   `xs-cutover-auto.timer` og `xs-baseline.service`. Bekræft at den stagede
   `/etc/xdp-sentinel/staged/01-xdp-vlan-bridge.yaml` validerer:
   `sudo netplan generate --root-dir <tmp>`.
2. **Kabl switchen**: router → P1, LAN-switch → P2, appliance → P3. Bekræft med
   switchens MAC-tabel at hver enhed er på den forventede port.
3. **Konfigurér switchen** (§2): opret VLAN 10/20, sæt medlemskab + PVID, sæt
   management-VLAN 10. Konfigurér port **2 og 3 først** (forstyrrer ikke en
   management-session ankommende på P1), derefter **port 1 sidst** — det fuldfører
   hairpinnet og trigger appliancens auto-cutover.
4. **Se appliancen bridge sig selv** (`journalctl -t xs-cutover -f`), eller kør
   `sudo xs-cutover` manuelt.
5. **Gem** switch-konfigurationen.
6. **Verificér** (§6).

> Rækkefølge betyder noget: flyt ikke port 1 / management-VLAN'et før port 2–3 er
> sat, og behold fysisk adgang til switchen (en ubrugt port forbliver på
> management-VLAN'et) i tilfælde af at du skal recovere.

---

## 6. Verifikation

```sh
# On the appliance
ip -br addr show br0                       # br0 UP with the management IP
bridge link show | grep -E 'vlan10|vlan20' # both in forwarding
ping -c1 1.1.1.1                           # appliance has internet via the router
sudo sentinelctl status -i vlan10          # XDP attached
sudo sentinelctl status -i vlan20          # XDP attached
sudo sentinelctl stats  -i vlan10          # rx climbs with internet traffic
sudo sentinelctl stats  -i vlan20          # rx climbs with the machines' traffic
sudo sentinelctl list   -i vlan10          # allowlist present

# From an admin box on VLAN 10
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.50/     # switch admin
curl -so /dev/null -w '%{http_code}\n' http://192.168.1.193:3001/login  # Grafana
```

En LAN-maskine på VLAN 20 bør stadig nå internettet (beviser at hairpinnet
forwarder end-to-end), og `sudo tcpdump -eni enp1s0 -c 20` bør vise `vlan 10`- og
`vlan 20`-taggede frames.

---

## 7. Drift & recovery

- **`xdp`-wrapper** (`/usr/local/bin/xdp`): `xdp status|stats|list|block|allow|
  flags|ratelimit|reset`. Den målretter `$XDP_IFACE` (sat i
  `/etc/profile.d/xdp-sentinel.sh`; brug `vlan10`, eller `XDP_IFACE=vlan20 xdp ...`).
- **Rul tilbage til et fladt netværk**: `sudo xs-cutover --rollback` på appliancen,
  **og** flyt router-kablet fra switch P1 direkte til LAN-switchen (eller revertér
  switch-VLAN'erne). Hurtigste nødudgang: tag appliancen ud og patch routeren til
  LAN-switchen direkte.
- **Hvis appliancen er nede**, mister LAN'et internet (den er in-path). Hold et
  kabel til at bypasse den.
- **Switch-admin uopnåelig** efter en VLAN-fejl: sæt en laptop i en hvilken som helst
  ubrugt switch-port (stadig på management-VLAN'et) og browse til `192.168.1.50`,
  eller brug switch-konsollen/reset.
- **XDP-off-switch**: `sudo sentinelctl detach -i vlan10` (og `vlan20`), eller
  `ip link set dev vlan10 xdpgeneric off`.

---

## 8. Begrænsninger specifikke for denne opsætning

- **~1 Gbps / generic XDP.** VLAN-subinterfaces + r8169 → generic-mode. Fint bag en
  SOHO-router; ikke et line-rate-10G-udsagn (se [performance.md](performance.md)).
- **Ingen intra-LAN-synlighed** (maskiner der deler P2-switchen).
- **ML-modeller er trænet på syntetiske data** (se [ml.md](ml.md)); den statistiske
  baseline-detektor driver mitigering. Gentræn på capturede real-trafik-features
  for produktionsgrad-detektion.
- **Single point of failure** på den kablede sti, ved design af en inline-scrubber.
