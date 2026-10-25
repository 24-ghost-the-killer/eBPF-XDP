<!-- Sprog: **Dansk** · [English](../EN/security-audit.md) -->

# Sikkerhedsaudit & produktionshærdning

Audit af xdp-sentinel-dataplanet, control plane, ML-pipelinen og den levende
deployment, til en skole-netværks-produktionsudrulning (router + managed
switches + inline-server). Baseret på en linje-for-linje-gennemgang af
`ebpf/src/` og den kørende appliance.

## Dom

- **Design: solidt.** Fast-omkostnings-XDP-pipeline, safe-default-zero-konfig,
  stærk RFC-kompatibel parsing, fail-open-for-availability /
  fail-closed-for-privilege.
- **Produktionsklar: nej — kræver hærdning.** Hullerne er operationelle, ikke
  arkitektoniske.
- **Samlet risiko som udrullet: HØJ** (committet credential, agent kører som root
  med CAP_SYS_ADMIN, SSH-password-auth, ingen stående spoofed-flood-grænse).

## Vigtigste fund (rangeret)

### P1 — Committet SNMP-community (Kritisk)
`deploy/monitoring/snmp-exporter/README.md` indeholdt det levende read-community i
klartekst (4 steder) **og i git-historikken**. Et v2c-community er et
read-password til switchen.
- **Fix:** working tree saneret til `<SWITCH_SNMP_COMMUNITY>`. **Stadig krævet:**
  rotér communityet på switchen (det er brændt — det var offentligt), og rens
  git-historikken:
  ```sh
  pip install git-filter-repo
  # sæt det GAMLE community (nu brændt) til venstre for ==>, commit IKKE denne fil:
  printf '%s==><SWITCH_SNMP_COMMUNITY>\n' "$OLD_COMMUNITY" > /tmp/scrub.txt
  git filter-repo --replace-text /tmp/scrub.txt && rm -f /tmp/scrub.txt
  git push --force-with-lease --all     # koordinér: omskriver offentlig historik
  ```
  Behold den rigtige værdi kun i den gitignorede `snmp.yml` / `.env`.

### P2 — Agenten kører som root med CAP_SYS_ADMIN (Høj)
Udrullet `sentinel-agent.service` kører som **root**, bounding set
`CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_SYS_ADMIN CAP_NET_BIND_SERVICE`
— langt bredere end trusselsmodellens "CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN, dedikeret
bruger." En agent-kompromittering = fuld boks + dataplan-kontrol.
- **Fix (trin 1, lav risiko):** reducér til `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN`.
- **Fix (trin 2, opfølgning):** `User=xs` + `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN`,
  med bpffs-pins chownet til `xs`-gruppen (pins er mode-700 root i dag, hvilket er
  grunden til at den kører som root). `KillMode=process` betyder at dataplanet
  overlever genstarten, så dette er genoprette­ligt.

### P3 — SSH-password-auth + svagt password (Høj)
`PasswordAuthentication yes`; operatør-passwordet er svagt. Inline-boks.
- **Fix:** `PasswordAuthentication no` (kun-nøgle) efter bekræftelse af
  nøgleadgang fra hver admin-maskine; rotér passwordet.

### P4 — Ingen stående spoofed-flood-mitigering (Høj, udrullet)
Per-source rate-limiting seeder-og-passer hver "ny" kilde
(`policy.h:xs_autorl_*`), så en spoofed-source-flood bliver aldrig
per-source-begrænset. Den aggregerede backstop `XS_CFG_GLOBAL_RL`
(`xdp_main.c:108`) er **slået fra** og har **ingen CLI** — kun risiko-motoren
(auto-mitigate, som er aktiveret) slår den til reaktivt.
- **Fix:** tilføj en `sentinelctl` global-RL-knap (eller konfig-felt) og sæt en
  statisk aggregeret grænse dimensioneret til uplinket; indtil da, stol på
  auto-mitigate + alarmering.

### P5 — Ingen mætnings-/collateral-alarmering (Mellem)
Ingen alarmer for NIC-RX-drops, softirq-mætning, ringbuf-sample-drops,
policy-map-fyldning eller collateral (drops af `dynamic_exempt`-kilder).
- **Fix:** Prometheus-regler (se `deploy/monitoring/prometheus/rules/`).

### P6 — CPU-isolering (Mellem)
Udrullet unit har ingen `CPUAffinity`; det dokumenterede `CPUAffinity=10-15` er
ugyldigt på denne 8-core-boks. En flood på RX-cores kan udsulte control plane.
- **Fix:** styr NIC-IRQ'er til cores 0–3; `CPUAffinity=4-7` på agenten.

### P7 — Parser-undvigelse: UNSUP-frames passerer alle L4-mitigeringer (Mellem)
`XS_PARSE_UNSUP_VLAN_DEPTH` (>2 VLAN-tags) og `XS_PARSE_UNSUP_IPV6_EXT_DEPTH`
(>6 ext-headers) returnerer `XDP_PASS` (`xdp_main.c:34-35`) og efterlader
`l4_parsed=0`, så UDP/TCP/flag/ICMP/port-drops og conntrack anvendes aldrig. En
angriber kan pakke en flood ind i ekstra VLAN-tags / ext-headers for at springe
L4-mitigeringer over.
- **Fix:** tilføj `XS_CFG_DROP_UNSUP`, eller som minimum alarmér på
  `parse_unsup_*`-rate.

### P8 — Ingen CI-secret-scanning / dependency-audit (Mellem)
Den committede hemmelighed beviser hullet.
- **Fix:** `.github/workflows/security.yml` tilføjet (gitleaks + cargo-audit/deny).

### P9 — ML ikke operationel (detektionshul, ikke en sårbarhed)
Modeller leveres trænet på `synthetic.csv` (pr_auc=1.0, dvs. trivielt separerbart);
ingen ClickHouse-sink, tomme feature-tabeller, inferens ikke koblet ind i agenten.
- **Fix:** real-data-collector kører nu (`/var/lib/xdp-sentinel/realdata/`);
  gentræn den usuperviserede anomali/baseline på ægte benign efter dages
  indsamling; lab (pktgen/TRex) til labelede angreb.

### P10 — Manuelle mitigerings-flag er ikke holdbare (Mellem)
`sentinelctl config --drop-*`-ændringer bliver **overskrevet ved runtime af
auto-mitigate-risiko-motorens baseline-restore** på de interfaces den styrer
(observeret: `vlan10`s `drop_malformed|drop_bad_tcp_flags` gik tilbage til
`check_allow|conntrack` uden agent-genstart; `vlan20`, som auto-mitigate ikke
styrer, beholdt dem). Agentens `Config`-struct (`userspace/agent/src/config.rs`,
`deny_unknown_fields`) har **intet felt til baseline-beskyttelses-flag**, så de
kan ikke sættes holdbart via konfig.
- **Effekt:** altid-tændte validitets-drops kan ikke pinnes på det
  internet-vendte interface; det er kun beskyttet *reaktivt* (auto-mitigate slår
  drops til under et angreb, og genopretter derefter observe-only-baselinen).
- **Fix (agent-feature):** tilføj valgfrie per-interface baseline-flag til
  `Interface` (f.eks. `drop_malformed`, `drop_bad_tcp_flags`), få agenten til at
  skrive dem til `xs_config` ved attach, og få auto-mitigate-*restore* til at
  målrette de flag i stedet for nul. Filer: `userspace/agent/src/config.rs` +
  attach/apply- og risiko-motor-restore-stierne. Kræver rebuild+deploy.

### P11 — Feature-collectoren kunne forgifte det benigne ML-sæt (Rettet)
Real-data-collectoren labelede hvert vindue `benign`, så et ægte angreb under
indsamling kontaminerede træningssættet (observeret: 126 vinduer fra en
hping-burst). **Rettet:** collectoren router nu anomale vinduer (høj
pps_zscore/udp_pps/pps/bad-flags/frag) til en separat `windows.csv.suspect`-fil;
de eksisterende 126 blev sat i karantæne til `windows.quarantine.csv`.

## Dataplan-gennemgang (ebpf/src/) — styrker bekræftet

- `xdp_main.c` — fast omkostning; sikker standard `XDP_PASS`; `xs_parse` er en
  `__noinline` global fn (verifier-state-firewall); `xs_opaque(rc)` besejrer en
  clang-21 bounds-check-sletning.
- `parsers.h` — hver læsning afgrænset mod `data_end`; IHL/totlen/plen/UDP-len
  maskeret+valideret; VLAN-dybde ≤2, IPv6-ext ≤6 via scalar-offset+mask; RFC 1858
  tiny-fragment, RFC 6946 atomic fragments, LAND, bad-flags. `SEC("xdp")` (ikke
  `.frags`) ⇒ ingen multi-buffer-trunkerings-undvigelse.
- `policy.h` — blok-tabel er HASH ikke LRU (angriber kan ikke udskifte en levende
  blok); IPv6 nøglet på /64; in-dataplan TTL-udløb (CLOCK_MONOTONIC); ukendt
  handling fejler åbent.
- `rate_limit.h` — GCRA korrekt; CAS prøvet igen én gang, derefter nonconforming
  (sikkert).
- `telemetry*.h` — per-CPU-tællere; afgrænset sampling (geometrisk skip + per-CPU
  token-bucket + no-wakeup-ringbuf, fejlet reserve tælles, blokerer aldrig).

Resterende dataplan-risici: UNSUP-undvigelse (P7); LRU-eviction af
conntrack/rate-state under høj-kardinalitet-floods (hold `DROP_UNTRACKED` slået
fra undtagen under en bekræftet ACK/RST-flood); faste compile-time
map-størrelser kræver et agent-side entry-budget + expired-entry-GC.

## Skole-netværks-deployment

Topologi: Router (isoleret fra Switch 1) → Switch 1 → Mellemmands-switch →
**Server (xdp-sentinel)** → Mellemmand → Switch 2.

- **Mode:** inline bridge. Ét VLAN pr. segment, tagget på server-trunken; bridge
  dem; XDP på hver VLAN-subif. Mellemmands-switchen tvinger al
  inter-segment-trafik gennem serveren.
- **Golden check:** ingen to segmenter deler et VLAN undtagen via server-trunken,
  ellers omgår trafik stille appliancen. Verificér med switch-MAC-tabeller +
  `tcpdump -eni <trunk>` (alle VLAN-tags til stede).
- **Risici:** enkelt in-path-punkt (hold et mærket bypass-kabel); ~1 Gbps
  generic-XDP-loft; intra-segment-trafik på én switch er usynlig
  (ét-VLAN-pr-host for at lukke det); VLAN double-tagging (sæt hver trunks
  native/PVID til et dedikeret tomt VLAN, aldrig VLAN 1).
- **Management:** separat management-VLAN (ikke delt med data); switch-admin over
  HTTPS, begrænset; Grafana over VPN/tunnel; allowlist mgmt-præfikset `full` kun
  på mgmt-interfacet.
- **Fail-safe:** STP slået fra, bridge forwarder straks; agent-død ⇒ observe-only;
  hold `xs-cutover` auto-rollback armet.

## Hærdnings-tjekliste

- [ ] Rotér SNMP-community; (gjort) sanér README; rens git-historik
- [ ] Agent-caps → `CAP_BPF CAP_PERFMON CAP_NET_ADMIN`; derefter `User=xs`
- [ ] SSH kun-nøgle + rotér operatør-password
- [ ] Stående aggregeret rate-grænse (`GLOBAL_RL`) dimensioneret til uplink
- [ ] Alarmer: NIC-RX-drops, softirq, ringbuf-drops, map-fyldning, collateral
- [ ] `CPUAffinity` til gyldige cores; NIC-IRQ-styring
- [ ] Håndtér UNSUP-parser-undvigelse (drop-flag eller alarm)
- [ ] (gjort) CI-secret-scanning + dependency-audit
- [ ] Verificér konfig-writer-stringens (`deny_unknown_fields`, TTL/budget/overlap)
- [ ] Kobl real-data-gentræning; lab til labelede angreb
- [ ] Runbooks, testet rollback, bypass-øvelse; validér på target-kerne
