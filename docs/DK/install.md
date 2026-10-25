<!-- Sprog: **Dansk** · [English](../EN/install.md) -->

# Installation af appliancen (`scripts/setup.sh`)

`scripts/setup.sh` bygger og installerer hele systemet på en Debian/Ubuntu-boks
i én kørsel: eBPF/XDP-dataplanet, `sentinelctl` + `sentinel-agent`, automatikken
til beskyttelse og lockdown, og — valgfrit — dashboardet (med HTTPS),
Twingate-gennem-XDP-integrationen og ufw-synkroniseringen.

Det centrale trin lader dig **vælge hvilke interfaces** dataplanet skal tilkobles
(piletaste-menu) og skriver dem til agentens konfiguration
(`/etc/xdp-sentinel/config.toml`).

> Installationsprogrammet kræver **ikke** et lokalt checkout: køres det ikke fra
> ét, kloner det selv repoet fra GitHub.

## Krav

- Debian 12/13 eller Ubuntu 24.04, Linux ≥ 6.1 med BTF
  (`/sys/kernel/btf/vmlinux`) og bpffs på `/sys/fs/bpf` (systemd monterer det som
  standard).
- `sudo`/root. Scriptet kører sig selv igen under sudo efter behov.
- Byggeafhængigheder installeres automatisk (clang, llvm, libbpf-dev, bpftool,
  make, Rust og Node til dashboardet); spring over med `--skip-deps`.

## Installation

### Fra et checkout

```sh
sudo bash scripts/setup.sh
```

### Fjernt, én kommando

Repoet er **privat**, så hentning kræver et GitHub-token (en fine-grained PAT med
læseadgang). Det sendes som en auth-header og skrives aldrig til disk:

```sh
T=github_pat_xxxxx
curl -fsSL -H "Authorization: Bearer $T" \
  https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh \
  | sudo GITHUB_TOKEN=$T bash
```

Gøres repoet offentligt, falder tokenet bort:

```sh
curl -fsSL https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh | sudo bash
```

De interaktive menuer læser tastaturet fra `/dev/tty`, så de virker også i den
rør-baserede form ovenfor.

## Interaktivt forløb (piletaster)

- **↑/↓** (eller `j`/`k`) flytter · **Mellemrum** slår til/fra · **Enter**
  bekræfter · **q** annullerer.
1. **Vælg interfaces** — en tjekliste over fundne interfaces; dine nuværende fra
   `config.toml` (eller `vlan10`/`vlan20`) er forudvalgt.
2. **XDP-tilstand** pr. interface — `generic` (virker altid; krævet til
   VLAN-underinterfaces og veths) eller `native` (NIC-driver, hurtigere).
3. **Valgfrie komponenter** — Dashboard, Dashboard over HTTPS, Twingate
   gennem-XDP, ufw → allowlist-synk.
4. **Bekræft** før noget tilkobles dataplanet.

## Flag (ikke-interaktivt)

| Flag | Betydning |
|---|---|
| `--ifaces "vlan10:generic,vlan20:generic"` | Interfaces der skal tilkobles, `navn[:generic\|native]`. |
| `--management IPS` | Management-IP'er der holdes på en livline (kommaliste; ellers auto-registreret). |
| `--https` / `--tls-port N` | Server dashboardet over TLS (standardport 443). |
| `--no-dashboard` | Spring dashboardet over. |
| `--with-twingate NAVN` | Send Twingate-connector-containeren `NAVN` gennem XDP. |
| `--with-ufw-sync` | Installér ufw → allowlist-synk. |
| `--admin-user` / `--admin-pass` | Dashboard-admin der oprettes (deaktiverer den indbyggede `admin/admin`). |
| `--dash-port N` / `--dash-user USER` | Dashboard-port / OS-bruger det kører som. |
| `--repo URL` / `--branch REF` / `--src-dir DIR` | Hvor repoet hentes fra, når man ikke er i et checkout. |
| `--skip-deps` / `--no-tests` | Spring afhængigheder / `make test-bpf`-verifikatortjek over. |
| `-y`, `--yes` | Ikke-interaktivt: brug standardvalg, ingen spørgsmål. |

Eksempel, helt uovervåget:

```sh
sudo bash scripts/setup.sh --ifaces "vlan10:generic,vlan20:generic" \
  --https --admin-pass 'vælg-et-stærkt-et' --yes
```

## HTTPS

`--https` (eller komponentmenuen) sætter dashboardet bag en **nginx
TLS-reverse-proxy** med et **selvsigneret certifikat** (SAN = boksens IP'er +
hostnavn), der terminerer på `--tls-port` (standard 443) og proxyer til
dashboardet på loopback. Det er additivt — den almindelige port virker fortsat —
så det afbryder aldrig din nuværende adgang.

- Installationsprogrammet **tilføjer TLS-porten til livlinen**, så XDP's
  default-deny ikke kan sortsluge HTTPS på et beskyttet interface (inklusive
  Twingate-veth'en).
- Et selvsigneret certifikat giver en browseradvarsel på en LAN-IP. Importér
  certifikatet (`/etc/xdp-sentinel/tls/dashboard.crt`) for at stole på det, eller
  brug `mkcert`.
- For at tilføje TLS til et allerede kørende dashboard uden hele
  installationsprogrammet: `sudo xs-https-setup --port 443 --upstream 127.0.0.1:3000`.

## Hvad det installerer

```
/usr/local/bin/sentinelctl, sentinel-agent         CLI + agent
/usr/lib/xdp-sentinel/xdp_main.bpf.o               dataplan-objekt
/usr/local/bin/xs-protect-apply, xs-lockdown-apply automatik-jobs
/etc/xdp-sentinel/config.toml                      agentens interface-liste
/etc/xdp-sentinel/{paths,dashboard,lockdown}.env   konfiguration
/etc/xdp-sentinel/dash-users.json                  dashboard-brugere (admin oprettes)
/var/lib/xdp-sentinel/dashboard/                   protect-plan.json, lockdown.json
systemd: sentinel-agent, xdp-sentinel-protect-apply.{service,path},
         xdp-sentinel-lockdown.{service,path,timer}, xdp-dashboard (+ nginx til HTTPS)
```

## Sikkerhedshærdning som installationsprogrammet laver

- Genererer én **tilfældig** signeringsnøgle til dashboardet (`DASH_SESSION`) og
  regenererer den aldrig (så en ny kørsel ikke logger alle ud).
- Opretter en **rigtig admin**-bruger, hvilket deaktiverer den usikre indbyggede
  `admin`/`admin`. Sæt adgangskoden med `--admin-pass` eller ved prompten.
- Skriver hemmeligheder med `0600`.

Gør stadig selv efter installation:

- Begræns dashboard-porten med `ufw` til betroede værter.
- Lad kiosk-URL'en (`?k=`) være deaktiveret med mindre den er nødvendig — den
  bærer signeringsnøglen.

## Verificér & administrér

```sh
systemctl status sentinel-agent xdp-dashboard
sudo sentinelctl status -i vlan10
journalctl -u sentinel-agent -f
```

Det er sikkert at køre installationsprogrammet igen (idempotent): det afstemmer
konfigurationen, beholder signeringsnøglen og spørger før `config.toml`
overskrives.
