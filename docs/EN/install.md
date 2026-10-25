<!-- Language: **English** · [Dansk](../DK/install.md) -->

# Appliance install (`scripts/setup.sh`)

`scripts/setup.sh` builds and installs the whole system on a Debian/Ubuntu box
in one run: the eBPF/XDP dataplane, `sentinelctl` + `sentinel-agent`, the
protection and lockdown automation, and — optionally — the dashboard (with
HTTPS), the Twingate-through-XDP integration, and the ufw sync.

Its headline step lets you **pick which interfaces** the dataplane attaches to
(arrow-key menu), writing them to the agent config (`/etc/xdp-sentinel/config.toml`).

> The installer does **not** need a local checkout: if it isn't run from one it
> clones the repo from GitHub itself.

## Requirements

- Debian 12/13 or Ubuntu 24.04, Linux ≥ 6.1 with BTF (`/sys/kernel/btf/vmlinux`)
  and bpffs at `/sys/fs/bpf` (systemd mounts it by default).
- `sudo`/root. The script re-execs itself under sudo when needed.
- Build dependencies are installed automatically (clang, llvm, libbpf-dev,
  bpftool, make, Rust, and Node for the dashboard); skip with `--skip-deps`.

## Install

### From a checkout

```sh
sudo bash scripts/setup.sh
```

### Remote, one command

The repo is **private**, so fetching it needs a GitHub token (a fine-grained PAT
with read access). It is sent as an auth header and never written to disk:

```sh
T=github_pat_xxxxx
curl -fsSL -H "Authorization: Bearer $T" \
  https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh \
  | sudo GITHUB_TOKEN=$T bash
```

If the repo is made public, the token drops out:

```sh
curl -fsSL https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh | sudo bash
```

The interactive menus read the keyboard from `/dev/tty`, so they work even in the
piped form above.

## Interactive flow (arrow keys)

- **↑/↓** (or `j`/`k`) move · **Space** toggles · **Enter** confirms · **q** cancels.
1. **Select interfaces** — a checklist of detected interfaces; your current
   `config.toml` ones (or `vlan10`/`vlan20`) are pre-checked.
2. **XDP mode** per interface — `generic` (always works; required for VLAN
   sub-interfaces and veths) or `native` (NIC driver, faster).
3. **Optional components** — Dashboard, Dashboard over HTTPS, Twingate
   through-XDP, ufw → allowlist sync.
4. **Confirm** before anything attaches to the dataplane.

## Non-interactive flags

| Flag | Meaning |
|---|---|
| `--ifaces "vlan10:generic,vlan20:generic"` | Interfaces to attach, `name[:generic\|native]`. |
| `--management IPS` | Management IPs kept on a lifeline (comma list; auto-detected otherwise). |
| `--https` / `--tls-port N` | Serve the dashboard over TLS (default port 443). |
| `--no-dashboard` | Skip the dashboard. |
| `--with-twingate NAME` | Route the Twingate connector container `NAME` through XDP. |
| `--with-ufw-sync` | Install the ufw → allowlist sync. |
| `--admin-user` / `--admin-pass` | Dashboard admin to create (disables the built-in `admin/admin`). |
| `--dash-port N` / `--dash-user USER` | Dashboard port / OS user it runs as. |
| `--repo URL` / `--branch REF` / `--src-dir DIR` | Where to fetch the repo when not in a checkout. |
| `--skip-deps` / `--no-tests` | Skip dependency install / the `make test-bpf` verifier check. |
| `-y`, `--yes` | Non-interactive: accept defaults, no prompts. |

Example, fully unattended:

```sh
sudo bash scripts/setup.sh --ifaces "vlan10:generic,vlan20:generic" \
  --https --admin-pass 'choose-a-strong-one' --yes
```

## HTTPS

`--https` (or the component menu) puts the dashboard behind an **nginx TLS
reverse proxy** with a **self-signed certificate** (SAN = the box's IPs +
hostname), terminating on `--tls-port` (default 443) and proxying to the
dashboard on loopback. It is additive — the plain port keeps working — so it
never cuts your current access.

- The installer **adds the TLS port to the lifeline** so XDP default-deny can't
  blackhole HTTPS on a protected interface (including the Twingate veth).
- A self-signed cert makes the browser warn on a LAN IP. Import the cert
  (`/etc/xdp-sentinel/tls/dashboard.crt`) to trust it, or use `mkcert`.
- To add TLS to an already-running dashboard without the full installer:
  `sudo xs-https-setup --port 443 --upstream 127.0.0.1:3000`.

## What it installs

```
/usr/local/bin/sentinelctl, sentinel-agent         CLI + agent
/usr/lib/xdp-sentinel/xdp_main.bpf.o               dataplane object
/usr/local/bin/xs-protect-apply, xs-lockdown-apply automation jobs
/etc/xdp-sentinel/config.toml                      agent interface list
/etc/xdp-sentinel/{paths,dashboard,lockdown}.env   config
/etc/xdp-sentinel/dash-users.json                  dashboard users (admin created)
/var/lib/xdp-sentinel/dashboard/                   protect-plan.json, lockdown.json
systemd: sentinel-agent, xdp-sentinel-protect-apply.{service,path},
         xdp-sentinel-lockdown.{service,path,timer}, xdp-dashboard (+ nginx for HTTPS)
```

## Security hardening the installer does

- Generates a **random** dashboard signing key (`DASH_SESSION`) once, and never
  regenerates it (so re-running won't log everyone out).
- Creates a **real admin** user, which disables the insecure built-in
  `admin`/`admin` fallback. Set the password with `--admin-pass` or at the prompt.
- Writes secrets `0600`.

After install, still do yourself:

- Restrict the dashboard port with `ufw` to trusted hosts.
- Leave the kiosk URL (`?k=`) disabled unless needed — it carries the signing key.

## Verify & manage

```sh
systemctl status sentinel-agent xdp-dashboard
sudo sentinelctl status -i vlan10
journalctl -u sentinel-agent -f
```

Re-running the installer is safe (idempotent): it reconciles config, keeps the
signing key, and asks before overwriting `config.toml`.
