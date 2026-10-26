#!/usr/bin/env bash
# =============================================================================
# xdp-sentinel — one-shot appliance installer
# =============================================================================
# Builds and installs the whole system on a Debian/Ubuntu box: the eBPF/XDP
# dataplane object, the sentinelctl CLI and sentinel-agent, the protection +
# lockdown automation (systemd), and (optionally) the dashboard, the Twingate
# through-XDP integration, and the ufw sync.
#
# The headline feature: you pick which interfaces the dataplane attaches to
# (and can add more). That selection is written to the agent config
# (/etc/xdp-sentinel/config.toml); the agent attaches exactly those.
#
# Run it ON the appliance. It does NOT need a local checkout: if it isn't run
# from one, it clones the repo from GitHub itself. Three equivalent ways:
#
#   # 1) download then run (recommended — interactive menus work):
#   curl -fsSLO https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh
#   sudo bash setup.sh
#
#   # 2) one-liner (keyboard menus read from /dev/tty, so they still work):
#   curl -fsSL https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh | sudo bash
#
#   # 3) from a checkout:
#   sudo bash scripts/setup.sh --ifaces "vlan10:generic,vlan20:generic" --yes
#
# It is idempotent: re-running reconciles. It never regenerates an existing
# signing key (so it won't log everyone out) and asks before overwriting config.
# -----------------------------------------------------------------------------
set -euo pipefail

# ---- defaults ---------------------------------------------------------------
# Where to fetch the repo when not run from a checkout (override with env/flags).
XS_REPO="${XS_REPO:-https://github.com/24-ghost-the-killer/eBPF-XDP.git}"
XS_BRANCH="${XS_BRANCH:-main}"
XS_SRC_DIR="${XS_SRC_DIR:-/opt/xdp-sentinel/src}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." 2>/dev/null && pwd || echo /nonexistent)"
PREFIX_BIN=/usr/local/bin
OBJ_DIR=/usr/lib/xdp-sentinel
ETC=/etc/xdp-sentinel
DATA_DIR=/var/lib/xdp-sentinel/dashboard         # protect-plan.json + lockdown.json live here
UNIT_DIR=/etc/systemd/system

IFACES_SPEC=""                                    # e.g. "vlan10:generic,vlan20:generic"
MGMT_IPS=""                                        # comma list; auto-detected if empty
DASH_PORT=3000
DASH_USER="${SUDO_USER:-$USER}"                   # who the dashboard runs as / owns its files
ADMIN_USER="admin"
ADMIN_PASS=""                                      # prompted if empty (interactive)
WITH_DASHBOARD=auto                                # auto|yes|no
WITH_TWINGATE=no
TWINGATE_CONTAINER=""
WITH_UFW_SYNC=no
ASSUME_YES=no
SKIP_DEPS=no
RUN_TESTS=yes
WITH_HTTPS=no                                      # serve the dashboard over TLS (nginx proxy)
TLS_PORT=443

# Network provisioning (fresh box only — never touches an existing VLAN/bridge).
WITH_NETWORK=auto                                  # auto|yes|no
NET_TRUNK=""                                        # physical NIC carrying the VLAN trunk
NET_WAN_VLAN=10
NET_LAN_VLAN=20
NET_BRIDGE_CIDR=""                                  # management IP on br0, e.g. 192.168.1.10/24
NET_GATEWAY=""
NET_DNS="1.1.1.1,9.9.9.9"

# ---- pretty logging ---------------------------------------------------------
c() { printf '\033[%sm' "$1"; }
say()  { printf '\n%s== %s ==%s\n' "$(c '1;36')" "$*" "$(c 0)"; }
info() { printf '   %s\n' "$*"; }
ok()   { printf '   %s✓%s %s\n' "$(c '1;32')" "$(c 0)" "$*"; }
warn() { printf '%s!! %s%s\n' "$(c '1;33')" "$*" "$(c 0)" >&2; }
die()  { printf '%sxx %s%s\n' "$(c '1;31')" "$*" "$(c 0)" >&2; exit 1; }
confirm() { # prompt -> 0 yes / 1 no
  [ "$ASSUME_YES" = yes ] && return 0
  local a; read -r -p "   $1 [y/N] " a </dev/tty; [[ "$a" =~ ^[Yy] ]]
}

# ---- arrow-key menus (pure bash, no dependencies) ---------------------------
# ↑/↓ or j/k to move, Space to toggle (multi), Enter to confirm, q to cancel.
declare -A MENU_PRE=()                 # preselect map for menu_multi (name -> 1)
MENU_RESULT=(); MENU_ONE=""
# Put the tty into no-echo, char-at-a-time mode for the menu's lifetime, then
# restore it. Relying on `read -s` alone left the arrow-key escape bytes
# ([A/[B) echoed as "^[[B" on some terminals (notably over SSH); forcing -echo
# via stty suppresses that regardless of how `read` behaves.
_TTY_SAVED=""
_tui_begin() {
  printf '\033[?25l' >&2                                   # hide cursor
  _TTY_SAVED="$(stty -g </dev/tty 2>/dev/null || true)"
  # Only force echo off (that is what stopped "^[[B" leaking). Leave canonical
  # mode alone so bash's own `read -n1` keeps delivering Enter as before.
  stty -echo </dev/tty 2>/dev/null || true
}
_tui_restore() {
  [ -n "$_TTY_SAVED" ] && stty "$_TTY_SAVED" </dev/tty 2>/dev/null || true
  _TTY_SAVED=""
  printf '\033[?25h' >&2                                   # show cursor again
}
_read_key() {
  local k rest
  IFS= read -rsn1 k </dev/tty 2>/dev/null || true
  if [ "$k" = $'\x1b' ]; then
    # Drain the rest of the CSI/SS3 sequence. Allow more time than one frame so
    # a laggy SSH link can't split "\e" from "[B" and leak the tail to screen.
    IFS= read -rsn2 -t 0.5 rest </dev/tty 2>/dev/null || true
    case "$rest" in '[A'|'OA') echo up;; '[B'|'OB') echo down;; *) echo other;; esac
  elif [ -z "$k" ] || [ "$k" = $'\r' ] || [ "$k" = $'\n' ]; then echo enter
  elif [ "$k" = ' ' ]; then echo space
  elif [ "$k" = j ]; then echo down
  elif [ "$k" = k ]; then echo up
  elif [ "$k" = q ]; then echo quit
  else echo other; fi
}
menu_multi() { # TITLE OPT... ; preselect via MENU_PRE ; result -> MENU_RESULT[]
  local title="$1"; shift
  local -a opts=("$@") chk=(); local n=${#opts[@]} cur=0 i key drawn=0
  MENU_RESULT=(); [ "$n" -gt 0 ] || return 0      # nothing to choose from
  for i in "${!opts[@]}"; do chk[$i]=0; [ "${MENU_PRE[${opts[$i]}]:-0}" = 1 ] && chk[$i]=1; done
  _tui_begin; trap _tui_restore EXIT
  printf '\n%s%s%s\n   %s↑/↓ move · Space toggle · Enter confirm%s\n' "$(c '1;37')" "$title" "$(c 0)" "$(c 2)" "$(c 0)" >&2
  while true; do
    [ "$drawn" = 1 ] && printf '\033[%dA' "$n" >&2
    for i in "${!opts[@]}"; do
      local box="[ ]"; [ "${chk[$i]}" = 1 ] && box="[$(c '1;32')x$(c 0)]"
      if [ "$i" = "$cur" ]; then printf '\033[K  %s▸%s %s %s\n' "$(c '1;36')" "$(c 0)" "$box" "${opts[$i]}" >&2
      else printf '\033[K    %s %s\n' "$box" "${opts[$i]}" >&2; fi
    done
    drawn=1; key=$(_read_key)
    case "$key" in up) cur=$(((cur-1+n)%n));; down) cur=$(((cur+1)%n));;
      space) chk[$cur]=$((1-chk[$cur]));; enter) break;; quit) _tui_restore; die "cancelled.";; esac
  done
  _tui_restore; trap - EXIT
  MENU_RESULT=(); for i in "${!opts[@]}"; do [ "${chk[$i]}" = 1 ] && MENU_RESULT+=("${opts[$i]}"); done
  return 0
}
menu_single() { # TITLE OPT... ; result -> MENU_ONE
  local title="$1"; shift
  local -a opts=("$@"); local n=${#opts[@]} cur=0 i key drawn=0
  MENU_ONE=""; [ "$n" -gt 0 ] || return 0         # nothing to choose from
  _tui_begin; trap _tui_restore EXIT
  printf '\n%s%s%s\n   %s↑/↓ move · Enter select%s\n' "$(c '1;37')" "$title" "$(c 0)" "$(c 2)" "$(c 0)" >&2
  while true; do
    [ "$drawn" = 1 ] && printf '\033[%dA' "$n" >&2
    for i in "${!opts[@]}"; do
      if [ "$i" = "$cur" ]; then printf '\033[K  %s▸ %s%s\n' "$(c '1;36')" "${opts[$i]}" "$(c 0)" >&2
      else printf '\033[K    %s\n' "${opts[$i]}" >&2; fi
    done
    drawn=1; key=$(_read_key)
    case "$key" in up) cur=$(((cur-1+n)%n));; down) cur=$(((cur+1)%n));; enter) break;; quit) _tui_restore; die "cancelled.";; esac
  done
  _tui_restore; trap - EXIT; MENU_ONE="${opts[$cur]}"
  return 0
}

# ---- network provisioning (fresh box only) ----------------------------------
# True when the box already has VLAN interfaces (=> an inline bridge is set up
# and we must NOT touch the network — fresh-box provisioning only).
have_vlans() { ip -o link show type vlan 2>/dev/null | grep -q .; }

provision_network() { # copy the repo netplan template, swap per-box values, apply w/ auto-revert
  command -v netplan >/dev/null || { warn "netplan not found — skipping network setup (install netplan.io or configure the VLAN/bridge manually)"; return 0; }
  local tmpl="$REPO_ROOT/configs/netplan-vlan-bridge.yaml"
  [ -f "$tmpl" ] || die "netplan template not found: $tmpl (repo layout changed?)."

  # Per-box values to swap into the template: addresses / default-route gateway /
  # nameservers. Prompted when interactive, else taken from flags.
  local a
  if [ "$TUI" = yes ]; then
    read -r -p "   Bridge (management) IP/CIDR, e.g. 192.168.1.194/24 [${NET_BRIDGE_CIDR:-none}]: " a </dev/tty; NET_BRIDGE_CIDR="${a:-$NET_BRIDGE_CIDR}"
    read -r -p "   Default gateway [${NET_GATEWAY:-none}]: " a </dev/tty; NET_GATEWAY="${a:-$NET_GATEWAY}"
    read -r -p "   DNS servers (comma) [$NET_DNS]: " a </dev/tty; NET_DNS="${a:-$NET_DNS}"
  fi
  [ -n "$NET_BRIDGE_CIDR" ] || die "bridge IP/CIDR required (--bridge-cidr)."
  [[ "$NET_BRIDGE_CIDR" == */* ]] || die "bridge IP must include a prefix, e.g. 192.168.1.194/24."
  [ -n "$NET_GATEWAY" ] || die "default gateway required (--gateway)."

  # Trunk NIC + VLANs come from the template; --trunk renames the NIC for this box.
  local tmpl_nic; tmpl_nic="$(awk '/^[[:space:]]*ethernets:/{f=1;next} f&&/^[[:space:]]+[^[:space:]#]/{sub(/^[[:space:]]+/,"");sub(/:.*/,"");print;exit}' "$tmpl")"
  local nic="${NET_TRUNK:-$tmpl_nic}"
  local dns_inline; dns_inline="$(printf '%s' "$NET_DNS" | sed 's/,/, /g; s/  */ /g; s/^ *//; s/ *$//')"
  local target=/etc/netplan/01-xdp-vlan-bridge.yaml

  install -d -m0755 /etc/netplan
  [ -f "$target" ] && { cp -a "$target" "$target.bak.$(date +%s)" && warn "backed up existing $target"; }

  # Copy the template, but: drop the WiFi block (keeps its committed password off
  # fresh boxes) and replace br0's addresses / default route / nameservers.
  awk -v cidr="$NET_BRIDGE_CIDR" -v gw="$NET_GATEWAY" -v dns="$dns_inline" '
    BEGIN{ inbr=0; drop=0 }
    /^[[:space:]]*#[[:space:]]*Optional uplink/ { drop=1 }
    /^[[:space:]]*wifis:/ { drop=1 }
    drop==1 { next }
    /^    br0:[[:space:]]*$/ { inbr=1; print; next }
    inbr==1 && /^  [^[:space:]]/ { inbr=0 }
    inbr==1 && /^      addresses:/   { print "      addresses: [" cidr "]"; next }
    inbr==1 && /^      routes:/      { print "      routes: [{to: default, via: " gw "}]"; next }
    inbr==1 && /^      nameservers:/ { print "      nameservers: {addresses: [" dns "]}"; next }
    { print }
  ' "$tmpl" > "$target"

  # Rename the trunk NIC if the box uses a different one than the template.
  if [ -n "$NET_TRUNK" ] && [ -n "$tmpl_nic" ] && [ "$NET_TRUNK" != "$tmpl_nic" ]; then
    sed -i "s/\\b${tmpl_nic}\\b/${NET_TRUNK}/g" "$target"
  fi
  chmod 0600 "$target"
  ok "wrote $target from template (trunk $nic, br0 $NET_BRIDGE_CIDR, gw $NET_GATEWAY, dns $dns_inline)"
  ip -o link show "$nic" >/dev/null 2>&1 || warn "trunk NIC '$nic' not present — pass --trunk <nic> or edit $target (the VLANs need a real link)."

  netplan generate || die "netplan generate failed — config invalid, NOT applied (your network is unchanged)."
  if [ "$ASSUME_YES" = yes ]; then
    warn "applying network config non-interactively (NO auto-revert)…"
    netplan apply || die "netplan apply failed."
  else
    warn "Applying with 'netplan try': if this session drops, it AUTO-REVERTS in 120s."
    warn "If your connection stays up, press ENTER at netplan's prompt to keep the config."
    netplan try --timeout 120 || die "netplan try reverted or failed — network left as it was."
  fi
  local _i; for _i in $(seq 10); do have_vlans && break; sleep 1; done
  ok "network up: br0 = $(ip -br addr show br0 2>/dev/null | awk '{$1=$1;print}')"
}

usage() {
  cat <<'EOF'
xdp-sentinel installer — builds and installs the whole system, lets you pick
the interfaces the XDP dataplane attaches to. Clones the repo from GitHub if
not run from a checkout.

  curl -fsSL https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh | sudo bash

EOF
  cat <<EOF
Options:
  --repo URL           Git repo to fetch when not in a checkout (default: $XS_REPO).
  --branch REF         Branch/tag/commit to fetch (default: $XS_BRANCH).
  --src-dir DIR        Where to clone it (default: $XS_SRC_DIR).
  --ifaces LIST        Interfaces to attach, comma/space separated, name[:mode]
                       (mode = generic|native, default generic). e.g.
                       --ifaces "vlan10:generic,vlan20:generic"
  --management IPS     Management IPs kept on a lifeline (comma list).
  --admin-user NAME    Dashboard admin username to create (default: admin).
  --admin-pass PASS    Dashboard admin password (else prompted; disables admin/admin).
  --dash-port N        Dashboard port (default 3000).
  --dash-user USER     OS user the dashboard runs as (default: the sudo caller).
  --no-dashboard       Skip building/installing the dashboard.
  --https              Serve the dashboard over TLS (nginx proxy + self-signed cert).
  --tls-port N         HTTPS port (default 443).
  --with-network       Provision the VLAN/bridge network (fresh box with no VLANs).
  --no-network         Never provision the network (default on an already-configured box).
  --trunk NIC          Physical NIC carrying the VLAN trunk (else prompted/menu).
  --wan-vlan ID        WAN VLAN id (default 10).
  --lan-vlan ID        LAN VLAN id (default 20).
  --bridge-cidr CIDR   Management IP/CIDR on br0, e.g. 192.168.1.10/24.
  --gateway IP         Default gateway for br0.
  --net-dns LIST       DNS servers, comma separated (default 1.1.1.1,9.9.9.9).
  --with-twingate NAME Also route the Twingate connector container NAME through XDP.
  --with-ufw-sync      Install the ufw -> allowlist sync automation.
  --skip-deps          Do not apt-get install build dependencies.
  --no-tests           Skip 'make test-bpf' (the verifier load check).
  -y, --yes            Non-interactive: accept defaults, no prompts.
  -h, --help           This help.
EOF
}

# ---- arg parsing ------------------------------------------------------------
RAW_ARGS=("$@")                                    # preserved verbatim for the sudo re-exec
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) XS_REPO="$2"; shift 2;;
    --branch|--ref) XS_BRANCH="$2"; shift 2;;
    --src-dir) XS_SRC_DIR="$2"; shift 2;;
    --ifaces) IFACES_SPEC="$2"; shift 2;;
    --management) MGMT_IPS="$2"; shift 2;;
    --admin-user) ADMIN_USER="$2"; shift 2;;
    --admin-pass) ADMIN_PASS="$2"; shift 2;;
    --dash-port) DASH_PORT="$2"; shift 2;;
    --dash-user) DASH_USER="$2"; shift 2;;
    --no-dashboard) WITH_DASHBOARD=no; shift;;
    --https) WITH_HTTPS=yes; shift;;
    --no-https) WITH_HTTPS=no; shift;;
    --tls-port) TLS_PORT="$2"; shift 2;;
    --with-network) WITH_NETWORK=yes; shift;;
    --no-network) WITH_NETWORK=no; shift;;
    --trunk) NET_TRUNK="$2"; shift 2;;
    --wan-vlan) NET_WAN_VLAN="$2"; shift 2;;
    --lan-vlan) NET_LAN_VLAN="$2"; shift 2;;
    --bridge-cidr) NET_BRIDGE_CIDR="$2"; shift 2;;
    --gateway) NET_GATEWAY="$2"; shift 2;;
    --net-dns) NET_DNS="$2"; shift 2;;
    --with-twingate) WITH_TWINGATE=yes; TWINGATE_CONTAINER="$2"; shift 2;;
    --with-ufw-sync) WITH_UFW_SYNC=yes; shift;;
    --skip-deps) SKIP_DEPS=yes; shift;;
    --no-tests) RUN_TESTS=no; shift;;
    -y|--yes) ASSUME_YES=yes; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown option: $1 (see --help)";;
  esac
done

# ---- ensure root ------------------------------------------------------------
# From a checkout run as a normal user, re-exec under sudo. When piped
# (curl | bash) there is no file to re-exec, so ask to be run with sudo.
if [ "$(id -u)" -ne 0 ]; then
  if [ -f "${BASH_SOURCE[0]:-}" ]; then
    info "re-running under sudo..."
    exec sudo -E DASH_USER="$DASH_USER" bash "${BASH_SOURCE[0]}" "${RAW_ARGS[@]}"
  else
    die "run it as root, e.g.:  curl -fsSL $XS_REPO/.../setup.sh | sudo bash   (or: sudo bash setup.sh)"
  fi
fi

# =============================================================================
say "0/10 Preflight"
# =============================================================================
[ "$(uname -s)" = Linux ] || die "this installer targets Linux."
command -v apt-get >/dev/null || die "need apt-get (Debian/Ubuntu); install deps manually and use --skip-deps."
[ -d /sys/fs/bpf ] || die "bpffs not mounted at /sys/fs/bpf."
# Interactive menus read the keyboard from /dev/tty, so they work even under
# 'curl | sudo bash' (where stdin is the piped script, not the terminal).
if [ -r /dev/tty ] && [ "$ASSUME_YES" != yes ]; then TUI=yes; else TUI=no; fi
if [ -r /sys/kernel/btf/vmlinux ]; then ok "kernel BTF present"; else warn "no /sys/kernel/btf/vmlinux — CO-RE may fail; ensure CONFIG_DEBUG_INFO_BTF=y"; fi

# ---- get the repo: use the checkout we're in, else clone from GitHub --------
if [ -d "$REPO_ROOT/ebpf/src" ] && [ -f "$REPO_ROOT/Makefile" ]; then
  ok "repo: $REPO_ROOT (local checkout)"
else
  info "not in a checkout — fetching $XS_REPO ($XS_BRANCH)"
  if ! command -v git >/dev/null; then
    info "installing git…"; apt-get update -qq && apt-get install -y -qq git >/dev/null || die "could not install git (needed to fetch the repo)."
  fi
  # Private repo: pass a token via GITHUB_TOKEN/GH_TOKEN. Sent as an auth header
  # (not embedded in the URL or saved to .git/config), so it isn't left on disk.
  XS_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  GIT_AUTH=()
  [ -n "$XS_TOKEN" ] && GIT_AUTH=(-c "http.extraHeader=Authorization: Bearer $XS_TOKEN") && info "using GITHUB_TOKEN for private-repo access"
  if [ -d "$XS_SRC_DIR/.git" ]; then
    info "updating existing clone at $XS_SRC_DIR"
    git "${GIT_AUTH[@]}" -C "$XS_SRC_DIR" fetch --depth 1 origin "$XS_BRANCH" >/dev/null 2>&1 \
      && git -C "$XS_SRC_DIR" checkout -q FETCH_HEAD || die "git fetch failed (check --repo/--branch, token and network)."
  else
    install -d -m0755 "$(dirname "$XS_SRC_DIR")"
    rm -rf "$XS_SRC_DIR"
    git "${GIT_AUTH[@]}" clone --depth 1 --branch "$XS_BRANCH" "$XS_REPO" "$XS_SRC_DIR" >/dev/null 2>&1 \
      || git "${GIT_AUTH[@]}" clone --depth 1 "$XS_REPO" "$XS_SRC_DIR" >/dev/null 2>&1 \
      || die "git clone failed — private repo? set GITHUB_TOKEN. (also check --repo/--branch, network)."
  fi
  REPO_ROOT="$XS_SRC_DIR"
  [ -f "$REPO_ROOT/Makefile" ] && [ -d "$REPO_ROOT/ebpf/src" ] || die "clone did not contain the expected repo layout."
  ok "repo cloned to $REPO_ROOT"
fi
id "$DASH_USER" >/dev/null 2>&1 || die "dashboard user '$DASH_USER' does not exist (pass --dash-user)."

# =============================================================================
say "1/10 Build dependencies"
# =============================================================================
if [ "$SKIP_DEPS" = yes ]; then
  info "skipping (--skip-deps)"
else
  PKGS=(clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config make bpftool)
  info "installing: ${PKGS[*]} (+ rust, node checked separately)"
  apt-get update -qq
  apt-get install -y -qq "${PKGS[@]}" >/dev/null
  ok "system build deps installed"
  command -v cargo >/dev/null || { warn "cargo not found — installing rustc/cargo via apt"; apt-get install -y -qq rustc cargo >/dev/null || die "install Rust manually (rustup recommended)"; }
  if [ "$WITH_DASHBOARD" != no ] && ! command -v npm >/dev/null; then
    warn "npm not found — installing nodejs/npm via apt"; apt-get install -y -qq nodejs npm >/dev/null || warn "install Node 18+ manually; dashboard build will be skipped"
  fi
fi
command -v cargo >/dev/null || die "cargo/rustc required to build the userspace."

# =============================================================================
say "2/10 Build (eBPF object + userspace)"
# =============================================================================
( cd "$REPO_ROOT" && make ebpf userspace )
[ -f "$REPO_ROOT/ebpf/build/xdp_main.bpf.o" ] || die "eBPF object not built."
[ -x "$REPO_ROOT/target/release/sentinelctl" ] || die "sentinelctl not built."
ok "built dataplane object + sentinelctl + sentinel-agent"
if [ "$RUN_TESTS" = yes ]; then
  say "2b   Verifier load check (make test-bpf)"
  if ( cd "$REPO_ROOT" && make test-bpf ); then ok "object loads through the verifier"; else die "test-bpf failed — not installing a dataplane that fails verification."; fi
fi

# =============================================================================
say "3/10 Network (VLAN/bridge)"
# =============================================================================
# Fresh-box only: if the inline bridge isn't set up yet (no VLAN interfaces),
# optionally create it so the interface picker below has vlanWAN/vlanLAN to show.
# An already-configured box is detected and left completely untouched.
if [ "$WITH_NETWORK" = no ]; then
  info "network provisioning disabled (--no-network)"
elif have_vlans; then
  [ "$WITH_NETWORK" = yes ] && warn "VLAN interfaces already exist — NOT reconfiguring the network (fresh-box only)."
  ok "existing VLAN/bridge network detected — leaving it untouched"
else
  DO_NET=no
  if [ "$WITH_NETWORK" = yes ]; then DO_NET=yes
  elif [ "$TUI" = yes ]; then
    menu_single "No VLAN/bridge network found — set it up now (trunk + 2 VLANs + br0)?" \
      "No — attach to interfaces that already exist" \
      "Yes — provision the VLAN/bridge network now"
    [ "$MENU_ONE" = "Yes — provision the VLAN/bridge network now" ] && DO_NET=yes
  fi
  [ "$DO_NET" = yes ] && provision_network || info "skipping network provisioning"
fi

# =============================================================================
say "4/10 Select interfaces"
# =============================================================================
# Candidates = real links, minus loopback. Show state so you can tell which are up.
mapfile -t CAND < <(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -vx lo)
declare -A IFMODE
parse_ifaces() { # "name[:mode],name[:mode]" -> IFMODE
  IFMODE=(); local tok name mode
  for tok in ${1//,/ }; do
    name="${tok%%:*}"; mode="generic"; [[ "$tok" == *:* ]] && mode="${tok#*:}"
    [[ "$mode" =~ ^(generic|native)$ ]] || die "interface mode must be generic|native, got '$mode' for '$name'"
    IFMODE["$name"]="$mode"
  done
}
# Default selection: whatever config.toml already has, else common inline-bridge names if present.
DEFAULT_SEL=""
if [ -f "$ETC/config.toml" ]; then
  DEFAULT_SEL="$(awk -F'"' '/^[[:space:]]*name[[:space:]]*=/{printf "%s,", $2}' "$ETC/config.toml")"
  DEFAULT_SEL="${DEFAULT_SEL%,}"
fi
[ -z "$DEFAULT_SEL" ] && for g in vlan10 vlan20; do printf '%s\n' "${CAND[@]}" | grep -qx "$g" && DEFAULT_SEL="${DEFAULT_SEL:+$DEFAULT_SEL,}$g:generic"; done

if [ -n "$IFACES_SPEC" ]; then
  parse_ifaces "$IFACES_SPEC"
elif [ "$ASSUME_YES" = yes ]; then
  [ -n "$DEFAULT_SEL" ] || die "no --ifaces given and no sensible default; pass --ifaces."
  parse_ifaces "$DEFAULT_SEL"
elif [ "$TUI" = yes ]; then
  MENU_PRE=()
  for tok in ${DEFAULT_SEL//,/ }; do MENU_PRE["${tok%%:*}"]=1; done
  menu_multi "Select the interfaces the XDP dataplane attaches to:" "${CAND[@]}"
  [ "${#MENU_RESULT[@]}" -gt 0 ] || die "no interfaces selected."
  IFMODE=()
  for n in "${MENU_RESULT[@]}"; do
    menu_single "XDP mode for '$n'  (generic = always works; native = NIC driver, faster):" generic native
    IFMODE["$n"]="$MENU_ONE"
  done
else
  # Fallback only when there is no usable terminal for the arrow menu
  # (TUI=no). Numbered list + one line, so an unattended/no-tty run still works.
  info "Interfaces detected on this box:"
  ix=1
  for n in "${CAND[@]}"; do
    printf '     %2d) %-16s %s\n' "$ix" "$n" "$(ip -br addr show "$n" 2>/dev/null | sed -E 's/^[^ ]+ +[^ ]+ +//')"
    ix=$((ix+1))
  done
  info "Type the NUMBERS or names to attach (space/comma separated, name[:native])."
  REPLY_IF=""
  read -r -p "   interfaces [${DEFAULT_SEL:-none}]: " REPLY_IF </dev/tty || REPLY_IF=""
  REPLY_IF="${REPLY_IF:-$DEFAULT_SEL}"
  [ -n "$REPLY_IF" ] || die "no interfaces selected."
  RESOLVED=""
  for tok in ${REPLY_IF//,/ }; do
    nm="${tok%%:*}"; md=""; [[ "$tok" == *:* ]] && md=":${tok#*:}"
    if [[ "$nm" =~ ^[0-9]+$ ]]; then
      idx=$((nm-1))
      { [ "$idx" -ge 0 ] && [ "$idx" -lt "${#CAND[@]}" ]; } || die "invalid number '$nm' (pick 1-${#CAND[@]})."
      nm="${CAND[$idx]}"
    fi
    RESOLVED="${RESOLVED:+$RESOLVED,}${nm}${md}"
  done
  parse_ifaces "$RESOLVED"
fi
[ "${#IFMODE[@]}" -gt 0 ] || die "no interfaces selected."
for n in "${!IFMODE[@]}"; do
  printf '%s\n' "${CAND[@]}" | grep -qx "$n" || warn "interface '$n' is not present right now (will attach when it appears)."
done
info "will attach: $(for n in "${!IFMODE[@]}"; do printf '%s(%s) ' "$n" "${IFMODE[$n]}"; done)"

# Optional components (arrow multi-select when interactive).
if [ "$TUI" = yes ] && [ -z "$IFACES_SPEC" ]; then
  MENU_PRE=([Dashboard]=1 ["Dashboard over HTTPS (nginx TLS)"]=1)
  menu_multi "Optional components to install (Space toggles):" "Dashboard" "Dashboard over HTTPS (nginx TLS)" "Twingate through-XDP" "ufw → allowlist sync"
  WITH_DASHBOARD=no; WITH_HTTPS=no; WITH_TWINGATE=no; WITH_UFW_SYNC=no
  for sel in "${MENU_RESULT[@]}"; do
    case "$sel" in
      Dashboard) WITH_DASHBOARD=yes;;
      "Dashboard over HTTPS"*) WITH_HTTPS=yes;;
      "Twingate through-XDP") WITH_TWINGATE=yes;;
      "ufw"*) WITH_UFW_SYNC=yes;;
    esac
  done
  [ "$WITH_HTTPS" = yes ] && [ "$WITH_DASHBOARD" = no ] && { warn "HTTPS needs the dashboard — enabling it too."; WITH_DASHBOARD=yes; }
  if [ "$WITH_TWINGATE" = yes ] && [ -z "$TWINGATE_CONTAINER" ]; then
    read -r -p "   Twingate connector container name: " TWINGATE_CONTAINER </dev/tty
  fi
fi

if [ "$TUI" = yes ]; then
  menu_single "Attach XDP and inspect traffic on: ${!IFMODE[*]} — proceed?" "Yes, install now" "No, cancel"
  [ "$MENU_ONE" = "Yes, install now" ] || die "aborted."
else
  confirm "Attaching XDP inspects traffic on these interfaces. Continue?" || die "aborted."
fi

# Management IPs (kept on a lifeline so default-deny never cuts SSH/dashboard).
if [ -z "$MGMT_IPS" ]; then
  MGMT_IPS="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)"
fi
info "management IPs (lifeline SSH+dashboard): ${MGMT_IPS:-none}"

# =============================================================================
say "5/10 Install binaries, object and scripts"
# =============================================================================
install -d -m0755 "$OBJ_DIR" "$ETC" "$DATA_DIR"
install -m0755 "$REPO_ROOT/target/release/sentinelctl"    "$PREFIX_BIN/sentinelctl"
install -m0755 "$REPO_ROOT/target/release/sentinel-agent" "$PREFIX_BIN/sentinel-agent"
install -m0644 "$REPO_ROOT/ebpf/build/xdp_main.bpf.o"     "$OBJ_DIR/xdp_main.bpf.o"
install -m0755 "$REPO_ROOT/scripts/xs-protect-apply"      "$PREFIX_BIN/xs-protect-apply"
install -m0755 "$REPO_ROOT/scripts/xs-lockdown-apply"     "$PREFIX_BIN/xs-lockdown-apply"
[ "$WITH_TWINGATE" = yes ] && {
  install -m0755 "$REPO_ROOT/scripts/xs-twingate-attach"   "$PREFIX_BIN/xs-twingate-attach"
  install -m0755 "$REPO_ROOT/scripts/xs-twingate-watchdog" "$PREFIX_BIN/xs-twingate-watchdog"
}
[ "$WITH_UFW_SYNC" = yes ] && install -m0755 "$REPO_ROOT/scripts/xs-ufw-sync" "$PREFIX_BIN/xs-ufw-sync"
[ "$WITH_HTTPS" = yes ] && install -m0755 "$REPO_ROOT/scripts/xs-https-setup" "$PREFIX_BIN/xs-https-setup"
# Pentest / regression suite (injects via bpftool prog run — nothing on the wire).
if [ -f "$REPO_ROOT/pentest/xdp_pentest.py" ]; then
  install -d -m0755 /opt/xdp-sentinel/pentest
  cp -a "$REPO_ROOT/pentest/." /opt/xdp-sentinel/pentest/
  install -m0755 "$REPO_ROOT/scripts/xs-pentest" "$PREFIX_BIN/xs-pentest"
  ok "pentest suite -> /opt/xdp-sentinel/pentest; launcher 'xs-pentest' installed"
fi
ok "installed to $PREFIX_BIN and $OBJ_DIR"

# =============================================================================
say "6/10 Configuration"
# =============================================================================
# 5a. agent config.toml — the interface list the agent attaches.
if [ -f "$ETC/config.toml" ] && ! confirm "Overwrite existing $ETC/config.toml?"; then
  info "keeping existing config.toml"
else
  { echo '# Generated by scripts/setup.sh'
    echo 'metrics_addr = "127.0.0.1:9464"'
    echo 'pin_root = "/sys/fs/bpf/xdp-sentinel"'
    echo 'bpf_obj  = "/usr/lib/xdp-sentinel/xdp_main.bpf.o"'
    for n in "${!IFMODE[@]}"; do
      printf '\n[[interface]]\nname   = "%s"\nmode   = "%s"\nattach = true\n' "$n" "${IFMODE[$n]}"
    done
  } > "$ETC/config.toml"
  chmod 0640 "$ETC/config.toml"
  ok "wrote $ETC/config.toml ($(echo "${!IFMODE[@]}" | wc -w) interface(s))"
fi

# Lifeline services always kept open on a protected management IP (so default-deny
# can never blackhole access). Includes the TLS port when serving HTTPS, or the
# HTTPS dashboard would be dropped on protected interfaces (incl. Twingate).
LIFELINE="tcp/22,tcp/3000"
[ "$WITH_HTTPS" = yes ] && LIFELINE="$LIFELINE,tcp/$TLS_PORT"

# 5b. paths.env — point the box jobs and dashboard at one data dir (drop-ins below).
cat > "$ETC/paths.env" <<EOF
# Generated by scripts/setup.sh — shared data-file locations.
XS_PROTECT_PLAN=$DATA_DIR/protect-plan.json
XS_LOCKDOWN_FILE=$DATA_DIR/lockdown.json
XS_PROTECT_MANAGEMENT=$MGMT_IPS
XS_PROTECT_LIFELINE=$LIFELINE
EOF
chmod 0644 "$ETC/paths.env"

# 5c. lockdown interfaces default to the attached set.
printf 'XS_LOCKDOWN_IFACES="%s"\n' "$(echo "${!IFMODE[@]}")" > "$ETC/lockdown.env"
chmod 0644 "$ETC/lockdown.env"

# 5d. protect.conf — management IPs under default-deny (lifeline forced open).
if [ ! -f "$ETC/protect.conf" ]; then
  { echo '# <ipv4> [iface]   one protected destination per line'
    FIRST_IF="$(echo "${!IFMODE[@]}" | awk '{print $1}')"
    for ip in ${MGMT_IPS//,/ }; do echo "$ip $FIRST_IF"; done
  } > "$ETC/protect.conf"
  chmod 0644 "$ETC/protect.conf"
  ok "wrote $ETC/protect.conf"
fi

# 5e. Twingate env (shared container name for attach + lockdown).
if [ "$WITH_TWINGATE" = yes ]; then
  [ -n "$TWINGATE_CONTAINER" ] || die "--with-twingate needs the connector container NAME."
  printf 'XS_TWINGATE_CONTAINER=%s\n' "$TWINGATE_CONTAINER" > "$ETC/twingate.env"
  chmod 0644 "$ETC/twingate.env"
  ok "Twingate container: $TWINGATE_CONTAINER (lockdown + allowlist will cover its veth)"
fi

# =============================================================================
say "7/10 systemd units"
# =============================================================================
D="$REPO_ROOT/deploy/systemd"
install -m0644 "$D/sentinel-agent.service" "$UNIT_DIR/"
install -m0644 "$D/xdp-sentinel-protect-apply.service" "$D/xdp-sentinel-protect-apply.path" "$UNIT_DIR/"
install -m0644 "$D/xdp-sentinel-lockdown.service" "$D/xdp-sentinel-lockdown.path" "$D/xdp-sentinel-lockdown.timer" "$UNIT_DIR/"
if [ "$WITH_TWINGATE" = yes ]; then
  install -m0644 "$D/xdp-sentinel-twingate-attach.service" "$D/xdp-sentinel-twingate-attach.path" "$UNIT_DIR/" 2>/dev/null || true
  install -m0644 "$D/xdp-sentinel-twingate-watchdog.service" "$D/xdp-sentinel-twingate-watchdog.timer" "$UNIT_DIR/" 2>/dev/null || true
fi
[ "$WITH_UFW_SYNC" = yes ] && install -m0644 "$D/xdp-sentinel-ufw-sync.service" "$D/xdp-sentinel-ufw-sync.path" "$UNIT_DIR/" 2>/dev/null || true

# Drop-ins so the jobs read paths.env (data-file locations) without editing shipped units.
for unit in xdp-sentinel-protect-apply xdp-sentinel-lockdown xdp-sentinel-twingate-attach; do
  [ -f "$UNIT_DIR/$unit.service" ] || continue
  install -d -m0755 "$UNIT_DIR/$unit.service.d"
  printf '[Service]\nEnvironmentFile=-%s\n' "$ETC/paths.env" > "$UNIT_DIR/$unit.service.d/paths.conf"
done
systemctl daemon-reload
ok "units installed"

# =============================================================================
say "8/10 Dashboard"
# =============================================================================
if [ "$WITH_DASHBOARD" = no ] || ! command -v npm >/dev/null; then
  [ "$WITH_DASHBOARD" = no ] && info "skipped (--no-dashboard)" || warn "npm missing — skipping dashboard"
else
  DASH_DST=/opt/xdp-sentinel/dashboard
  install -d -m0755 /opt/xdp-sentinel
  info "building dashboard (npm ci && build)…"
  ( cd "$REPO_ROOT/dashboard" && npm ci --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null )
  rm -rf "$DASH_DST"; cp -a "$REPO_ROOT/dashboard" "$DASH_DST"
  chown -R "$DASH_USER": /opt/xdp-sentinel

  # dashboard.env — generate a RANDOM signing key once; never regenerate (would
  # invalidate every session). Secrets file is 0600.
  if [ -f "$ETC/dashboard.env" ] && grep -q '^DASH_SESSION=' "$ETC/dashboard.env"; then
    info "keeping existing DASH_SESSION (not regenerating — would log users out)"
  else
    SESSION_KEY="$(head -c48 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    cat > "$ETC/dashboard.env" <<EOF
# Generated by scripts/setup.sh
DASH_SESSION=$SESSION_KEY
DASH_USERS_FILE=$ETC/dash-users.json
DASH_PROTECT_PLAN=$DATA_DIR/protect-plan.json
DASH_LOCKDOWN_FILE=$DATA_DIR/lockdown.json
DASH_PROTECT_MANAGEMENT=$MGMT_IPS
DASH_PROTECT_LIFELINE=$LIFELINE
DASH_PROTECT_IFACE=$(echo "${!IFMODE[@]}" | awk '{print $1}')
DASH_LOCKDOWN_IFACES=$(echo "${!IFMODE[@]}" | tr ' ' ',')
PROM_URL=http://127.0.0.1:9091
AGENT_URL=http://127.0.0.1:9464
DASH_PORT=$DASH_PORT
PORT=$DASH_PORT
EOF
    chmod 0600 "$ETC/dashboard.env"; ok "generated dashboard.env with a random signing key"
  fi

  # Create a REAL admin so the built-in admin/admin stops working (security).
  if [ -z "$ADMIN_PASS" ] && [ "$ASSUME_YES" != yes ]; then
    read -rs -p "   Set dashboard admin ('$ADMIN_USER') password: " ADMIN_PASS </dev/tty; echo
  fi
  if [ -n "$ADMIN_PASS" ]; then
    DASH_USERS_FILE="$ETC/dash-users.json" DASH_NEW_PASSWORD="$ADMIN_PASS" \
      node "$DASH_DST/scripts/dash-users.mjs" add "$ADMIN_USER" admins >/dev/null \
      && ok "created admin '$ADMIN_USER' (built-in admin/admin now disabled)" \
      || warn "could not create admin automatically; run dash-users.mjs manually — admin/admin stays active until you do"
  else
    warn "no admin password given: the INSECURE built-in admin/admin remains active. Create a real admin ASAP."
  fi
  chown "$DASH_USER": "$ETC/dash-users.json" "$ETC/dashboard.env" 2>/dev/null || true
  chown -R "$DASH_USER": "$DATA_DIR"

  cat > "$UNIT_DIR/xdp-dashboard.service" <<EOF
[Unit]
Description=xdp-sentinel dashboard
After=network-online.target sentinel-agent.service
Wants=network-online.target
[Service]
Type=simple
User=$DASH_USER
WorkingDirectory=$DASH_DST
EnvironmentFile=$ETC/dashboard.env
ExecStart=$(command -v npm) run start -- -p $DASH_PORT
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "dashboard installed at $DASH_DST (runs as $DASH_USER on :$DASH_PORT)"
fi

# =============================================================================
say "9/10 Enable and start services"
# =============================================================================
chown -R "$DASH_USER": "$DATA_DIR"
systemctl enable --now sentinel-agent.service
ok "sentinel-agent started (attaching: ${!IFMODE[*]})"
# Give the agent a moment, then verify a pin exists for the first interface.
FIRST_IF="$(echo "${!IFMODE[@]}" | awk '{print $1}')"
for _ in $(seq 20); do [ -e "/sys/fs/bpf/xdp-sentinel/$FIRST_IF/xs_service_v4" ] && break; sleep 1; done
[ -e "/sys/fs/bpf/xdp-sentinel/$FIRST_IF/xs_service_v4" ] && ok "dataplane attached on $FIRST_IF" || warn "no pin for $FIRST_IF yet — check: journalctl -u sentinel-agent"

systemctl enable --now xdp-sentinel-protect-apply.path
systemctl enable --now xdp-sentinel-lockdown.path xdp-sentinel-lockdown.timer
ok "protection + lockdown automation enabled"
if [ "$WITH_TWINGATE" = yes ] && [ -f "$UNIT_DIR/xdp-sentinel-twingate-attach.path" ]; then
  systemctl enable --now xdp-sentinel-twingate-attach.service xdp-sentinel-twingate-attach.path || true
  [ -f "$UNIT_DIR/xdp-sentinel-twingate-watchdog.timer" ] && systemctl enable --now xdp-sentinel-twingate-watchdog.timer || true
  ok "Twingate through-XDP enabled"
fi
[ "$WITH_UFW_SYNC" = yes ] && { systemctl enable --now xdp-sentinel-ufw-sync.path || true; ok "ufw sync enabled"; }
[ -f "$UNIT_DIR/xdp-dashboard.service" ] && { systemctl enable --now xdp-dashboard.service; ok "dashboard started"; }
if [ "$WITH_HTTPS" = yes ] && [ -f "$UNIT_DIR/xdp-dashboard.service" ]; then
  "$PREFIX_BIN/xs-https-setup" --port "$TLS_PORT" --upstream "127.0.0.1:$DASH_PORT" \
    && ok "HTTPS enabled on :$TLS_PORT (self-signed) — lifeline opens tcp/$TLS_PORT" \
    || warn "HTTPS setup reported a problem; dashboard still reachable on http://…:$DASH_PORT"
fi

# =============================================================================
say "10/10 Summary"
# =============================================================================
echo
ok "Install complete."
echo "   dataplane : $(systemctl is-active sentinel-agent)  on  ${!IFMODE[*]}"
if [ -f "$UNIT_DIR/xdp-dashboard.service" ]; then
  if [ "$WITH_HTTPS" = yes ]; then echo "   dashboard : $(systemctl is-active xdp-dashboard)  ->  https://${MGMT_IPS%%,*}:$TLS_PORT/analytics  (self-signed)"
  else echo "   dashboard : $(systemctl is-active xdp-dashboard)  ->  http://${MGMT_IPS%%,*}:$DASH_PORT/analytics"; fi
fi
echo "   config    : $ETC/config.toml   data: $DATA_DIR"
[ -x "$PREFIX_BIN/xs-pentest" ] && echo "   pentest   : 'xs-pentest --coverage' (safe), 'sudo xs-pentest --run' (full suite)"
echo
warn "SECURITY — do this now:"
if [ "$WITH_HTTPS" = yes ]; then
  echo "   • Dashboard is HTTPS on :$TLS_PORT (self-signed — browser will warn; import the cert to trust it)."
  echo "   • Restrict it: 'sudo ufw allow from <trusted> to any port $TLS_PORT proto tcp'."
else
  echo "   • Restrict the dashboard port: 'sudo ufw allow from <trusted> to any port $DASH_PORT proto tcp' (it is plain HTTP, LAN-grade — consider --https)."
fi
echo "   • Ensure a real admin exists (admin/admin works until one does): node $DASH_DST/scripts/dash-users.mjs list"
echo "   • Do NOT use the kiosk URL (?k=) over any logged path — it carries the signing key. Leave kiosk disabled unless needed."
echo
info "Enable drop mitigations deliberately once you've watched traffic, e.g.:"
info "  sudo sentinelctl config -i $FIRST_IF --drop-malformed on --drop-bad-tcp-flags on"
