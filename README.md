# xdp-sentinel

A Linux XDP/eBPF network security appliance for 10 Gbps links: DDoS, flood,
scan and abusive-client detection and mitigation, with an asynchronous
ML-assisted control plane.

```
NIC → RSS queues → XDP fast path (C/eBPF) → per-CPU counters / maps / ring buffer
    → Rust collector → flow aggregation → features → ML inference (ONNX, sandboxed)
    → risk/policy engine → BPF maps (with TTLs) → XDP mitigation
```

The packet path never waits for userspace, ML or storage. Every dynamic
mitigation expires on its own, enforced inside XDP, so a crashed control
plane stops mitigating instead of starting to drop.

Docs are available in **English** ([`docs/EN/`](docs/EN/)) and **Dansk**
([`docs/DK/`](docs/DK/)).

## Status

| Phase | State |
|---|---|
| 1. XDP parser + counters, `sentinelctl`, tests, program-cost benchmark | **done** |
| 2–16 (policies, rate limiting, agent, telemetry, features, ML, risk engine, dashboard, 10 G benchmarks) | designed, see [development.md](docs/EN/development.md) |

No line-rate claim is made yet: that is Phase 16, on real hardware, per
[performance.md](docs/EN/performance.md).

The reference inline-bridge deployment additionally runs the **dashboard**
(protection plan, per-host stats, a lockdown kill-switch), **Twingate-through-XDP**
(the connector's traffic is inspected by the same dataplane), and optional
**HTTPS** — all wired up by the installer below.

## Install as an appliance (one command)

`scripts/setup.sh` builds and installs the whole system on a Debian/Ubuntu box:
the eBPF/XDP dataplane, `sentinelctl` + `sentinel-agent`, the protection and
lockdown automation, and — optionally — the dashboard (with HTTPS), the
Twingate integration and the ufw sync. It lets you **pick the interfaces** the
dataplane attaches to from an **arrow-key menu**, and clones the repo from GitHub
itself if it isn't run from a checkout.

```sh
# from a checkout (interactive):
sudo bash scripts/setup.sh

# non-interactive:
sudo bash scripts/setup.sh --ifaces "vlan10:generic,vlan20:generic" --https --yes

# remote one-liner (private repo → fine-grained read token):
T=github_pat_xxxxx
curl -fsSL -H "Authorization: Bearer $T" \
  https://raw.githubusercontent.com/24-ghost-the-killer/eBPF-XDP/main/scripts/setup.sh \
  | sudo GITHUB_TOKEN=$T bash
```

It is idempotent, generates a random dashboard signing key once, and creates a
real admin (disabling the built-in `admin/admin`). Full guide:
**[docs/EN/install.md](docs/EN/install.md)** · Dansk: **[docs/DK/install.md](docs/DK/install.md)**.

## Build & test (development)

Linux build host (clang ≥ 16, libbpf-dev, bpftool, Rust ≥ 1.85):

```sh
make                          # BPF object + sentinelctl
make test                     # unprivileged: host parser tests, Rust tests
sudo make test-bpf            # verifier + in-kernel corpus tests
sudo make test-integration    # veth end-to-end, native XDP
sudo target/release/sentinelctl attach -i <iface> --obj ebpf/build/xdp_main.bpf.o
sudo target/release/sentinelctl stats -i <iface> --interval 1
```

macOS or any Docker host: `make docker-image && make docker-test`.

The default dataplane config is **observe only**. Validity-based dropping
is opt-in: `sentinelctl config -i <iface> --drop-malformed on`.

## Documentation

Index: [English](docs/EN/) · [Dansk](docs/DK/). Every document below exists in
both languages (swap `EN` for `DK` in the path).

| Document | Sections |
|---|---|
| [install.md](docs/EN/install.md) | appliance install (`setup.sh`): interface selection, HTTPS, Twingate, lockdown, hardening |
| [architecture.md](docs/EN/architecture.md) | A overview, B stack, E repo layout, F XDP design, H userspace, API, failure modes |
| [hardware-tuning.md](docs/EN/hardware-tuning.md) | C hardware, D CPU/NUMA/RSS/IRQ strategy |
| [bpf-maps.md](docs/EN/bpf-maps.md) | G map design |
| [feature-schema.md](docs/EN/feature-schema.md) | I features, flow key |
| [ml.md](docs/EN/ml.md) | J models, bot and distributed-attack detection, training, deployment |
| [policy-engine.md](docs/EN/policy-engine.md) | K risk engine, rate limiting, false-positive control, allowlists |
| [storage.md](docs/EN/storage.md) | L ClickHouse schema |
| [observability.md](docs/EN/observability.md) | M metrics and alerts, N dashboard |
| [threat-model.md](docs/EN/threat-model.md) | O threat model |
| [performance.md](docs/EN/performance.md) | P benchmark methodology, Phase 1 numbers |
| [deployment.md](docs/EN/deployment.md) | systemd, privileges, operations, monitoring |
| [inline-vlan-deployment.md](docs/EN/inline-vlan-deployment.md) | one-NIC VLAN hairpin: switch + server setup, cutover, reproduce |
| [system-setup-and-vlan-security.md](docs/EN/system-setup-and-vlan-security.md) | whole-system setup & VLAN interception / jumping analysis |
| [security-audit.md](docs/EN/security-audit.md) | security audit & production-hardening findings |
| [development.md](docs/EN/development.md) | Q roadmap, build, tests, Phase 1 report |
| [XDP_RESILIENCE_TEST_PLAN.md](docs/EN/XDP_RESILIENCE_TEST_PLAN.md) · [ASSESSMENT](docs/EN/XDP_RESILIENCE_ASSESSMENT_SUMMARY.md) · [FIX_PROMPT](docs/EN/XDP_FIX_PROMPT.md) | resilience / bypass penetration testing |

## License

eBPF dataplane: GPL-2.0-only OR BSD-2-Clause. Everything else: Apache-2.0.
See [LICENSE](LICENSE).
