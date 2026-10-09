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

## Status

| Phase | State |
|---|---|
| 1. XDP parser + counters, `sentinelctl`, tests, program-cost benchmark | **done** |
| 2–16 (policies, rate limiting, agent, telemetry, features, ML, risk engine, dashboard, 10 G benchmarks) | designed, see [docs/development.md](docs/development.md) |

No line-rate claim is made yet: that is Phase 16, on real hardware, per
[docs/performance.md](docs/performance.md).

## Quick start

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

| Document | Sections |
|---|---|
| [architecture.md](docs/architecture.md) | A overview, B stack, E repo layout, F XDP design, H userspace, API, failure modes |
| [hardware-tuning.md](docs/hardware-tuning.md) | C hardware, D CPU/NUMA/RSS/IRQ strategy |
| [bpf-maps.md](docs/bpf-maps.md) | G map design |
| [feature-schema.md](docs/feature-schema.md) | I features, flow key |
| [ml.md](docs/ml.md) | J models, bot and distributed-attack detection, training, deployment |
| [policy-engine.md](docs/policy-engine.md) | K risk engine, rate limiting, false-positive control, allowlists |
| [storage.md](docs/storage.md) | L ClickHouse schema |
| [observability.md](docs/observability.md) | M metrics and alerts, N dashboard |
| [threat-model.md](docs/threat-model.md) | O threat model |
| [performance.md](docs/performance.md) | P benchmark methodology, Phase 1 numbers |
| [deployment.md](docs/deployment.md) | systemd, privileges, operations |
| [inline-vlan-deployment.md](docs/inline-vlan-deployment.md) | one-NIC VLAN hairpin: switch + server setup, cutover, reproduce |
| [development.md](docs/development.md) | Q roadmap, build, tests, Phase 1 report |

## License

eBPF dataplane: GPL-2.0-only OR BSD-2-Clause. Everything else: Apache-2.0.
See [LICENSE](LICENSE).
