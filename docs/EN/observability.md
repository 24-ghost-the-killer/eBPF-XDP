<!-- Language: **English** · [Dansk](../DK/observability.md) -->

# M. Metrics and alerting, N. Dashboard

## M. Prometheus metrics

**Implemented in Phase 1 (interim):** the dataplane-counter families below
(`xs_rx_*`, `xs_verdict_*`, `xs_l3_*`, `xs_l4_*`, `xs_tcp_flags_*`,
`xs_anomaly_*`, `xs_parse_outcome_*`, `xs_fragment_*`, `xs_vlan_*`,
`xs_ipv6_ext_*`, `xs_dataplane_attached`, `xs_config_flag`) are produced by
`sentinelctl stats --prometheus` via node_exporter's textfile collector,
with a provisioned Grafana dashboard and the Phase 1 subset of the alert
rules (`deploy/monitoring/`, see [deployment.md](deployment.md#monitoring-phase-1-interim-deploymonitoring)).
Everything else in this document lands with the agent (Phase 4) and
Phase 7.

Exported by `sentinel-agent` at `/metrics` (OpenMetrics, `prometheus-client`
crate). Host metrics (per-CPU softirq time, per-queue NIC counters via
node_exporter's `ethtool` collector, memory) come from node_exporter; we do
not re-export them.

**Cardinality rule:** no label may take attacker-controlled values. There
are no per-IP, per-port or per-flow labels. Top talkers are served by the
agent API and ClickHouse, not by Prometheus. Label value sets are closed
(enum-like) or bounded by configuration (`service` ≤ 4 096, typically tens).

### Dataplane (derived from BPF counters every scrape, monotonic)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `xs_rx_packets_total`, `xs_rx_bytes_total` | counter | `iface` | frames seen by XDP |
| `xs_verdict_packets_total`, `xs_verdict_bytes_total` | counter | `iface`, `verdict` (pass, drop, tx, redirect) | |
| `xs_dropped_packets_total`, `xs_dropped_bytes_total` | counter | `iface`, `reason` (malformed, bad_tcp_flags, fragment, policy_block, rate_limit, service_budget) | |
| `xs_rate_limited_packets_total` | counter | `iface`, `class` (any, tcp_syn, udp, icmp) | nonconforming packets |
| `xs_parse_outcome_packets_total` | counter | `iface`, `outcome` (24 values, e.g. `err_tcp_trunc`) | parser errors and classifications |
| `xs_l3_packets_total` / `xs_l4_packets_total` | counter | `iface`, `proto` | protocol mix |
| `xs_tcp_flags_packets_total` | counter | `iface`, `class` (syn, synack, ack, fin, rst) | |
| `xs_anomaly_packets_total` | counter | `iface`, `kind` (ipv4_options, tcp_bad_flags, udp_len_mismatch, land) | |
| `xs_service_packets_total`, `xs_service_dropped_packets_total` | counter | `service` | per-destination traffic |
| `xs_ringbuf_drops_total` | counter | `iface` | samples lost (ring full) |
| `xs_xdp_exceptions_total` | counter | `iface` | `XDP_ABORTED`/driver XDP errors, from a tiny BPF program on the `xdp:xdp_exception` tracepoint |
| `xs_nic_rx_missed_total`, `xs_nic_rx_dropped_total` | counter | `iface` | from `/sys/class/net/<if>/statistics/{rx_missed_errors,rx_dropped}`: packets lost *before* XDP (host too slow) |

### State (gauges)

| Metric | Labels | Meaning |
|---|---|---|
| `xs_active_sources`, `xs_active_destinations`, `xs_active_flows` | `iface` | HLL estimates for the last window |
| `xs_policies_active` | `action`, `origin` (rule, ml, manual) | active dynamic policies |
| `xs_policy_map_utilization` | `map` | entries / max_entries |
| `xs_service_state` | `service` | 0 normal, 1 suspect, 2 under attack |
| `xs_service_ddos_score`, `xs_service_anomaly_score` | `service` | latest scores |
| `xs_service_confidence` | `service` | latest confidence |
| `xs_coordinated_attack` | `service` | 1 while the coordinated-attack signal is active |
| `xs_circuit_breaker_open` | `service` | 1 while ML escalations are frozen |
| `xs_model_info` | `model`, `version`, `schema_hash`, `mode` | constant 1 (info metric) |
| `xs_model_ood_share` | `model` | share of scored rows with out-of-range features |
| `xs_inference_up` | | 1 if the last request succeeded |
| `xs_dataplane_attached` | `iface`, `mode` | 1 if our program is attached in that mode |

### Control plane

| Metric | Type | Labels |
|---|---|---|
| `xs_collector_tick_duration_seconds` | histogram | `stage` (counters, hll, heavy_hitters, services) |
| `xs_window_to_decision_seconds` | histogram | | window end → policies written |
| `xs_inference_latency_seconds` | histogram | `model` |
| `xs_inference_timeouts_total` | counter | `model` |
| `xs_policy_updates_total` | counter | `op` (insert, update, delete), `origin` |
| `xs_policy_apply_duration_seconds` | histogram | |
| `xs_policy_map_full_total` | counter | `map` |
| `xs_feedback_total` | counter | `label` (false_positive, true_positive) |
| `xs_ringbuf_samples_total` | counter | | samples consumed |
| `xs_sample_queue_dropped_total` | counter | | userspace sample queue overflow |
| `xs_clickhouse_rows_total`, `xs_clickhouse_dropped_rows_total`, `xs_clickhouse_insert_errors_total` | counter | `table` |
| `xs_config_reload_failures_total` | counter | |
| `xs_build_info` | gauge | `version`, `git_sha`, `kernel`, `bpf_obj_sha` |

## Alerting (§20)

Recording rules turn counters into rates once; alert rules use them.
Shipped in `deploy/prometheus/xs-alerts.yaml` (Phase 7). Representative
rules (thresholds are defaults, tune per site):

```yaml
groups:
- name: xs-recording
  rules:
  - record: xs:rx_pps:rate1m
    expr: sum by (iface) (rate(xs_rx_packets_total[1m]))
  - record: xs:rx_bps:rate1m
    expr: 8 * sum by (iface) (rate(xs_rx_bytes_total[1m]))
  - record: xs:syn_pps:rate1m
    expr: sum by (iface) (rate(xs_tcp_flags_packets_total{class="syn"}[1m]))
  - record: xs:ack_pps:rate1m
    expr: sum by (iface) (rate(xs_tcp_flags_packets_total{class="ack"}[1m]))
  - record: xs:udp_pps:rate1m
    expr: sum by (iface) (rate(xs_l4_packets_total{proto="udp"}[1m]))

- name: xs-traffic
  rules:
  - alert: TrafficSpike
    expr: xs:rx_pps:rate1m > 3 * avg_over_time(xs:rx_pps:rate1m[1h] offset 1d) and xs:rx_pps:rate1m > 100000
    for: 2m
    labels: {severity: warning}
  - alert: SustainedDDoS
    expr: max by (service) (xs_service_state) == 2
    for: 5m
    labels: {severity: critical}
  - alert: SynFlood
    expr: xs:syn_pps:rate1m > 50000 and xs:syn_pps:rate1m > 10 * (xs:ack_pps:rate1m + 1)
    for: 1m
    labels: {severity: critical}
  - alert: UdpFlood
    expr: xs:udp_pps:rate1m > 5 * avg_over_time(xs:udp_pps:rate1m[1h] offset 1w) and xs:udp_pps:rate1m > 200000
    for: 1m
    labels: {severity: critical}
  - alert: AbnormalDestinationTraffic
    expr: xs_service_anomaly_score > 0.9 and xs_service_confidence > 0.7
    for: 2m
    labels: {severity: warning}
  - alert: CoordinatedSourceActivity
    expr: xs_coordinated_attack == 1
    for: 1m
    labels: {severity: critical}

- name: xs-health
  rules:
  - alert: ModelConfidenceAnomaly
    expr: xs_model_ood_share > 0.2 or avg_over_time(xs_service_confidence[30m]) < 0.3
    for: 10m
    labels: {severity: warning}
  - alert: InferenceDown
    expr: xs_inference_up == 0
    for: 2m
    labels: {severity: warning}      # deterministic protection continues
  - alert: CollectorOverload
    expr: histogram_quantile(0.99, sum by (le) (rate(xs_collector_tick_duration_seconds_bucket[5m]))) > 0.5
    for: 5m
    labels: {severity: warning}
  - alert: RingbufLoss
    expr: sum(rate(xs_ringbuf_drops_total[5m])) > 0
    for: 5m
    labels: {severity: warning}
  - alert: RxCpuSaturation
    expr: avg by (instance) (rate(node_cpu_seconds_total{mode="softirq", cpu=~"$RX_CPUS"}[1m])) > 0.9
    for: 2m
    labels: {severity: critical}
  - alert: HostDroppingPackets          # packets lost before XDP: resource exhaustion
    expr: sum by (iface) (rate(xs_nic_rx_missed_total[1m]) + rate(xs_nic_rx_dropped_total[1m])) > 1000
    for: 1m
    labels: {severity: critical}
  - alert: PolicyMapNearlyFull
    expr: xs_policy_map_utilization > 0.9
    for: 1m
    labels: {severity: critical}
  - alert: PolicyCircuitBreakerOpen
    expr: xs_circuit_breaker_open == 1
    labels: {severity: critical}
  - alert: DataplaneNotAttached
    expr: xs_dataplane_attached{mode="native"} == 0
    for: 30s
    labels: {severity: critical}
  - alert: AgentDown
    expr: up{job="xdp-sentinel"} == 0
    for: 1m
    labels: {severity: critical}     # dataplane keeps running; policies expire on TTL
  - alert: ClickHouseWriteFailing
    expr: rate(xs_clickhouse_dropped_rows_total[5m]) > 0
    for: 5m
    labels: {severity: warning}
```

(`$RX_CPUS` is substituted from the deployment's CPU plan at install time.)

## Grafana

Provisioned dashboards (`deploy/grafana/`): **Traffic** (pps/Gbps per
interface, verdicts, drop reasons, protocol mix, parse outcomes), **Services**
(per-service traffic, state, scores), **Mitigation** (active policies by
action and origin, policy churn, map utilisation, circuit breakers),
**Dataplane health** (RX-core softirq %, per-queue packets, NIC drops,
ring-buffer loss, XDP exceptions), **Control plane** (tick durations,
window-to-decision latency, inference latency, ClickHouse writer).

Grafana is the operator's *operations* view; the dashboard below is the
*security* view (entities, events, actions).

## N. Dashboard architecture

### Stack

* **React + TypeScript, built with Vite into a static bundle**, served by
  the agent (or nginx) from `/ui`. Not Next.js: there is no SEO/SSR need,
  and a static bundle means no Node.js server process on a security
  appliance (smaller attack surface, nothing to patch at runtime).
* TanStack Query (REST caching/retries), TanStack Table (virtualised event
  tables), **uPlot** for live time series (renders thousands of points per
  second cheaply), ECharts for distribution charts.
* Data sources, all via the agent API (the browser never talks to
  ClickHouse or Prometheus):
  * live: `GET /api/v1/stream` (Server-Sent Events, one message per 1 s
    window, ~5–20 KB);
  * tables: `/policies`, `/events`, `/attacks`, `/traffic/top`;
  * history: agent endpoints backed by `service_minutes` rollups.
* Auth: OIDC at the reverse proxy; the proxy passes identity headers from a
  trusted hop only. Roles: `viewer` (read) and `operator` (mitigation,
  allowlist, feedback, model activation). CSRF tokens on mutating calls,
  strict Content-Security-Policy, no third-party scripts.

### Views

| View | Content |
|---|---|
| Overview | current Gbps and pps (in/passed/dropped), protocol distribution, DDoS score and bot score (fleet max + per service), active attacks, drops by reason |
| Traffic | live and historical charts; top sources, destinations, destination ports (from heavy hitters) |
| Mitigation | blocked and rate-limited sources with origin, reason, remaining TTL (live countdown), "remove" and "mark false positive" actions |
| Attacks | episode timeline per service: vectors, signature, peak pps/bps, unique sources, collateral (`known_good_drop_share`) |
| Events | detailed event table (below) with filters on time, type, source, destination, service, action |
| System | CPU utilisation per core (RX vs control plane), RX-queue utilisation, XDP drops and exceptions, ring-buffer loss, ML latency, model versions and modes |

Event detail columns: timestamp, source, destination, protocol, service,
traffic volume (pps/bps), anomaly score, DDoS score, bot score, action,
reason (the risk explanation, including the top contributing signals and
features), policy expiration, model version(s), and a link to the
`policy_decisions` history for the entity.
