<!-- Sprog: **Dansk** · [English](../EN/observability.md) -->

# M. Metrics og alarmering, N. Dashboard

## M. Prometheus-metrics

**Implementeret i Fase 1 (midlertidigt):** dataplan-tæller-familierne nedenfor
(`xs_rx_*`, `xs_verdict_*`, `xs_l3_*`, `xs_l4_*`, `xs_tcp_flags_*`,
`xs_anomaly_*`, `xs_parse_outcome_*`, `xs_fragment_*`, `xs_vlan_*`,
`xs_ipv6_ext_*`, `xs_dataplane_attached`, `xs_config_flag`) produceres af
`sentinelctl stats --prometheus` via node_exporters textfile-collector, med et
provisioneret Grafana-dashboard og Fase 1-delmængden af alarm-reglerne
(`deploy/monitoring/`, se [deployment.md](deployment.md#monitoring-phase-1-interim-deploymonitoring)).
Alt andet i dette dokument lander med agenten (Fase 4) og Fase 7.

Eksporteret af `sentinel-agent` på `/metrics` (OpenMetrics, `prometheus-client`-crate).
Host-metrics (per-CPU softirq-tid, per-kø NIC-tællere via node_exporters
`ethtool`-collector, hukommelse) kommer fra node_exporter; vi re-eksporterer dem
ikke.

**Kardinalitetsregel:** ingen label må tage angriber-kontrollerede værdier. Der er
ingen per-IP-, per-port- eller per-flow-labels. Top talkers serveres af agent-API'et
og ClickHouse, ikke af Prometheus. Label-værdisæt er lukkede (enum-lignende) eller
afgrænset af konfiguration (`service` ≤ 4 096, typisk titals).

### Dataplan (afledt af BPF-tællere ved hver scrape, monotont)

| Metrik | Type | Labels | Betydning |
|---|---|---|---|
| `xs_rx_packets_total`, `xs_rx_bytes_total` | counter | `iface` | frames set af XDP |
| `xs_verdict_packets_total`, `xs_verdict_bytes_total` | counter | `iface`, `verdict` (pass, drop, tx, redirect) | |
| `xs_dropped_packets_total`, `xs_dropped_bytes_total` | counter | `iface`, `reason` (malformed, bad_tcp_flags, fragment, policy_block, rate_limit, service_budget) | |
| `xs_rate_limited_packets_total` | counter | `iface`, `class` (any, tcp_syn, udp, icmp) | nonconforming pakker |
| `xs_parse_outcome_packets_total` | counter | `iface`, `outcome` (24 værdier, f.eks. `err_tcp_trunc`) | parser-fejl og klassifikationer |
| `xs_l3_packets_total` / `xs_l4_packets_total` | counter | `iface`, `proto` | protokol-blanding |
| `xs_tcp_flags_packets_total` | counter | `iface`, `class` (syn, synack, ack, fin, rst) | |
| `xs_anomaly_packets_total` | counter | `iface`, `kind` (ipv4_options, tcp_bad_flags, udp_len_mismatch, land) | |
| `xs_service_packets_total`, `xs_service_dropped_packets_total` | counter | `service` | per-destination-trafik |
| `xs_ringbuf_drops_total` | counter | `iface` | samples tabt (ring fuld) |
| `xs_xdp_exceptions_total` | counter | `iface` | `XDP_ABORTED`/driver-XDP-fejl, fra et lille BPF-program på `xdp:xdp_exception`-tracepointet |
| `xs_nic_rx_missed_total`, `xs_nic_rx_dropped_total` | counter | `iface` | fra `/sys/class/net/<if>/statistics/{rx_missed_errors,rx_dropped}`: pakker tabt *før* XDP (host for langsom) |

### State (gauges)

| Metrik | Labels | Betydning |
|---|---|---|
| `xs_active_sources`, `xs_active_destinations`, `xs_active_flows` | `iface` | HLL-estimater for seneste vindue |
| `xs_policies_active` | `action`, `origin` (rule, ml, manual) | aktive dynamiske politikker |
| `xs_policy_map_utilization` | `map` | entries / max_entries |
| `xs_service_state` | `service` | 0 normal, 1 suspect, 2 under angreb |
| `xs_service_ddos_score`, `xs_service_anomaly_score` | `service` | seneste scores |
| `xs_service_confidence` | `service` | seneste konfidens |
| `xs_coordinated_attack` | `service` | 1 mens coordinated-attack-signalet er aktivt |
| `xs_circuit_breaker_open` | `service` | 1 mens ML-eskaleringer er frosset |
| `xs_model_info` | `model`, `version`, `schema_hash`, `mode` | konstant 1 (info-metrik) |
| `xs_model_ood_share` | `model` | andel af scorede rækker med out-of-range-features |
| `xs_inference_up` | | 1 hvis seneste request lykkedes |
| `xs_dataplane_attached` | `iface`, `mode` | 1 hvis vores program er tilkoblet i den mode |

### Control plane

| Metrik | Type | Labels |
|---|---|---|
| `xs_collector_tick_duration_seconds` | histogram | `stage` (counters, hll, heavy_hitters, services) |
| `xs_window_to_decision_seconds` | histogram | | vindue slut → politikker skrevet |
| `xs_inference_latency_seconds` | histogram | `model` |
| `xs_inference_timeouts_total` | counter | `model` |
| `xs_policy_updates_total` | counter | `op` (insert, update, delete), `origin` |
| `xs_policy_apply_duration_seconds` | histogram | |
| `xs_policy_map_full_total` | counter | `map` |
| `xs_feedback_total` | counter | `label` (false_positive, true_positive) |
| `xs_ringbuf_samples_total` | counter | | samples forbrugt |
| `xs_sample_queue_dropped_total` | counter | | userspace sample-kø-overløb |
| `xs_clickhouse_rows_total`, `xs_clickhouse_dropped_rows_total`, `xs_clickhouse_insert_errors_total` | counter | `table` |
| `xs_config_reload_failures_total` | counter | |
| `xs_build_info` | gauge | `version`, `git_sha`, `kernel`, `bpf_obj_sha` |

## Alarmering (§20)

Recording-rules omsætter tællere til rates én gang; alarm-regler bruger dem.
Leveres i `deploy/prometheus/xs-alerts.yaml` (Fase 7). Repræsentative regler
(tærskler er standardvalg, tune pr. site):

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

(`$RX_CPUS` substitueres fra deploymentets CPU-plan ved installationstid.)

## Grafana

Provisionerede dashboards (`deploy/grafana/`): **Traffic** (pps/Gbps pr.
interface, verdicts, drop-årsager, protokol-blanding, parse-udfald), **Services**
(per-service-trafik, state, scores), **Mitigation** (aktive politikker efter
handling og oprindelse, policy-churn, map-udnyttelse, circuit breakers),
**Dataplane health** (RX-core softirq %, per-kø-pakker, NIC-drops,
ring-buffer-tab, XDP-exceptions), **Control plane** (tick-varigheder,
window-to-decision-latency, inferens-latency, ClickHouse-writer).

Grafana er operatørens *operations*-view; dashboardet nedenfor er
*security*-viewet (entiteter, events, handlinger).

## N. Dashboard-arkitektur

### Stak

* **React + TypeScript, bygget med Vite til et statisk bundle**, serveret af
  agenten (eller nginx) fra `/ui`. Ikke Next.js: der er intet SEO/SSR-behov, og
  et statisk bundle betyder ingen Node.js-server-proces på en
  sikkerheds-appliance (mindre angrebsflade, intet at patche ved runtime).
* TanStack Query (REST-caching/retries), TanStack Table (virtualiserede
  event-tabeller), **uPlot** til live-tidsserier (renderer tusinder af punkter pr.
  sekund billigt), ECharts til distributions-grafer.
* Datakilder, alle via agent-API'et (browseren taler aldrig med ClickHouse eller
  Prometheus):
  * live: `GET /api/v1/stream` (Server-Sent Events, én besked pr. 1 s vindue,
    ~5–20 KB);
  * tabeller: `/policies`, `/events`, `/attacks`, `/traffic/top`;
  * historik: agent-endpoints bakket af `service_minutes`-rollups.
* Auth: OIDC ved reverse-proxyen; proxyen videregiver identitets-headers kun fra
  et betroet hop. Roller: `viewer` (læs) og `operator` (mitigering, allowlist,
  feedback, model-aktivering). CSRF-tokens på muterende kald, streng
  Content-Security-Policy, ingen tredjeparts-scripts.

### Views

| View | Indhold |
|---|---|
| Overview | aktuel Gbps og pps (in/passeret/droppet), protokol-distribution, DDoS-score og bot-score (fleet-max + per service), aktive angreb, drops efter årsag |
| Traffic | live- og historiske grafer; top-kilder, -destinationer, -destinationsporte (fra heavy hitters) |
| Mitigation | blokerede og rate-limitede kilder med oprindelse, årsag, resterende TTL (live-nedtælling), "fjern"- og "markér falsk positiv"-handlinger |
| Attacks | episode-tidslinje pr. service: vektorer, signatur, peak pps/bps, unikke kilder, collateral (`known_good_drop_share`) |
| Events | detaljeret event-tabel (nedenfor) med filtre på tid, type, kilde, destination, service, handling |
| System | CPU-udnyttelse pr. core (RX vs control plane), RX-kø-udnyttelse, XDP-drops og -exceptions, ring-buffer-tab, ML-latency, model-versioner og -modes |

Event-detalje-kolonner: timestamp, kilde, destination, protokol, service,
trafikvolumen (pps/bps), anomali-score, DDoS-score, bot-score, handling, årsag
(risiko-forklaringen, inkl. de vigtigste bidragende signaler og features),
policy-udløb, model-version(er), og et link til `policy_decisions`-historikken for
entiteten.
