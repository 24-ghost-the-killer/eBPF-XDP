# L. ClickHouse schema

ClickHouse stores **aggregates and decisions, never raw packets**. Volume at
defaults: 1 row/s per interface, 1 row/s per active service (≤ 4 096),
≤ 40 k source rows / 5 s, capped samples (optional, off by default in
production). Typical ingest is 1–10 k rows/s: a single modest ClickHouse
node, preferably **not** on the appliance itself.

Conventions:
* addresses are `IPv6` (IPv4 stored as `::ffff:a.b.c.d`), one column type,
  one index;
* enumerations are `Enum8` (closed sets owned by our code) or
  `LowCardinality(String)` (open sets such as model versions);
* timestamps `DateTime64(3, 'UTC')` with `CODEC(DoubleDelta, ZSTD)`;
  monotonic counters `CODEC(T64, ZSTD)`; floats `CODEC(Gorilla, ZSTD)`;
* every feature row carries `schema_hash`, so training can select rows
  produced by one feature definition;
* partitions by day; TTLs delete whole parts (`ttl_only_drop_parts = 1`).

The DDL below lives in `deploy/clickhouse/*.sql` (Phase 7) and is applied by
a versioned migration script; the agent refuses to write if the schema
version in `xs.schema_migrations` is older than it expects.

```sql
CREATE DATABASE IF NOT EXISTS xs;

-- 1. Global per-interface windows (1 s) ------------------------------------
CREATE TABLE xs.traffic_windows
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    host            LowCardinality(String),
    iface           LowCardinality(String),
    window_ms       UInt16,
    window_complete UInt8,                        -- 0 if a tick was late/missed
    schema_hash     FixedString(32),
    packets         UInt64 CODEC(T64, ZSTD),
    bytes           UInt64 CODEC(T64, ZSTD),
    drop_packets    UInt64 CODEC(T64, ZSTD),
    drop_bytes      UInt64 CODEC(T64, ZSTD),
    tcp_syn         UInt64 CODEC(T64, ZSTD),
    tcp_synack      UInt64 CODEC(T64, ZSTD),
    tcp_ack         UInt64 CODEC(T64, ZSTD),
    tcp_rst         UInt64 CODEC(T64, ZSTD),
    tcp_fin         UInt64 CODEC(T64, ZSTD),
    udp             UInt64 CODEC(T64, ZSTD),
    icmp            UInt64 CODEC(T64, ZSTD),
    frag            UInt64 CODEC(T64, ZSTD),
    malformed       UInt64 CODEC(T64, ZSTD),
    unique_src      UInt32,
    unique_dst      UInt32,
    unique_flows    UInt32,
    ringbuf_drops   UInt32,
    sample_coverage Float32,
    parse_outcomes  Map(LowCardinality(String), UInt64),  -- parse_* counters
    features        Map(LowCardinality(String), Float32)  -- full feature vector
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, iface, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 2. Per-service windows (1 s): the main training table ---------------------
CREATE TABLE xs.service_windows
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    host            LowCardinality(String),
    service_id      UInt16,
    service         LowCardinality(String),
    window_complete UInt8,
    schema_hash     FixedString(32),
    state           Enum8('normal' = 0, 'suspect' = 1, 'under_attack' = 2),
    packets         UInt64 CODEC(T64, ZSTD),
    bytes           UInt64 CODEC(T64, ZSTD),
    drop_packets    UInt64 CODEC(T64, ZSTD),
    features        Map(LowCardinality(String), Float32),
    -- model outputs for this window (NULL when a model was not run)
    anomaly_score   Nullable(Float32),
    ddos_score      Nullable(Float32),
    ddos_type       LowCardinality(Nullable(String)),
    confidence      Nullable(Float32),
    model_versions  Map(LowCardinality(String), LowCardinality(String))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (service_id, ts)
TTL toDateTime(ts) + INTERVAL 180 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 3. Per-source windows (5 s, heavy hitters only) ---------------------------
CREATE TABLE xs.source_windows
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    host            LowCardinality(String),
    src             IPv6,
    src_prefix      IPv6,                         -- /24 (v4) or /48 (v6), for cohort queries
    top_service_id  UInt16,
    schema_hash     FixedString(32),
    packets         UInt64 CODEC(T64, ZSTD),
    bytes           UInt64 CODEC(T64, ZSTD),
    dropped         UInt64 CODEC(T64, ZSTD),
    features        Map(LowCardinality(String), Float32),
    bot_score       Nullable(Float32),
    action          Enum8('pass' = 0, 'monitor' = 1, 'sample' = 2, 'rate_limit' = 3,
                          'aggressive_rate_limit' = 4, 'temporary_block' = 5),
    INDEX idx_prefix src_prefix TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src, ts)                                 -- "what did this source do"
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 4. Flow summaries (from sampled-flow reconstruction, on eviction) --------
CREATE TABLE xs.flow_summaries
(
    first_seen      DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    last_seen       DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    host            LowCardinality(String),
    iface           LowCardinality(String),
    src             IPv6,
    dst             IPv6,
    sport           UInt16,
    dport           UInt16,
    proto           UInt8,
    sampled_packets UInt32,
    sampled_bytes   UInt64,
    sample_one_in   UInt32,                        -- scale factor at capture time
    tcp_flags_union UInt8,
    size_min        UInt16,
    size_max        UInt16,
    iat_mean_us     Float32,
    iat_cv          Float32,
    INDEX idx_dst dst TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(first_seen)
ORDER BY (src, first_seen)
TTL toDateTime(first_seen) + INTERVAL 14 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 5. Security events (anything an operator may want to look at) ------------
CREATE TABLE xs.security_events
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    event_id        UUID,
    host            LowCardinality(String),
    type            Enum8('anomaly' = 1, 'ddos' = 2, 'bot' = 3, 'scan' = 4,
                          'malformed_flood' = 5, 'policy_applied' = 6,
                          'policy_expired' = 7, 'circuit_breaker' = 8, 'system' = 9),
    severity        Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    src             Nullable(IPv6),
    dst             Nullable(IPv6),
    proto           Nullable(UInt8),
    dport           Nullable(UInt16),
    service         LowCardinality(String),
    pps             Float32,
    bps             Float32,
    anomaly_score   Nullable(Float32),
    ddos_score      Nullable(Float32),
    bot_score       Nullable(Float32),
    confidence      Nullable(Float32),
    action          LowCardinality(String),
    reason          String,                        -- human-readable, from the risk explanation
    policy_id       Nullable(UInt32),
    policy_expires  Nullable(DateTime64(3, 'UTC')),
    model_versions  Map(LowCardinality(String), LowCardinality(String)),
    attack_id       Nullable(UUID),
    INDEX idx_src src TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dst dst TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (type, ts, event_id)
TTL toDateTime(ts) + INTERVAL 400 DAY;

-- 6. Attack episodes (one row per state change; ReplacingMergeTree keeps the latest)
CREATE TABLE xs.attack_events
(
    attack_id       UUID,
    updated_at      DateTime64(3, 'UTC'),
    host            LowCardinality(String),
    service_id      UInt16,
    service         LowCardinality(String),
    started_at      DateTime64(3, 'UTC'),
    ended_at        Nullable(DateTime64(3, 'UTC')),
    vectors         Array(LowCardinality(String)),  -- syn_flood, udp_reflection, ...
    signature       String,                         -- behaviour signature (feature-schema.md)
    peak_pps        Float64,
    peak_bps        Float64,
    unique_sources  UInt32,
    dropped_packets UInt64,
    known_good_drop_share Float32,
    label           Enum8('unlabelled' = 0, 'confirmed' = 1, 'false_positive' = 2, 'lab' = 3)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(started_at)
ORDER BY (service_id, started_at, attack_id);

-- 7. Every policy decision, applied or shadow ------------------------------
CREATE TABLE xs.policy_decisions
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    decision_id     UUID,
    host            LowCardinality(String),
    mode            Enum8('enforce' = 0, 'shadow' = 1),
    origin          Enum8('rule' = 0, 'ml' = 1, 'manual' = 2, 'expiry' = 3, 'feedback' = 4),
    entity_type     Enum8('source' = 0, 'prefix' = 1, 'service' = 2),
    entity          String,                          -- canonical text form
    action_before   LowCardinality(String),
    action_after    LowCardinality(String),
    risk            Float32,
    contributions   Map(LowCardinality(String), Float32), -- noisy-OR factors
    rate_pps        Nullable(UInt32),
    ttl_s           UInt32,
    expires_at      DateTime64(3, 'UTC'),
    policy_id       UInt32,
    model_versions  Map(LowCardinality(String), LowCardinality(String)),
    schema_hash     FixedString(32),
    reason          String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (entity_type, entity, ts)
TTL toDateTime(ts) + INTERVAL 400 DAY;

-- 8. Operator feedback (labels) and audit log -------------------------------
CREATE TABLE xs.feedback
(
    ts          DateTime64(3, 'UTC'),
    event_id    UUID,
    decision_id Nullable(UUID),
    operator    LowCardinality(String),
    label       Enum8('false_positive' = 1, 'true_positive' = 2),
    note        String
)
ENGINE = MergeTree ORDER BY (ts, event_id);

CREATE TABLE xs.audit_log
(
    ts          DateTime64(3, 'UTC'),
    operator    LowCardinality(String),
    action      LowCardinality(String),              -- policy.create, allowlist.delete, model.activate, ...
    request_id  String,
    payload     String,                              -- validated request, JSON
    result      Enum8('ok' = 0, 'rejected' = 1, 'error' = 2)
)
ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY ts;

-- 9. Optional raw samples (debug/forensics; disabled by default) -----------
CREATE TABLE xs.packet_samples
(
    ts        DateTime64(6, 'UTC') CODEC(DoubleDelta, ZSTD),
    host      LowCardinality(String),
    src IPv6, dst IPv6, sport UInt16, dport UInt16,
    proto UInt8, tcp_flags UInt8, ttl UInt8, len UInt16, verdict UInt8, parse_rc UInt8
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 3 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 10. 1-minute rollups for dashboards and long history ---------------------
CREATE TABLE xs.service_minutes
(
    minute        DateTime('UTC'),
    service_id    UInt16,
    packets       SimpleAggregateFunction(sum, UInt64),
    bytes         SimpleAggregateFunction(sum, UInt64),
    drop_packets  SimpleAggregateFunction(sum, UInt64),
    peak_pps      SimpleAggregateFunction(max, Float64),
    max_ddos      SimpleAggregateFunction(max, Nullable(Float32))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (service_id, minute)
TTL minute + INTERVAL 2 YEAR;

CREATE MATERIALIZED VIEW xs.service_minutes_mv TO xs.service_minutes AS
SELECT
    toStartOfMinute(w.ts)                        AS minute,
    w.service_id                                 AS service_id,
    sum(w.packets)                               AS packets,
    sum(w.bytes)                                 AS bytes,
    sum(w.drop_packets)                          AS drop_packets,
    max(toFloat64(w.packets))                    AS peak_pps,   -- 1 s windows: packets per window == pps
    max(w.ddos_score)                            AS max_ddos
-- Qualified with w: the packets alias above would otherwise shadow the
-- column inside max() and nest one aggregate in another.
FROM xs.service_windows AS w
GROUP BY minute, service_id;
```

Index and key rationale:

* `ORDER BY` puts the **most selective, most queried** column first:
  services by `service_id`, sources by `src`, decisions by entity. Time is
  second, so range scans for one entity touch contiguous granules.
* `bloom_filter` skip indexes on addresses serve "everything involving
  address X" queries on tables ordered by something else.
* Feature vectors are `Map(LowCardinality(String), Float32)`: adding a
  feature needs no DDL change, and `schema_hash` says which definition
  produced the row. Training reads maps into columns with polars.
* `ReplacingMergeTree` for attack episodes: the agent re-emits a row on
  every state change; queries use `FINAL` or `argMax(…, updated_at)`.

## Write path

The agent's ClickHouse writer (tokio task) batches per table: flush at
10 000 rows or 1 s, RowBinary over HTTP, `async_insert = 0` (we already
batch). The queue is bounded (60 s or 200 MB, whichever first); on overflow
it drops the oldest batches and increments
`xs_clickhouse_dropped_rows_total`. Detection and mitigation never wait for
ClickHouse.

Credentials: a dedicated `xs_writer` user with `INSERT` on `xs.*` only; the
training pipeline uses `xs_reader` (`SELECT` only); the dashboard never
talks to ClickHouse directly (only through the agent API).
