-- xdp-sentinel ClickHouse schema (Phase 7). Applied idempotently by the agent
-- on startup; the agent refuses to write if xs.schema_migrations is older than
-- it expects. Mirror of docs/storage.md.

CREATE DATABASE IF NOT EXISTS xs;

CREATE TABLE IF NOT EXISTS xs.schema_migrations
(
    version   UInt32,
    applied_at DateTime64(3, 'UTC') DEFAULT now64(3),
    note      String
)
ENGINE = ReplacingMergeTree(applied_at)
ORDER BY version;

-- 1. Global per-interface windows (1 s) --------------------------------------
CREATE TABLE IF NOT EXISTS xs.traffic_windows
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    host            LowCardinality(String),
    iface           LowCardinality(String),
    window_ms       UInt16,
    window_complete UInt8,
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
    parse_outcomes  Map(LowCardinality(String), UInt64),
    features        Map(LowCardinality(String), Float32)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (host, iface, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 2. Per-service windows (1 s): the main training table ----------------------
CREATE TABLE IF NOT EXISTS xs.service_windows
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

-- 3. Per-source windows (5 s, heavy hitters only) ----------------------------
CREATE TABLE IF NOT EXISTS xs.source_windows
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    host            LowCardinality(String),
    src             IPv6,
    src_prefix      IPv6,
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
ORDER BY (src, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1;

-- 4. Flow summaries ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS xs.flow_summaries
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
    sample_one_in   UInt32,
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

-- 5. Security events ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS xs.security_events
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
    reason          String,
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

-- 6. Attack episodes ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS xs.attack_events
(
    attack_id       UUID,
    updated_at      DateTime64(3, 'UTC'),
    host            LowCardinality(String),
    service_id      UInt16,
    service         LowCardinality(String),
    started_at      DateTime64(3, 'UTC'),
    ended_at        Nullable(DateTime64(3, 'UTC')),
    vectors         Array(LowCardinality(String)),
    signature       String,
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

-- 7. Policy decisions (applied or shadow) ------------------------------------
CREATE TABLE IF NOT EXISTS xs.policy_decisions
(
    ts              DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD),
    decision_id     UUID,
    host            LowCardinality(String),
    mode            Enum8('enforce' = 0, 'shadow' = 1),
    origin          Enum8('rule' = 0, 'ml' = 1, 'manual' = 2, 'expiry' = 3, 'feedback' = 4),
    entity_type     Enum8('source' = 0, 'prefix' = 1, 'service' = 2),
    entity          String,
    action_before   LowCardinality(String),
    action_after    LowCardinality(String),
    risk            Float32,
    contributions   Map(LowCardinality(String), Float32),
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

-- 10. 1-minute rollups -------------------------------------------------------
CREATE TABLE IF NOT EXISTS xs.service_minutes
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

CREATE MATERIALIZED VIEW IF NOT EXISTS xs.service_minutes_mv TO xs.service_minutes AS
SELECT
    toStartOfMinute(w.ts)                        AS minute,
    w.service_id                                 AS service_id,
    sum(w.packets)                               AS packets,
    sum(w.bytes)                                 AS bytes,
    sum(w.drop_packets)                          AS drop_packets,
    max(toFloat64(w.packets))                    AS peak_pps,
    max(w.ddos_score)                            AS max_ddos
-- Qualified with w: the packets alias above would otherwise shadow the
-- column inside max() and nest one aggregate in another.
FROM xs.service_windows AS w
GROUP BY minute, service_id;

INSERT INTO xs.schema_migrations (version, note) VALUES (1, 'phase 7 initial schema');
