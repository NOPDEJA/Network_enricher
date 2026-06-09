-- ============================================================
-- Network Enricher — ClickHouse Schema
-- ============================================================

-- Main flow table.
-- Partition by day: queries almost always filter by time range;
-- daily partitions enable efficient partition pruning.
--
-- Order key (tenant_id, timestamp, src_ip, dst_ip): tenant and
-- time-range queries are fast; arbitrary IP scans are slower —
-- acceptable for this use case.
--
-- TTL: drop rows older than 90 days to keep storage bounded.
CREATE TABLE IF NOT EXISTS flows (
    timestamp        DateTime,
    tenant_id        UInt32,
    tenant_name      LowCardinality(String),
    src_ip           String,
    dst_ip           String,
    src_port         UInt32,
    dst_port         UInt32,
    protocol         LowCardinality(String),
    bytes            UInt64,
    packets          UInt64,

    -- GeoIP fields
    src_country      LowCardinality(String),
    src_city         String,
    src_lat          Float64,
    src_lon          Float64,
    src_asn          UInt32,
    src_org          LowCardinality(String),
    dst_country      LowCardinality(String),
    dst_city         String,
    dst_lat          Float64,
    dst_lon          Float64,
    dst_asn          UInt32,
    dst_org          LowCardinality(String),

    -- Threat intelligence
    is_threat_src    UInt8,
    is_threat_dst    UInt8,
    threat_label     LowCardinality(String),

    -- sFlow sampling
    -- is_sampled=1 means bytes/packets are raw sampled values;
    -- expanded_* are the estimated true counts (raw * sampling_rate).
    is_sampled       UInt8,
    sampling_rate    UInt64,
    expanded_bytes   UInt64,
    expanded_packets UInt64,

    exporter_ip      String,
    flow_type        LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 90 DAY DELETE;


-- ============================================================
-- 1-minute rollup
-- SummingMergeTree automatically sums numeric columns on merge,
-- so dashboard queries can hit this table instead of raw flows.
-- ============================================================
CREATE TABLE IF NOT EXISTS flows_1m (
    timestamp    DateTime,
    tenant_id    UInt32,
    src_country  LowCardinality(String),
    dst_country  LowCardinality(String),
    protocol     LowCardinality(String),
    bytes        UInt64,
    packets      UInt64,
    flow_count   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, src_country, dst_country, protocol);

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_1m_mv TO flows_1m AS
SELECT
    toStartOfMinute(timestamp) AS timestamp,
    tenant_id,
    src_country,
    dst_country,
    protocol,
    sum(bytes)   AS bytes,
    sum(packets) AS packets,
    count()      AS flow_count
FROM flows
GROUP BY timestamp, tenant_id, src_country, dst_country, protocol;


-- ============================================================
-- 1-hour rollup — same shape, coarser granularity
-- ============================================================
CREATE TABLE IF NOT EXISTS flows_1h (
    timestamp    DateTime,
    tenant_id    UInt32,
    src_country  LowCardinality(String),
    dst_country  LowCardinality(String),
    protocol     LowCardinality(String),
    bytes        UInt64,
    packets      UInt64,
    flow_count   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, src_country, dst_country, protocol);

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_1h_mv TO flows_1h AS
SELECT
    toStartOfHour(timestamp) AS timestamp,
    tenant_id,
    src_country,
    dst_country,
    protocol,
    sum(bytes)   AS bytes,
    sum(packets) AS packets,
    count()      AS flow_count
FROM flows
GROUP BY timestamp, tenant_id, src_country, dst_country, protocol;
