# Network Enricher

A network flow analysis **enrichment engine** built in Go, on top of
[goflow2](https://github.com/netsampler/goflow2). It ingests NetFlow v5/v9, IPFIX,
and sFlow data, enriches each flow through a multi-stage pipeline, and writes
enriched records to ClickHouse.

Think: an open-source [ElastiFlow](https://www.elastiflow.com/) alternative.

```
nflow-generator ──► goflow2 ──► Redpanda ──► [ Go Enricher ] ──► ClickHouse
   (NetFlow v5)     (decode)    (raw-flows)    (this repo)
```

> **Status:** Week 7 of 8 complete — fully enriched flows reaching ClickHouse,
> worker pool live, Prometheus metrics and pprof available.

---

## Pipeline stages

```
Redpanda (raw-flows)
  └─► Dedup (LRU, 7-tuple, 60 s TTL)
        └─► Worker pool (N × NumCPU goroutines)
              ├─► GeoIP + ASN  (MaxMind GeoLite2, hot-reload 24 h)
              ├─► Threat intel (Feodo Tracker CSV, hot-reload 1 h)
              ├─► Tenant mapping (CIDR radix tree, hot-reload 5 min)
              └─► sFlow expansion (bytes × sampling_rate)
                    └─► BatchWriter → ClickHouse (50 k rows or 1 s, whichever first)
```

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Go](https://go.dev/dl/) 1.24+
- MaxMind GeoLite2 databases (free — sign up at [maxmind.com](https://www.maxmind.com))
  - `GeoLite2-City.mmdb`
  - `GeoLite2-ASN.mmdb`

### Two-machine setup (recommended)

The Docker stack (Redpanda + ClickHouse + goflow2 + nflow-generator) is resource-heavy
(~3–6 GB RAM). Running it on a separate machine keeps your dev box free for Go tooling.

Point the enricher at the infra machine with `REDPANDA_ADDR` and `CLICKHOUSE_ADDR`
(see [Configuration](#configuration) below).

---

## Quick start

**1. Bring up the stack**

```bash
docker compose -f docker_compose.yml up -d
```

Starts Redpanda (`:9092`), ClickHouse (`:9000` / `:8123`), goflow2 (`:2055` UDP),
and nflow-generator. The generator immediately sends NetFlow v5 to goflow2, which
decodes and publishes JSON records to the `raw-flows` topic.

**2. Run the enricher**

```bash
# Minimal — no GeoIP, writes to stdout
go run .

# Full enrichment to ClickHouse (on a separate infra machine at 192.168.1.50):
export REDPANDA_ADDR=192.168.1.50:9092
export CLICKHOUSE_ADDR=192.168.1.50:9000
export GEOIP_CITY_PATH=/path/to/GeoLite2-City.mmdb
export GEOIP_ASN_PATH=/path/to/GeoLite2-ASN.mmdb
export TENANT_CONFIG_PATH=/path/to/tenants.yaml
go run .
```

```powershell
# PowerShell equivalent:
$env:REDPANDA_ADDR="192.168.1.50:9092"
$env:CLICKHOUSE_ADDR="192.168.1.50:9000"
$env:GEOIP_CITY_PATH="C:\path\to\GeoLite2-City.mmdb"
$env:GEOIP_ASN_PATH="C:\path\to\GeoLite2-ASN.mmdb"
go run .
```

Startup output:

```
metrics server listening on :9090
connected to Redpanda, reading from raw-flows (workers=16)...
geoip loaded
tenant config loaded
threat feed loaded: 1423 IPs
clickhouse schema ready
```

**3. Observe**

- Prometheus metrics: `http://localhost:9090/metrics`
- pprof: `http://localhost:9090/debug/pprof/`
- CPU profile: `go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30`

**4. Tear down**

```bash
docker compose -f docker_compose.yml down
```

---

## Project layout

| File | Purpose |
|---|---|
| `main.go` | Kafka consumer, `FlowMessage` / `EnrichedFlow` models, `enrich()` pipeline wiring, worker pool |
| `geoip.go` | `GeoStore` — MaxMind mmdb lookup, `sync.RWMutex` hot-reload |
| `geoip_test.go` | Unit tests for private IP detection and GeoStore lookup |
| `tenant.go` | `TenantStore` — CIDR radix tree (cidranger), YAML config, hot-reload |
| `tenant_test.go` | Unit tests for CIDR lookup and longest-prefix matching |
| `threat.go` | `ThreatStore` — Feodo Tracker CSV download, IP→label map, hot-reload |
| `threat_test.go` | Unit tests for threat label lookup and CSV parsing |
| `dedup.go` | `DedupStore` — 7-tuple LRU dedup with TTL (hashicorp/golang-lru v2) |
| `dedup_test.go` | Unit tests for dedup hit/miss, TTL expiry, exporter distinction |
| `batchwriter.go` | `BatchWriter` — ClickHouse native batch API, count+time dual-trigger flush, schema DDL |
| `metrics.go` | Prometheus counters/gauge definitions, `/metrics` + pprof HTTP server |
| `bench_test.go` | Benchmarks for `enrich()`, dedup hit, dedup miss |
| `docker_compose.yml` | Dev stack: Redpanda, ClickHouse, goflow2, nflow-generator |
| `go.mod` / `go.sum` | Module definition and dependency checksums |
| `CLAUDE.md` | Engineering guidelines for this project |

---

## Configuration

All settings are controlled via environment variables. Everything is optional —
unset variables fall back to safe defaults, and enrichers that can't initialize
(e.g. missing GeoIP files) fail open and log a warning rather than crashing.

| Variable | Default | Description |
|---|---|---|
| `REDPANDA_ADDR` | `localhost:9092` | Kafka/Redpanda broker address |
| `CLICKHOUSE_ADDR` | `localhost:9000` | ClickHouse native protocol address |
| `CLICKHOUSE_DB` | `default` | ClickHouse database |
| `CLICKHOUSE_USER` | `default` | ClickHouse username |
| `CLICKHOUSE_PASSWORD` | _(empty)_ | ClickHouse password |
| `GEOIP_CITY_PATH` | _(disabled)_ | Path to `GeoLite2-City.mmdb` |
| `GEOIP_ASN_PATH` | _(disabled)_ | Path to `GeoLite2-ASN.mmdb` |
| `TENANT_CONFIG_PATH` | _(disabled)_ | Path to tenant YAML config |
| `THREAT_FEED_URL` | Feodo Tracker CSV | Override threat intel feed URL |
| `DEDUP_SIZE` | `1000000` | Max entries in the dedup LRU |
| `DEDUP_TTL_SECONDS` | `60` | Seconds before a flow 7-tuple expires from dedup |
| `ENRICH_WORKERS` | `runtime.NumCPU()` | Number of parallel enrichment workers |
| `METRICS_ADDR` | `:9090` | Address for Prometheus `/metrics` and pprof |

### Tenant config format (`tenants.yaml`)

```yaml
tenants:
  - id: 1
    name: "corp-network"
    subnets:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
  - id: 2
    name: "guest-wifi"
    subnets:
      - "192.168.100.0/24"
```

---

## ClickHouse schema

The enricher auto-creates tables on startup (no manual DDL needed):

| Table | Engine | Purpose |
|---|---|---|
| `flows` | `MergeTree` | Raw enriched flows, 90-day TTL, partitioned by day |
| `flows_1m` | `SummingMergeTree` | Per-minute aggregates (bytes, packets, flow count) |
| `flows_1h` | `SummingMergeTree` | Per-hour aggregates |

Materialized views (`flows_1m_mv`, `flows_1h_mv`) populate the aggregate tables automatically.

---

## Running tests and benchmarks

```bash
# Unit tests
go test ./...

# Benchmarks (3 s each)
go test -bench=. -benchmem -benchtime=3s ./...
```

Benchmark baselines on Intel i7-12650H:

| Benchmark | ns/op | allocs/op |
|---|---|---|
| `BenchmarkEnrich` (nil stores) | 42 | 0 |
| `BenchmarkDedupHit` | 159 | 0 |
| `BenchmarkDedupMiss` | 2,692 | 1 |

---

## Prometheus metrics

| Metric | Type | Description |
|---|---|---|
| `enricher_flows_received_total` | Counter | Flows read from Kafka |
| `enricher_flows_deduplicated_total` | Counter | Flows dropped as 7-tuple duplicates |
| `enricher_flows_written_total` | Counter | Flows forwarded to ClickHouse or stdout |
| `enricher_threat_hits_total{direction}` | Counter | Flows matching threat intel (`src`/`dst`) |
| `enricher_clickhouse_flushes_total` | Counter | ClickHouse batch flush operations |
| `enricher_clickhouse_rows_written_total` | Counter | Rows written to ClickHouse |
| `enricher_threat_ips_loaded` | Gauge | Current count of IPs in the threat store |

---

## Roadmap

- [x] **Week 1** — Docker Compose dev stack (Redpanda, ClickHouse, goflow2, nflow-generator)
- [x] **Week 2** — Redpanda consumer, `FlowMessage` struct, graceful shutdown
- [x] **Week 3** — GeoIP + ASN enrichment (MaxMind mmdb, hot-reload, unit tests)
- [x] **Week 4** — Tenant mapping (CIDR radix tree) + threat intel (Feodo CSV) + sFlow expansion
- [x] **Week 5** — ClickHouse schema + batched native-protocol writer
- [x] **Week 6** — Flow deduplication (LRU) + Prometheus metrics
- [x] **Week 7** — Worker pool (parallel enrichment) + pprof + benchmarks
- [ ] **Week 8** — Documentation + PoC→production gap analysis

---

## Key design principles

- **Fail open** — packet loss is worse than enrichment failure. If a lookup fails, log and continue; never drop a flow.
- **Stateless enrichment** — per-flow enrichment is fast, non-blocking, and idempotent.
- **No blocking I/O in the hot path** — GeoIP and threat lookups are in-memory; ClickHouse writes are batched and async.
- **Bounded caches** — every lookup cache has a TTL and a max size; no unbounded growth.
- **Hot-reload without downtime** — GeoIP, tenant config, and threat feed refresh behind a `sync.RWMutex`; no restarts needed.
