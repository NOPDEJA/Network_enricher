# Network Enricher

A network flow analysis **enrichment engine** built in Go, on top of
[goflow2](https://github.com/netsampler/goflow2). It ingests NetFlow v5/v9, IPFIX,
and sFlow data, enriches the flows (GeoIP, ASN, threat intel, tenant mapping, …),
and forwards the enriched records downstream to ClickHouse.

Think: an open-source [ElastiFlow](https://www.elastiflow.com/) alternative.

```
nflow-generator ──► goflow2 ──► Redpanda ──► [ Go Enricher ] ──► ClickHouse
   (NetFlow v5)     (decode)    (raw-flows)    (this repo)
```

> **Status:** early prototype — Week 3 complete. GeoIP + ASN enrichment is live.
> See [Roadmap](#roadmap) for full plan and progress.

---

## What works today

- **Dev stack** (`docker_compose.yml`): Redpanda, ClickHouse, goflow2, and a
  NetFlow traffic generator, all via `docker compose up`.
- **goflow2** decodes incoming NetFlow and publishes JSON flow records to the
  `raw-flows` Kafka topic on Redpanda.
- **Go consumer** (`main.go`): reads `raw-flows`, deserializes each record into a
  `FlowMessage`, enriches it, and prints a one-line summary per flow. Shuts down
  cleanly on SIGTERM / Ctrl+C.
- **GeoIP + ASN enrichment** (`geoip.go`): every flow tagged with source/destination
  country code, city, coordinates, ASN number, and ASN org name — using MaxMind
  GeoLite2 mmdb files loaded in-memory. Hot-reloads the databases every 24 hours
  without restarting. Private/RFC1918 addresses are labeled `"private"`;
  unallocated bogon addresses are labeled `"unknown"`.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Go](https://go.dev/dl/) 1.21+
- MaxMind GeoLite2 databases (free — sign up at [maxmind.com](https://www.maxmind.com))
  - `GeoLite2-City.mmdb`
  - `GeoLite2-ASN.mmdb`

---

## Quick start

**1. Bring up the stack**

```bash
docker compose -f docker_compose.yml up -d
```

This starts Redpanda (`:9092`), ClickHouse (`:8123` / `:9000`), goflow2
(`:2055` & `:4739` UDP), and the NetFlow generator. The generator immediately
starts sending NetFlow v5 traffic to goflow2, which decodes it and publishes to
the `raw-flows` topic.

**2. Run the enricher**

```bash
# With GeoIP enrichment enabled:
export GEOIP_CITY_PATH=/path/to/GeoLite2-City.mmdb
export GEOIP_ASN_PATH=/path/to/GeoLite2-ASN.mmdb
go run .
```

```powershell
# PowerShell equivalent:
$env:GEOIP_CITY_PATH="C:\path\to\GeoLite2-City.mmdb"
$env:GEOIP_ASN_PATH="C:\path\to\GeoLite2-ASN.mmdb"
go run .
```

GeoIP is **optional** — omit the env vars and the enricher starts without it.

You should see enriched flow records printed as they arrive:

```
connected to Redpanda, reading from raw-flows...
geoip loaded
209.223.38.104:31534 → 77.27.22.123:8475  proto=TCP  bytes=666  src_country=US  dst_country=ES  src_asn=3561  dst_asn=12334
10.154.20.12:9010    → 77.12.190.94:3306  proto=TCP  bytes=586  src_country=private  dst_country=DE  src_asn=0  dst_asn=6805
...
```

Press `Ctrl+C` to stop — the consumer drains and exits cleanly.

**3. Tear down**

```bash
docker compose -f docker_compose.yml down
```

---

## Project layout

| File                 | Purpose                                                              |
|----------------------|----------------------------------------------------------------------|
| `main.go`            | Redpanda consumer, `FlowMessage` + `EnrichedFlow` models, `enrich()` wiring. |
| `geoip.go`           | `GeoStore` — MaxMind mmdb lookup with `sync.RWMutex` hot-reload.    |
| `geoip_test.go`      | Unit tests for private IP detection and GeoStore lookup behavior.    |
| `docker_compose.yml` | Dev stack: Redpanda, ClickHouse, goflow2, nflow-generator.          |
| `goflow2.yaml`       | Standalone goflow2 config (reference; not mounted by compose).       |
| `go.mod` / `go.sum`  | Go module definition and dependency checksums.                       |
| `CLAUDE.md`          | Engineering guidelines for this project.                             |

---

## Configuration

| Setting             | Default / Value          | How to set               |
|---------------------|--------------------------|--------------------------|
| Redpanda broker     | `localhost:9092`         | `main.go`                |
| Consumer group      | `enricher-group`         | `main.go`                |
| Topic               | `raw-flows`              | `main.go` / goflow2      |
| NetFlow listeners   | `:2055`, `:4739`         | `docker_compose.yml`     |
| Flow format         | `json`                   | `docker_compose.yml`     |
| GeoIP city database | _(disabled if unset)_    | `GEOIP_CITY_PATH` env var |
| GeoIP ASN database  | _(disabled if unset)_    | `GEOIP_ASN_PATH` env var  |
| GeoIP refresh interval | 24 hours              | `geoip.go`               |

---

## Running tests

```bash
go test ./...
```

Tests cover private IP detection and GeoStore lookup behavior. No mmdb files required.

---

## Roadmap

The enricher is being built over an 8-week intern plan. Current progress:

- [x] **Week 1** — Go basics + Docker Compose dev stack
- [x] **Week 2** — Redpanda consumer in Go (flows deserialized and printed)
- [x] **Week 3** — GeoIP + ASN enrichment (MaxMind mmdb, hot-reload, unit tests)
- [ ] **Week 4** — Tenant mapping (CIDR radix tree) + threat intel + sFlow expansion
- [ ] **Week 5** — ClickHouse schema + batched native-protocol writer
- [ ] **Week 6** — Flow deduplication + graceful shutdown + Prometheus metrics
- [ ] **Week 7** — Load testing, pprof profiling, worker pool
- [ ] **Week 8** — Documentation + PoC→production gap analysis + handoff

(Graceful shutdown — a Week 6 item — is already in place.)

---

## Key design principles

- **Fail open** — packet loss is worse than enrichment failure. If a lookup
  fails, log a metric and continue; never drop a flow.
- **Stateless, fast enrichment** — flows are stateless records; per-flow
  enrichment must be fast, non-blocking, and idempotent.
- **No blocking I/O in the hot path** — offload DNS/HTTP/DB to async workers.
- **Bounded caches** — every lookup cache has a TTL and max size.
- **Hot-reload without downtime** — lookup tables (GeoIP, tenant config, threat feed)
  refresh in the background behind a `sync.RWMutex`; no restarts needed.
