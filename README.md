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

> **Status:** Week 8 complete — PoC finished. See [Gap Analysis](#gap-analysis-poc--production) before promoting to production.

---

## Pipeline stages

```
Redpanda (raw-flows)
  └─► Reader pool (KAFKA_READERS readers in one consumer group, split across partitions)
        └─► Worker pool (ENRICH_WORKERS goroutines)
              ├─► JSON decode (goccy/go-json)
              ├─► Dedup (16-shard LRU, 7-tuple, 60 s TTL)
              ├─► GeoIP + ASN  (MaxMind GeoLite2, hot-reload 24 h)
              ├─► Threat intel (Feodo Tracker CSV, hot-reload 1 h)
              ├─► Tenant mapping (CIDR radix tree, hot-reload 5 min)
              └─► Sampling expansion (bytes × sampling_rate, sFlow + sampled NetFlow/IPFIX)
                    └─► BatchWriter → ClickHouse (50 k rows or 1 s, whichever first)
```

Decode and dedup run *inside* the worker pool (not on the reader), so they spread
across all cores rather than bottlenecking a single goroutine.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Go](https://go.dev/dl/) 1.26+
- MaxMind GeoLite2 databases (free — sign up at [maxmind.com](https://www.maxmind.com))
  - `GeoLite2-City.mmdb`
  - `GeoLite2-ASN.mmdb`

### Two-machine setup (recommended)

The Docker stack (Redpanda + ClickHouse + goflow2 + nflow-generator) is resource-heavy
(~3–6 GB RAM). Running it on a separate machine keeps your dev box free for Go tooling.

**On the infra machine** — export its LAN IP so Redpanda advertises the right address
to remote clients (without this, a remote client connects and gets redirected to
`localhost`, which fails):

```bash
cat > .env <<EOF
REDPANDA_EXTERNAL_ADDR=<INFRA_IP>          # ← the infra machine's LAN IP
CLICKHOUSE_PASSWORD=<choose-a-password>    # empty passwords are rejected for remote connections
EOF
docker compose -f docker_compose.yml up -d
```

**On the dev machine** — point the enricher at the infra machine:

```bash
export REDPANDA_ADDR=<INFRA_IP>:9092
export CLICKHOUSE_ADDR=<INFRA_IP>:9000
export CLICKHOUSE_PASSWORD=<same-password>
go run .
```

---

## Quick start

**1. Bring up the stack**

```bash
docker compose -f docker_compose.yml up -d
```

Starts Redpanda (`:9092`), ClickHouse (`:9000` / `:8123`), goflow2 (NetFlow/IPFIX
on `:2055` + `:4739` UDP, sFlow on `:6343` UDP), and nflow-generator. The generator
immediately sends NetFlow v5 to goflow2, which decodes and publishes JSON records
to the `raw-flows` topic.

**2. Run the enricher**

```bash
# Minimal — no GeoIP, writes to stdout
go run .

# Full enrichment to ClickHouse (on a separate infra machine at <INFRA_IP>):
export REDPANDA_ADDR=<INFRA_IP>:9092
export CLICKHOUSE_ADDR=<INFRA_IP>:9000
export GEOIP_CITY_PATH=/path/to/GeoLite2-City.mmdb
export GEOIP_ASN_PATH=/path/to/GeoLite2-ASN.mmdb
export TENANT_CONFIG_PATH=/path/to/tenants.yaml
go run .
```

```powershell
# PowerShell equivalent:
$env:REDPANDA_ADDR="<INFRA_IP>:9092"
$env:CLICKHOUSE_ADDR="<INFRA_IP>:9000"
$env:GEOIP_CITY_PATH="C:\path\to\GeoLite2-City.mmdb"
$env:GEOIP_ASN_PATH="C:\path\to\GeoLite2-ASN.mmdb"
go run .
```

Startup output:

```
metrics server listening on :9090
connected to Redpanda, reading from raw-flows (readers=1, workers=16)...
geoip loaded
tenant config loaded
threat feed loaded: 1423 IPs
clickhouse schema ready
```

**3. Observe**

- Prometheus metrics: `http://localhost:9090/metrics`
- pprof: `http://localhost:9090/debug/pprof/`
- CPU profile: `go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30`
- **Grafana dashboard: `http://localhost:3000`** — flows/sec, bytes/sec, protocol mix,
  top destination countries, top talkers, and top destination orgs (ASN), straight
  off the ClickHouse `flows` / `flows_1m` tables. The stack auto-provisions the
  ClickHouse datasource and the "Network Enricher — Flows" dashboard on first start
  (anonymous admin, no login). Default time range is the last 30 days; if panels are
  still empty, widen it further — they only show data the enricher has already written.

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
| `pseudonym.go` | `Tokenizer` — HMAC-SHA256 pseudonymization of usernames/MACs/hostnames, fail-closed key load |
| `npslog.go` | NPS DTS-XML RADIUS accounting parser → tokenized `RadiusEvent` |
| `dhcplog.go` | Windows DHCP audit-log parser → tokenized `DhcpEvent` |
| `identity.go` | `IdentityStore` — ip→mac→user current-state join, hot-path `Lookup`, file poller, ClickHouse event writer |
| `pseudonym_test.go` / `npslog_test.go` / `dhcplog_test.go` / `identity_test.go` | Identity unit + golden tests (`testdata/nps`, `testdata/dhcp` fixtures) |
| `dedup.go` | `DedupStore` — 7-tuple dedup, 16-shard LRU with TTL (hashicorp/golang-lru v2) |
| `dedup_test.go` | Unit tests for dedup hit/miss, TTL expiry, exporter distinction |
| `batchwriter.go` | `BatchWriter` — ClickHouse native batch API, count+time dual-trigger flush, schema DDL |
| `metrics.go` | Prometheus counters/gauge definitions, `/metrics` + pprof HTTP server |
| `enrich_test.go` | Unit tests for sampling expansion (sFlow + NetFlow/IPFIX) |
| `bench_test.go` | Benchmarks for `enrich()`, dedup hit, dedup miss |
| `loadtest_test.go` | Per-stage load-test benchmarks: JSON decode, real-store enrich, serial + parallel consume path |
| `cmd/loadgen/` | Standalone producer that floods `raw-flows` with high-cardinality synthetic NetFlow for end-to-end load testing |
| `cmd/trace/` | Read-only forensic CLI: query ClickHouse for which internal host reached a given external destination around a time |
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
| `IDENTITY_TOKEN_KEY_FILE` | _(disabled)_ | Path to the HMAC key file for identity pseudonymization. **Required** to enable identity; empty/missing keeps identity off (fail closed) |
| `IDENTITY_NPS_DIR` | _(disabled)_ | Directory of NPS DTS-XML accounting logs to tail |
| `IDENTITY_DHCP_DIR` | _(disabled)_ | Directory of Windows DHCP audit logs to tail |
| `IDENTITY_MAX_LEASE` | `24h` | Max age a DHCP lease is trusted without renewal (Go duration) |
| `IDENTITY_MAX_SESSION` | `24h` | Idle bound on a RADIUS session with no Stop (Go duration) |
| `DEDUP_SIZE` | `1000000` | Max entries in the dedup LRU |
| `DEDUP_TTL_SECONDS` | `60` | Seconds before a flow 7-tuple expires from dedup |
| `DEDUP_DISABLE` | `false` | Bypass dedup entirely (load-test only — lets every flow reach enrich+write) |
| `ENRICH_WORKERS` | `runtime.NumCPU()` | Number of parallel enrichment workers |
| `KAFKA_READERS` | `1` | Kafka reader goroutines in the consumer group; set ≥ partitions of `raw-flows` to parallelize ingest |
| `METRICS_ADDR` | `:9090` | Address for Prometheus `/metrics` and pprof |
| `LOG_FORMAT` | `text` | Structured log format: `text` (key=value, dev) or `json` (searchable, production) |
| `LOG_LEVEL` | `info` | Minimum log level: `debug`, `info`, `warn`, `error`. `debug` also prints per-flow records when ClickHouse is unavailable |

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

### Identity enrichment (scaffold)

Adds the **"who"** side to flows for campus-WiFi forensics. MUIC WiFi
authenticates via 802.1X against Microsoft NPS (RADIUS), but RADIUS accounting
carries only the client's **MAC**, never its IP. So identity is a two-hop join
on the MAC:

```
flow src/dst IP  --(DHCP lease)-->  MAC  --(RADIUS session)-->  username
```

`identity.go` keeps a small in-memory *current-state* view — `ip → macToken`
from the DHCP audit log, `macToken → userToken` from the NPS accounting log —
and a poller tails both log directories every 30 s (tracking per-file byte
offsets, re-reading from 0 on rotation). Each flow does two cheap `RWMutex` map
reads to stamp four token columns (`src_mac_token`, `src_user_token`,
`dst_mac_token`, `dst_user_token`); both directions are resolved because the
client is the source outbound and the destination on the return half. The raw
events are also appended to `identity_dhcp_events` / `identity_radius_events` in
ClickHouse as the forensic source of truth.

**Privacy — pseudonymous only ("instant noodle").** Usernames, MACs, and
hostnames are **never** stored in the clear. Each is replaced at parse time by
`token = hex(HMAC-SHA256(key, normalize(id)))[:32]`, so the logs never instantly
reveal who — resolving a token back to a person requires the secret key held
outside the pipeline. Normalization collapses every notation of one identifier
to one token (MAC separators stripped and lowercased; `DOMAIN\user` / `user@realm`
reduced to `user`), which is exactly what lets a DHCP MAC join a RADIUS MAC.

**Fail closed** (the one deliberate inversion of the project's fail-open rule):
if `IDENTITY_TOKEN_KEY_FILE` is missing or empty the entire identity subsystem
stays disabled and no raw identifier can ever be written — but **flows keep
flowing** untouched either way. Identity turns on only when the key file *and*
at least one of `IDENTITY_NPS_DIR` / `IDENTITY_DHCP_DIR` are set.

Run the identity tests (they use synthetic fixtures under `testdata/nps` and
`testdata/dhcp`, no external services):

```bash
go test -run 'Tokenizer|NPS|DHCP|Identity|RADIUS|Lease|Roam|Ingest|NoRaw|FailOpen' -v .
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

## Forensic attribution (`cmd/trace`)

`cmd/trace` is a read-only CLI that queries the `flows` table to answer:
**"which internal host reached a given external destination (e.g. Facebook) around time T?"**
It uses the same `CLICKHOUSE_*` env vars as the enricher.

```bash
# By friendly service name, ±15m around a time:
go run ./cmd/trace -service facebook -around "2026-06-16 14:30:00" -window 15m

# By ASN, explicit window, narrowed to one suspect source:
go run ./cmd/trace -dst-asn 15169 -from "2026-06-16 00:00:00" -to "2026-06-16 23:59:59" -src-ip 10.3.7.21

# By destination org substring (case-insensitive), as JSON lines:
go run ./cmd/trace -dst-org cloudflare -around 2026-06-16 -json
```

Pick exactly one destination (`-service`, `-dst-asn`, `-dst-org`, `-dst-ip`) and one
time window (`-around` + optional `-window`, default `10m`; or `-from`/`-to`).
**All times — both the flags and the displayed timestamps — are UTC**, matching how
ClickHouse stores flow timestamps (a window in the wrong zone would silently miss flows).
`-service` resolves friendly names to ASNs (facebook/meta/instagram/whatsapp → 32934,
google/youtube → 15169, cloudflare → 13335). It is equivalent to this hand-written SQL:

```sql
SELECT timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes,
       dst_asn, dst_org, exporter_ip, tenant_name
FROM flows
WHERE timestamp BETWEEN ? AND ?
  AND dst_asn IN (?)          -- or positionCaseInsensitive(dst_org, ?) > 0, or dst_ip = ?
ORDER BY timestamp
LIMIT ?;
```

The time window drives partition pruning (`flows` is partitioned by day), so a bounded
window keeps scans cheap. All user values are bound as `?` parameters — never
string-concatenated — so `-dst-org`/`-src-ip` cannot inject SQL.

**Limitations (read before acting on results):**
- NetFlow proves a host opened a connection to a Facebook IP on `:443` — **not** which
  page, post, or message. It is connection metadata, not content.
- `-service` ASN mapping is a convenience; confirm e.g. `32934` is Facebook/Meta in your
  GeoIP/ASN database before relying on it.
- Sampled exporters (`sampling_rate > 1`) record only a fraction of flows, so absence of a
  row is **not** proof a host did not connect.
- **Identity mapping (IP → person) is out of scope.** `trace` answers *which internal IP*;
  resolving that to a user is a separate, confidential join against DHCP/RADIUS records.

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
| `BenchmarkEnrich` (nil stores) | 40 | 0 |
| `BenchmarkEnrichRealStores` (GeoIP + tenant) | 1,096 | 7 |
| `BenchmarkDedupHit` | 145 | 0 |
| `BenchmarkDedupMiss` | 1,237 | 1 |
| `BenchmarkDedupMissParallel` (16 threads) | 97 | 0 |
| `BenchmarkUnmarshal` | 1,574 | 2 |
| `BenchmarkConsumePath` (serial) | 3,330 | 9 |
| `BenchmarkConsumePathParallel` (16 threads) | 1,245 | 6 |

JSON decode uses `goccy/go-json` (12→2 allocs vs `encoding/json`); the dedup LRU
is 16-shard so `DedupMissParallel` *improves* with core count instead of
contending on one lock. The parallel consume path at ~1.25 µs/flow implies a
**~800k flows/s CPU ceiling** on this machine — the real-world limit is the
broker/network/ClickHouse, not enricher CPU (see below).

### End-to-end throughput

Micro-benchmarks measure CPU only; the real ceiling was found by flooding
`raw-flows` with `cmd/loadgen` and measuring `enricher_flows_received_total`.
Two bottlenecks were found and removed, in order:

1. **Synchronous offset commit** — the Kafka reader committed offsets per message
   (one broker round-trip each), capping throughput at **~58 flows/s**. Setting
   `CommitInterval` took it to **~20k flows/s**.
2. **The network transport** — measuring from a dev machine across **Wi-Fi**
   capped the pipeline at **~22k flows/s** (≈100 Mbps ÷ ~550 B/flow), *regardless
   of code or broker cores*. This masked all CPU work.

Run **co-located with the broker** (or over wired gigabit) and the real numbers
appear. On a single ThinkBook (Redpanda `--smp 4`, `raw-flows` = 12 partitions,
enricher `KAFKA_READERS=8`), full pipeline to ClickHouse:

| Setup | Throughput |
|---|---|
| enricher + 1 producer (steady state) | **~108k flows/s** @ ~25% CPU |
| enricher flat-out (drain a backlog) | **~365k flows/s** |

The enricher is **not** the limiter — at 108k/s it sat at ~25% CPU. The path to
more is more producers/partitions and a provisioned ClickHouse.

```bash
# Flood the topic, then run the enricher and watch the receive rate.
# Run BOTH on/near the broker — over Wi-Fi you only measure the Wi-Fi link.
go run ./cmd/loadgen -addr <ip>:9092 -count 5000000
```

---

## Testing with real traffic (softflowd)

`cmd/loadgen` proves *throughput* with synthetic flows; it deliberately emits
100% unique 7-tuples with uniform timing, which is nothing like real traffic.
To test *realism* — real IPs through GeoIP, real duplicate patterns through
dedup, live timestamps in Grafana — run [softflowd](https://github.com/irino/softflowd)
on the infra machine. It captures packets on a real interface and exports
NetFlow v9 into the same goflow2 listener the compose stack already publishes
on UDP 2055, so the entire real path is exercised:

```
real packets → softflowd (NetFlow v9) → goflow2 → Kafka → enricher → ClickHouse → Grafana
```

### Setup (on the infra machine)

```bash
# 1. Stop the synthetic generator so it doesn't mix fake flows in.
docker compose stop nflow-generator

# 2. Install softflowd.
sudo apt install softflowd

# 3. Find the active interface (the one with the default route).
ip route | grep default

# 4. Export the interface's traffic as NetFlow v9 to goflow2.
#    -d           stay in the foreground (softflowd daemonizes by default)
#    -v 9         NetFlow v9 (matches the goflow2 listener on 2055)
#    -t maxlife=60  export every flow within 60 s so data appears quickly
sudo softflowd -d -i <iface> -n 127.0.0.1:2055 -v 9 -t maxlife=60
```

Then start the enricher as usual and generate some traffic on the machine
(`curl`, `apt update`, an SSH session — anything). Verify flows are moving:

```bash
docker compose logs -f goflow2          # goflow2 receiving exports
curl -s localhost:9090/metrics | grep enricher_flows_received_total
```

Expect **tens of flows/s**, not thousands — a single host's connection rate.
That's correct: this test is about flow *shape*, not volume (see the
throughput section above for volume).

### What real flows look like in the data

- **Source geo will be `private`** — the machine's own address is RFC1918, so
  `src_country` is `private` by design; destinations resolve to real
  countries/ASNs.
- **Tenant mapping works for real** — add the machine's subnet to
  `tenants.yaml` and its flows attribute to that tenant.
- **Dedup finally has real work** — long-lived connections re-export on the
  active timeout, so `enricher_flows_deduplicated_total` moves for the first
  time with honest duplicates.

### Variant: replay a research PCAP

softflowd can also read a capture file instead of a live interface:

```bash
softflowd -d -r capture.pcap -n 127.0.0.1:2055 -v 9
```

Public datasets (MAWI backbone traces, CICIDS2017 — labeled attack traffic
that exercises the threat enricher) give campus-scale traffic shape with no
privacy concerns. **Gotcha:** replayed flows carry the capture's *original*
timestamps, so rows land in old ClickHouse partitions and a "last 6 hours"
Grafana range shows nothing — set the dashboard time range to the capture's
date.

### Scaling up to genuinely multi-user traffic

Two options, in order of effort:

1. **Route your own devices through the infra machine** (hotspot/gateway) —
   softflowd then sees real multi-device traffic; still entirely your own,
   so no authorization needed.
2. **Ask the network team for flow export or a SPAN port** from real
   infrastructure. Requires explicit authorization (it's other people's
   traffic) and a **static IP** on the collector — a DHCP address that drifts
   breaks the export destination. Passive Wi-Fi sniffing is *not* an option:
   WPA2/3 encrypts per-client, so a mirror on the wired side is the correct
   tap point.

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
| `enricher_identity_events_parsed_total{source}` | Counter | Identity log events parsed+applied (`nps`/`dhcp`) |
| `enricher_identity_parse_errors_total{source}` | Counter | Malformed identity log lines skipped (`nps`/`dhcp`) |
| `enricher_identity_tag_hits_total` | Counter | Flows where identity resolved ≥1 token |
| `enricher_identity_tag_misses_total` | Counter | Flows where identity resolved no token |
| `enricher_identity_event_write_errors_total` | Counter | ClickHouse identity-event writes that failed (retried next scan) |

---

## Roadmap

- [x] **Week 1** — Docker Compose dev stack (Redpanda, ClickHouse, goflow2, nflow-generator)
- [x] **Week 2** — Redpanda consumer, `FlowMessage` struct, graceful shutdown
- [x] **Week 3** — GeoIP + ASN enrichment (MaxMind mmdb, hot-reload, unit tests)
- [x] **Week 4** — Tenant mapping (CIDR radix tree) + threat intel (Feodo CSV) + sFlow expansion
- [x] **Week 5** — ClickHouse schema + batched native-protocol writer
- [x] **Week 6** — Flow deduplication (LRU) + Prometheus metrics
- [x] **Week 7** — Worker pool (parallel enrichment) + pprof + benchmarks
- [x] **Week 8** — Documentation + PoC→production gap analysis

---

## Key design principles

- **Fail open** — packet loss is worse than enrichment failure. If a lookup fails, log and continue; never drop a flow.
- **Stateless enrichment** — per-flow enrichment is fast, non-blocking, and idempotent.
- **No blocking I/O in the hot path** — GeoIP and threat lookups are in-memory; ClickHouse writes are batched and async.
- **Bounded caches** — every lookup cache has a TTL and a max size; no unbounded growth.
- **Hot-reload without downtime** — GeoIP, tenant config, and threat feed refresh behind a `sync.RWMutex`; no restarts needed.

---

## Gap analysis: PoC → production

Items that are fine for a PoC but need work before real traffic.

### Security
| Gap | Current state | Production fix |
|---|---|---|
| No auth on Redpanda | PLAINTEXT, no SASL | Enable SASL/SCRAM, pass credentials via env |
| No auth on ClickHouse | Empty password | Set `CLICKHOUSE_PASSWORD`, enable TLS |
| No TLS anywhere | All connections plaintext | TLS for Kafka and ClickHouse native protocol |
| Threat feed over HTTP | CSV fetched over HTTPS (OK) but no signature verification | Verify feed hash/signature if source supports it |

### Reliability
| Gap | Current state | Production fix |
|---|---|---|
| Kafka offset auto-commit (read-committed) | `CommitInterval=1s` commits offsets independent of the ClickHouse flush. Transient CH write failures no longer lose flows (see next row), so the remaining exposure is a **hard process crash**, which can lose flows already committed but still buffered (`enricher_clickhouse_buffer_rows` shows that window). Accepted, documented limitation for the PoC | Commit offsets only after `batch.Send()` returns nil, tracking a per-partition watermark across the worker pool, for true write-committed at-least-once |
| ClickHouse write failure (runtime) | `flush()` re-queues a failed batch ahead of new rows with a 1s back-off rather than dropping it; bounded at 500k buffered rows, past which the oldest are dropped and counted (`enricher_clickhouse_write_errors_total`, `enricher_clickhouse_rows_dropped_total`) | Persist the backlog to a durable spool or use `async_insert`; alert on `rows_dropped_total > 0` |
| No dead-letter queue | Unmarshal failures are logged and dropped | Publish bad messages to a `raw-flows-dlq` topic for inspection |
| Single instance | One enricher process — no HA | Run 2+ replicas; Kafka consumer group handles partition distribution automatically |
| ClickHouse reconnect | `NewBatchWriter` fails fast on startup; no retry | Retry with backoff, or crash and let the container orchestrator restart |

### Observability
| Gap | Current state | Production fix |
|---|---|---|
| ~~Unstructured logs~~ (done) | `slog` with `LOG_FORMAT=text\|json` and `LOG_LEVEL`; structured key/value fields throughout. Per-flow stdout fallback retired — now a guarded `slog.Debug` that costs nothing at the default level | Ship JSON to a log aggregator; add request-scoped fields if tracing is added |
| No alerting rules | Prometheus metrics exist but no alerts | Add Alertmanager rules: `enricher_flows_received_total` rate = 0, dedup rate > 50%, CH flush errors |
| ~~No dashboards~~ (done) | Grafana auto-provisioned on `http://localhost:3000` — flows/sec, bytes/sec, protocol mix, top countries/talkers/orgs off ClickHouse | Add Prometheus-sourced panels too (dedup rate, threat hit rate, CH flush latency) and lock down anonymous admin |
| No tracing | No spans | Add OpenTelemetry traces for the enrich → write path |

### Operations
| Gap | Current state | Production fix |
|---|---|---|
| GeoIP updates are manual | Databases loaded at startup, refresh every 24 h from the same path | Use MaxMind's `geoipupdate` cron job to pull fresh mmdb files automatically |
| Config is env-var only | Works for dev and containers | For secrets (passwords, API keys), use a secrets manager (Vault, AWS SSM, K8s secrets) |
| No schema migrations | `applySchema()` is idempotent but unversioned | Add a migration tool (e.g., `golang-migrate`) or version the DDL |
| Docker Compose only | Dev stack only | Helm chart or Terraform module for a real deployment target |
| No graceful Kafka partition revocation | Consumer group rebalance mid-processing can duplicate flows | Implement `kafka.ReaderConfig` with manual commit + rebalance listener |

### Performance (at scale)
| Gap | Current state | Production fix |
|---|---|---|
| Dedup is per-instance | Each replica has its own LRU — duplicates can cross replicas | Use Redis or a shared bloom filter for cross-replica dedup |
| GeoIP lookup on every flow | Fast (RLock + mmdb binary search) but still per-flow | Benchmark at >100k flows/s; consider L1 cache (sync.Map keyed by /24 prefix) |
| Threat store is a flat map | O(1) lookup — fine up to ~1M IPs | Switch to a bloom filter + confirm map for much larger threat feeds |
