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

> **Status:** early prototype. The dev stack and a Redpanda consumer are working;
> the enrichment stages are being built out week by week. See
> [Roadmap](#roadmap) for the full plan and what's done.

---

## What works today

- **Dev stack** (`docker_compose.yml`): Redpanda, ClickHouse, goflow2, and a
  NetFlow traffic generator, all via `docker compose up`.
- **goflow2** decodes incoming NetFlow and publishes JSON flow records to the
  `raw-flows` Kafka topic on Redpanda.
- **Go consumer** (`main.go`): reads `raw-flows`, deserializes each record into a
  `FlowMessage`, and prints a one-line summary per flow. Shuts down cleanly on
  SIGTERM / Ctrl+C.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Go](https://go.dev/dl/) 1.26+ (only needed to run/build the enricher locally)

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
go run .
```

You should see flow records printed as they arrive:

```
connected to Redpanda, reading from raw-flows...
10.0.0.5:443 → 192.168.1.20:51514  proto=TCP  etype=IPv4  bytes=1480  packets=2  exporter=172.18.0.4
...
```

Press `Ctrl+C` to stop — the consumer drains and exits cleanly.

**3. Tear down**

```bash
docker compose -f docker_compose.yml down
```

---

## Project layout

| File                 | Purpose                                                        |
|----------------------|---------------------------------------------------------------|
| `main.go`            | Redpanda consumer + `FlowMessage` model (the enricher entry).  |
| `docker_compose.yml` | Dev stack: Redpanda, ClickHouse, goflow2, nflow-generator.    |
| `goflow2.yaml`       | Standalone goflow2 config (reference; not mounted by compose). |
| `go.mod` / `go.sum`  | Go module definition and dependency checksums.                 |
| `CLAUDE.md`          | Engineering guidelines for this project.                       |

> **Note:** the running pipeline currently uses **JSON** as the flow format
> (`-format=json` in compose, `json.Unmarshal` in `main.go`). `goflow2.yaml`
> documents a Protobuf (`pb`) variant for later, when moving off JSON for
> throughput.

---

## Configuration

Defaults currently live in `main.go` / `docker_compose.yml`:

| Setting           | Value             | Where                |
|-------------------|-------------------|----------------------|
| Redpanda broker   | `localhost:9092`  | `main.go`            |
| Consumer group    | `enricher-group`  | `main.go`            |
| Topic             | `raw-flows`       | `main.go` / goflow2  |
| NetFlow listeners | `:2055`, `:4739`  | `docker_compose.yml` |
| Flow format       | `json`            | `docker_compose.yml` |

---

## Roadmap

The enricher is being built over an 8-week plan. Current progress:

- [x] **Week 1** — Go basics + Docker Compose dev stack
- [x] **Week 2** — Redpanda consumer in Go (flows deserialized and printed)
- [ ] **Week 3** — GeoIP + ASN enrichment (MaxMind mmdb, hot-reload, unit tests)
- [ ] **Week 4** — Tenant mapping (CIDR radix tree) + threat intel + sFlow expansion
- [ ] **Week 5** — ClickHouse schema + batched native-protocol writer
- [ ] **Week 6** — Flow deduplication + graceful shutdown + Prometheus metrics
- [ ] **Week 7** — Load testing, pprof profiling, worker pool
- [ ] **Week 8** — Documentation + PoC→production gap analysis + handoff

(Graceful shutdown — a Week 6 item — is already in place.)

---

## Key design principles

From `CLAUDE.md`:

- **Fail open** — packet loss is worse than enrichment failure. If a lookup
  fails, log a metric and continue; never drop a flow.
- **Stateless, fast enrichment** — flows are stateless records; per-flow
  enrichment must be fast, non-blocking, and idempotent.
- **No blocking I/O in the hot path** — offload DNS/HTTP/DB to async workers.
- **Bounded caches** — every lookup cache has a TTL and max size.
