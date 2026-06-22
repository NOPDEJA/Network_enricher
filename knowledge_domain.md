# Project Domain Knowledge (`knowledge_domain.md`)

This document serves as a technical knowledge base for AI agents (like Claude) interacting with this repository. While `CLAUDE.md` governs *behavior* and *coding style*, this file defines the *domain context*, *architectural patterns*, and *performance constraints* of the Network Enricher project.

## 1. Domain: Network Flows

The system processes network telemetry data, not raw packets. It is essential to understand the difference.

- **Stateless Connection Metadata:** Flows represent metadata about a network connection (Source IP, Dest IP, Ports, Bytes, Packets). They do **not** contain payload data.
- **Protocols Handled:**
  - **NetFlow v5 / v9 & IPFIX:** Typically unsampled or systematically sampled.
  - **sFlow:** Inherently packet-sampled (e.g., 1 in 1000 packets).
- **Sampling Expansion:** To estimate true traffic volume, the enricher must multiply `bytes` and `packets` by the `sampling_rate` (found in the goflow2 template). A rate of 1 or 0 means unsampled.
- **Fail Open Strategy:** Packet/flow loss is considered much worse than enrichment failure. If a lookup (e.g., GeoIP or Threat Intel) fails, the flow must be passed downstream un-enriched. **Never drop a flow** unless the upstream buffer is OOM-risking.

## 2. Core Architecture: High-Throughput Pipeline

The system is designed to handle **> 100,000 flows per second** with a low memory footprint (~3-6GB stack total).

### The Worker Pool Model
- **Ingest Bottleneck Mitigation:** Kafka (Redpanda) reading is strictly network I/O. Deserializing JSON is CPU-intensive.
- **Implementation:** The reader goroutine (`KAFKA_READERS`) pushes raw `[]byte` payloads into a buffered channel. A pool of `ENRICH_WORKERS` (defaulting to `runtime.NumCPU()`) reads from this channel, performs the heavy JSON unmarshalling (`goccy/go-json`), deduplicates, and enriches.

### State & Caching Patterns
- **Hot-Reloading Maps:** Enrichment databases (GeoIP `GeoStore`, Threat `ThreatStore`, Tenant `TenantStore`) use `sync.RWMutex`. Background goroutines refresh the underlying data periodically. Readers acquire an `RLock`, ensuring updates happen with zero downtime and minimal contention.
- **Radix Trees for CIDR:** IP address to Tenant mapping uses an IPv4/IPv6 Radix tree (`github.com/yl2chen/cidranger`). This provides sub-microsecond longest-prefix matching (`O(1)` relative to the number of tenants, bounded by IP length).

### High-Performance Deduplication
- **The Problem:** Deduplicating 100k flows/s using a single LRU cache creates a massive mutex lock contention bottleneck across the worker pool.
- **The Solution:** The `DedupStore` implements a **Hash-Sharded LRU**.
  - A 7-tuple (Src/Dst IP, Src/Dst Port, Proto, Exporter, Type) is hashed using a zero-allocation FNV-1a implementation.
  - The hash routes the flow to one of 16 independent `expirable.LRU` shards.
  - This fragments the lock contention, enabling linear scaling on multi-core machines.

## 3. Data Store Integrations

### Kafka / Redpanda (Source)
- **Async Commits:** Synchronous offset commits (one round-trip per flow) cap throughput at ~58 flows/s over a LAN. The consumer uses `CommitInterval: 1s` for read-committed delivery.
- **Partitioning:** The `raw-flows` topic is partitioned. The `readerCount` is set to utilize multiple partitions in parallel.

### ClickHouse (Sink)
- **Batched Native Protocol:** Writing single rows to an OLAP database like ClickHouse is fatal. The `BatchWriter` buffers up to `50,000` rows before executing a `Send()`.
- **Back-off and Re-queueing:** If a ClickHouse write fails (e.g., transient network issue), the buffer is **not** discarded. The `flush()` function re-queues the rows and applies a 1-second back-off. Rows are only dropped if the queue exceeds the hard memory cap (`500,000` rows), preventing process OOM.
- **Schema Engine:** The primary table uses `MergeTree`. Aggregation tables (1 min, 1 hour) use `SummingMergeTree` and are populated automatically via `MATERIALIZED VIEW` constructs.

## 4. Key Dependencies & Rationale

- **`goflow2`**: The upstream generator/decoder. It outputs protobuf/JSON. The enricher treats goflow2 fields as immutable read-only inputs.
- **`goccy/go-json`**: Used instead of `encoding/json` because it significantly reduces allocations during the heavy unmarshal phase.
- **`clickhouse-go/v2`**: Used for the native binary protocol (faster than HTTP).
- **`hashicorp/golang-lru/v2`**: Used for the underlying `expirable.LRU` in the deduplication shards.
- **`cidranger`**: For high-performance tenant subnet lookups.