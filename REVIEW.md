# Codebase Review: 100k flows/sec with 4000+ users

The objective of this review is to determine whether the enrichment pipeline can handle a workload of 100,000 flows per second while supporting a tenant configuration of 4000+ users (subnets).

## Summary

**Yes**, the system is well-architected to handle this throughput and user scale. The bottlenecks are network I/O and downstream limits (Kafka, ClickHouse), not CPU processing or data structure lookups.

## Key Findings

### 1. Tenant Mapping (CIDR Matching)

The `TenantStore` relies on `github.com/yl2chen/cidranger`, an efficient IPv4/IPv6 Radix tree implementation.

- A custom benchmark simulating 4000 subnets showed `TenantStore.Lookup` takes roughly **~300 ns** for a match.
- At 100k flows/second, 100,000 lookups will take **~30 milliseconds** of total CPU time per second.
- Across multiple worker goroutines, this lookup uses an `RWMutex.RLock`, meaning reads can happen entirely concurrently with negligible contention.

### 2. Processing Pipeline & Decoding

The single biggest cost per-flow is JSON deserialization (`BenchmarkUnmarshal` takes ~3 µs).

- The ingest path is successfully scaled using `ENRICH_WORKERS` to distribute JSON decoding and enrichment across available cores.
- Using `goccy/go-json` significantly reduces heap allocations, maintaining the high throughput.
- At 100k flows/s, JSON decode takes about 300 ms of cumulative CPU time, well within the limits of a modern multi-core processor.

### 3. Deduplication (LRU)

The flow deduplication cache needs to track the 7-tuple uniqueness of 100,000 flows per second. An unoptimized LRU would introduce severe lock contention across the worker pool.

- The application uses `DedupStore`, which splits the load into `16` independent `expirable.LRU` shards based on a hash of the 7-tuple.
- This hash-sharding design reduces contention, allowing the deduplication phase to effectively scale to > 100k ops/sec across workers without acting as a bottleneck.

### 4. Batched Data Stores

Network sinks are correctly batched and async:
- **Kafka**: The reader uses an asynchronous `CommitInterval: 1s` and fetches data in chunks (`MinBytes: 10e3, MaxBytes: 10e6`), decoupling the ingest loop from broker latency.
- **ClickHouse**: Enriched records are batched via `BatchWriter` which buffers up to `50,000` rows before performing native-protocol writes, preventing high-frequency small inserts.

## Conclusion

The architecture can comfortably handle 100k flows/s with 4000+ configured users. To consistently hit this ceiling, ensure the deployment provides sufficient Redpanda partitions, multiple worker goroutines (`ENRICH_WORKERS`), and a dedicated fast network link to ClickHouse.
