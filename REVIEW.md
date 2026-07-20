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

## Addendum (2026-07-09): Identity + DNS Enrichment

Two forensic enrichers were added after this review (identity "who"-tokens, merged 5d20369; DNS "what"-hostnames, merged 9422e3d). The conclusion above is unchanged:

- **Hot path:** each enabled subsystem adds RWMutex-guarded in-memory map reads per flow (identity: both addresses; DNS: both client/answer orientations) — the same read-mostly pattern as `TenantStore`, with no I/O and no allocation in the flow path. A miss leaves fields empty (fail open).
- **Off the hot path:** log parsing runs on dedicated 30s poller goroutines; identity/DNS event rows go to ClickHouse through small dedicated buffered writers, separate from the flow `BatchWriter`.
- **Memory:** the DNS live map is the only store whose key space scales with traffic (client × destination); it is hard-capped at ~1M entries with expired-first eviction, where victim *selection* runs under `RLock` so flow-path lookups are not stalled by an eviction sweep.
- **Verified:** `go test -race` clean and an end-to-end synthetic run on the live pipeline (per-client tagging, replay dedup via `ReplacingMergeTree`) passed 2026-07-09.

## Addendum (2026-07-20): Identity v2 — evidence-path determinism

Follow-up to the tombstone fix (1ed2c4b). An independent review found that the
*forensic* path resolved same-timestamp events by the order ClickHouse happened
to return the rows in — information the stored evidence does not contain — plus
a schema defect losing raw events outright. Three changes, all off the hot path:

- **`cmd/trace` is the evidence path and is now deterministic.** `identity_join.go`
  folds events whose `event_time` is identical as a **set** (candidate set +
  one carried deadline) instead of sequentially, so the answer no longer depends
  on row order. Where the evidence genuinely holds several candidates, the tool
  reports **"ambiguous at that time"** — deliberately distinct from the existing
  **"unknown at that time"** — rather than silently picking one; an ambiguous
  device short-circuits the RADIUS join, since there is no single MAC to key on.
  This file **no longer mirrors `identity.go`** and must not be re-synced to it.
- **The live store remains advisory / best-effort and is UNCHANGED.** It still
  folds in arrival order, so live tags and `cmd/trace` can disagree under
  same-second replay; `cmd/trace` is the answer of record. Its known false-
  attribution hole (F1: a same-second cross-entity open erases the single-slot
  tombstone, letting a replayed older open resurrect a closed session) is
  **documented, not fixed** — a correct fix needs per-entity tombstones with
  heap-based expiry, and the reviewed design put an O(n) scan under the mutex
  `Lookup` holds, which violates CLAUDE.md §6 to harden a store that is advisory
  anyway. `cmd/trace` is immune to F1 by construction.
- **Identity ORDER BY widened to the full row, forward-only.**
  `identity_radius_events` omitted `user_token`/`nas_ip` and
  `identity_dhcp_events` omitted `host_token`, so `ReplacingMergeTree` + `FINAL`
  collapsed genuinely distinct same-second events into one row — raw evidence
  loss in the source of truth. `migrations/002_identity_orderby.sql` fixes the
  schema going forward; rows already collapsed under the old key are **gone and
  are not recovered**. NPS timestamps are now truncated to whole seconds at parse
  so the live store stops ordering by a precision that never reaches the
  second-resolution `DateTime` column.

Verified: `go build`/`go vet`/`go test ./...` green; the 11 spec cases are
table-driven and same-timestamp batches are asserted over **every permutation**;
the regression cases were confirmed red against the previous implementation
before the fix landed. `go test -race` is pending — it runs on the Linux box, as
this dev machine has no 64-bit CGO.
