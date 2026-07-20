# Project Domain Knowledge (`knowledge_domain.md`)

This document serves as a technical knowledge base for AI agents (like Claude) interacting with this repository. While `CLAUDE.md` governs *behavior* and *coding style*, this file defines the *domain context*, *architectural patterns*, and *performance constraints* of the Network Enricher project.

## 1. Domain: Network Flows

The system processes network telemetry data, not raw packets. It is essential to understand the difference.

- **Stateless Connection Metadata:** Flows represent metadata about a network connection (Source IP, Dest IP, Ports, Bytes, Packets). They do **not** contain payload data.
- **Protocols Handled:**
  - **NetFlow v5 / v9 & IPFIX:** Typically unsampled or systematically sampled.
  - **sFlow:** Inherently packet-sampled (e.g., 1 in 1000 packets).
- **Sampling Expansion:** To estimate true traffic volume, the enricher must multiply `bytes` and `packets` by the `sampling_rate` (found in the goflow2 template). A rate of 1 or 0 means unsampled.
- **Fail Open Strategy:** Packet/flow loss is considered much worse than enrichment failure. If a lookup (e.g., GeoIP or Threat Intel) fails, the flow must be passed downstream un-enriched. **Never drop a flow** unless the upstream buffer is OOM-risking. There are exactly two deliberate inversions of this rule, both in the forensic subsystems (section 5): the pseudonym tokenizer **fails closed** (no key → identity enrichment stays off entirely; raw MAC/username must never be written), and log-timezone resolution **fails loud** (an invalid `LOG_TZ` is a fatal startup error, because silently mis-parsed timestamps corrupt forensic joins rather than merely dropping enrichment).

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

## 4. Forensic Enrichment: Identity ("who") and DNS ("what")

Built for campus-WiFi legal forensics (MUIC use case): given a timestamp and an external service, produce *which internal device/user* — without day-to-day logs ever exposing a real identity. Two subsystems, both optional and env-gated, both following the same shape: a file poller ingests server logs, an in-memory store does best-effort **live tagging** of flows, and append-only ClickHouse event tables are the **forensic source of truth** (the live maps are a convenience, never the record).

### Identity — DHCP + 802.1x/RADIUS ("who")
- **Sources:** Microsoft NPS RADIUS accounting logs (DTS-XML) give username ↔ MAC sessions; Windows DHCP audit logs give IP ↔ MAC leases. MUIC's RADIUS does **not** carry Framed-IP-Address (auth happens before DHCP), so the chain is always `flow IP + time → DHCP lease → MAC → RADIUS session → user`, joined on MAC. Both mappings are temporal; lease intervals are derived from events (open at assign/renew, close at release/reassign/max-lease fallback).
- **Pseudonymization:** identifiers are tokenized as `HMAC-SHA256(keyfile, normalized id)` (truncated). Deterministic, so the MAC join works across tables. There is **no token→person mapping table anywhere** — re-identification is recompute-forward: an authorized holder of the key tokenizes a candidate identity and compares. **Fail closed:** if the key file can't be loaded, the whole identity subsystem stays off.
- **Flow tagging:** 4 columns (`src/dst_mac_token`, `src/dst_user_token`), both directions like dst-tenant attribution.
- **Gating:** `IDENTITY_TOKEN_KEY_FILE` + at least one of `IDENTITY_NPS_DIR`/`IDENTITY_DHCP_DIR`.

### DNS — BIND9 resolver logs ("what")
- **Why:** one CDN IP serves thousands of sites; the DNS query is the only network-level record of the actual hostname. Correlation is **per-client**: `(clientIP, answeredIP) → hostname`, so one client's resolution never labels another client's flows.
- **`DNSStore`:** live map with entries valid for the record TTL bounded to [60s, 1h]; hard-capped at ~1M entries (client×dst cardinality can explode) with expired-first-then-oldest eviction — victim selection runs under `RLock` so hot-path lookups are never stalled (single-mutator invariant: only the poller writes). Hostnames are *not* personal data in this design and stay in the clear.
- **Parsers (`DNS_LOG_FORMAT`):** three formats, one event contract. `bind` — BIND9 querylog lines (query-only; its modeled one-line response variant never occurs in real BIND output and survives only for compatibility). `tcpdump` — stateful two-line `tcpdump -v` text, the real MUIC capture format (answers but no TTLs → fixed 10-minute validity horizon). `dnstap` — stateful multi-line `dnstap-read -y` YAML blocks produced by the `dnstap-export` compose sidecar from BIND's binary dnstap stream; the only source carrying **real answer TTLs**, and its timestamps carry an explicit zone so `DNS_LOG_TZ` does not apply. All three capture the client source port as the per-line dedup discriminator.
- **Flow tagging:** `src_hostname`/`dst_hostname`, both orientations (src-as-client tags dst_hostname; dst-as-client tags src_hostname).
- **Gating:** `DNS_LOG_DIR` + `DNS_LOG_FORMAT=bind|tcpdump|dnstap` (default `bind`; the tcpdump format adds `DNS_TCPDUMP_DATE`/`DNS_TCPDUMP_RESOLVER_IP` for capture replay).

### Shared machinery
- **Event tables:** `identity_dhcp_events`, `identity_radius_events`, `dns_events` — `ReplacingMergeTree` with fully-identifying `ORDER BY` keys, so restart/replay re-ingestion deduplicates instead of double-counting; 90d TTL matching `flows`.
- **File poller (`filepoller.go`):** shared incremental scan core — 30s ticker, per-file byte offsets, rotation/truncation detection, 8MB-per-scan read cap, panic-recovered scans. Owned by one goroutine per store; offsets need no lock.
- **Timezones (`logtz.go`):** server logs carry naive local timestamps. Parsers interpret them in the zone from per-source overrides (`NPS_LOG_TZ`/`DHCP_LOG_TZ`/`DNS_LOG_TZ`) falling back to `LOG_TZ`, default UTC; invalid zones are fatal at startup. `time/tzdata` is imported so this works on Windows dev machines.
- **Hot-path cost:** live tagging is RWMutex-guarded map reads only — no I/O, no allocation. All log parsing and ClickHouse event writes happen on the poller goroutines, never in the flow path.

### Evidence path vs. live store (identity v2, 2026-07-20)

The two identity consumers are deliberately **not** the same algorithm, and must not be re-synced:

- **`cmd/trace` is the evidence path and is deterministic.** It folds identity events in a *batch* over identical `event_time` values: all events sharing one timestamp are applied as a set, so the answer cannot depend on the order ClickHouse returned the rows in. Where the evidence holds several equally-valid candidates at the queried instant it reports **"ambiguous at that time"**, which is distinct from **"unknown at that time"** (nothing bound). The same question over the same rows always gives the same answer.
- **The live store (`identity.go`) is advisory / best-effort.** It folds in *arrival* order into a current-state view, which is the right shape for annotating flows cheaply, but means a same-second tie is decided by information the stored evidence does not contain. Live tags and `cmd/trace` **can disagree** under same-second replay. `cmd/trace` is the answer of record; a live tag is a convenience.
- **Known, unfixed limitation in the live store (F1, false attribution).** The tombstone is a single slot on the binding. A legitimate same-second *cross-entity* open overwrites it, so a subsequently replayed same-or-older open of the closed entity resurrects it: `Stop S1@T; Start S2@T; replayed Start S1@T` leaves S1 active, attributing traffic to a user whose session had ended. Not fixed in this pass: a correct fix needs per-entity tombstones with heap-based expiry, and the reviewed design would have put an O(n) scan under the mutex `Lookup` holds — a hot-path violation (CLAUDE.md §6) to harden a store that is advisory anyway. `cmd/trace` is immune to F1 by construction (batch fold), so the forensic answer is unaffected.
- **Known limitation, inherited and unchanged:** a bare `Interim-Update` naming a session never `Start`ed silently *displaces* the currently active session with no `Stop`. Both paths behave this way (live: `TestRADIUSNewestWins` "bootstraps", `identity_test.go:222`; trace: spec case 11). It is pinned by tests rather than endorsed — real NPS logs do emit interims for sessions whose Start was lost, and treating them as an open is preferable to dropping them, but it means an unmatched interim can end an attribution window without evidence of a logout.
- **The identity ORDER BY migration is forward-only.** `identity_dhcp_events` and `identity_radius_events` were widened to full-row keys (`+ host_token`; `+ user_token, nas_ip`) because `ReplacingMergeTree` was collapsing genuinely distinct same-second events that differed only in an omitted column — evidence loss in the forensic source of truth. `migrations/002_identity_orderby.sql` (copy + manual count gate) and `002b_identity_orderby_swap.sql` (atomic `EXCHANGE TABLES` per pair) fix it going forward only: rows already collapsed under the old key are **unrecoverable**, there is no backfill, and the surviving row is the only copy that exists. Note the DDL that actually creates these tables lives in `batchwriter.go` (`schemaStatements`, run by `applySchema` on startup) — `schema.sql` is the operator-facing copy. Both must move together: every bootstrap statement is `CREATE TABLE IF NOT EXISTS`, so a wrong key there is a no-op on an existing box and surfaces only on a fresh volume. `TestSchemaIdentityOrderByIsFullRow` pins it.

## 5. Key Dependencies & Rationale

- **`goflow2`**: The upstream generator/decoder. It outputs protobuf/JSON. The enricher treats goflow2 fields as immutable read-only inputs.
- **`goccy/go-json`**: Used instead of `encoding/json` because it significantly reduces allocations during the heavy unmarshal phase.
- **`clickhouse-go/v2`**: Used for the native binary protocol (faster than HTTP).
- **`hashicorp/golang-lru/v2`**: Used for the underlying `expirable.LRU` in the deduplication shards.
- **`cidranger`**: For high-performance tenant subnet lookups.