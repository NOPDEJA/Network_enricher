---
name: perf-check
description: Run the enricher's micro-benchmarks (optionally an end-to-end throughput check) and diff them against the README.md baselines to catch performance regressions. Use before merging hot-path changes (enrich, dedup, batchwriter, Kafka reader), or when asked to benchmark or verify throughput.
---

# Enricher perf-check

Regression check, not perf discovery — the throughput ceiling was already found and
documented in `README.md` (`## Running tests and benchmarks` / `### End-to-end throughput`).
This skill re-runs the same measurements and diffs them against those documented numbers.

## Steps

1. **Micro-benchmarks (always run these — no infra needed):**
   ```bash
   go test -bench=. -benchmem -benchtime=3s ./...
   ```
   Compare each benchmark's `ns/op` and `allocs/op` against the baseline table in
   `README.md`. Flag anything with `ns/op` up >20% or a new nonzero `allocs/op`
   where the baseline was `0` — those are the two regressions this project has
   actually hit before (see `dedup_test.go`/`bench_test.go` history: JSON decoder
   allocs, dedup lock contention).

2. **End-to-end throughput (only if the user asks, or the change touches the
   Kafka reader / batch writer / dedup sharding — i.e. things a micro-benchmark
   with nil stores can't see):**
   - Confirm broker/infra is reachable (`REDPANDA_ADDR`, per README's two-machine
     setup) — don't assume it's up, ask if unclear.
   - Start the enricher (`go run .`), then flood the topic:
     ```bash
     go run ./cmd/loadgen -addr <broker>:9092 -count 5000000
     ```
   - Poll `enricher_flows_received_total` on `http://localhost:9090/metrics`
     (or `$METRICS_ADDR`) and compute the rate over a steady window.
   - Compare against the documented baselines: **~108k flows/s** steady-state,
     **~365k flows/s** flat-out drain. Note CPU% too — the README notes the
     enricher sat at ~25% CPU at 108k/s, so a high-CPU/low-throughput result
     means something upstream (broker/network) is the new bottleneck, not code.
   - **Must run co-located with the broker or over wired gigabit.** Over Wi-Fi
     the link itself caps at ~22k flows/s regardless of code — don't mistake
     that for a code regression (this is the exact trap documented in the README).

3. **Report, don't silently fix.** Summarize pass/fail per benchmark plus the
   end-to-end number if measured. If something regressed, name the likely
   suspect (recent diff touching that code path) and let the user decide
   whether to investigate now or accept the change — per this project's
   surgical-changes rule, don't go fix unrelated code while checking perf.
