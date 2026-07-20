# CLAUDE.md

Behavioral guidelines for this project. Merged from general best practices + project-specific rules.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

---

## Project Context

This is a **network flow analysis enricher** built in Go using [goflow2](https://github.com/netsampler/goflow2).
It ingests NetFlow v5/v9, IPFIX, and sFlow data, enriches flows (GeoIP, ASN, DNS, threat intel, interface mapping, etc.),
and forwards enriched records downstream (e.g. Kafka, Elasticsearch, ClickHouse, stdout JSON).

Think: open-source ElastiFlow alternative.

**Key concepts to know:**
- Flows are stateless records — enrichment must be fast and non-blocking
- Packet loss is worse than enrichment failure — always fail open
- Proto/struct definitions come from goflow2's `pb/` — do not modify without asking
- Enrichers run as a pipeline; order matters

---

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly, then proceed (no need to wait for confirmation).
- If multiple interpretations exist, pick the most conservative and say which you chose.
- If a simpler approach exists, say so. Push back when warranted.
- If something is genuinely ambiguous (e.g. field naming, enricher ordering), name it and make a call.
- **Scale the asking bar to the cost of being wrong.** For inline edits, a wrong assumption is cheap to correct — just proceed. But *before delegating to `engineer`*, resolve any load-bearing ambiguity with the user first (use `AskUserQuestion`): a wrong delegation burns a whole Opus implementation cycle, so one clarifying question is the cheaper path.

---

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions unless the same logic appears 3+ times.
- No "pluggable interface" or "configurable factory" unless explicitly requested.
- No error handling for impossible scenarios (e.g. nil checks on always-initialized structs).
- Prefer flat structs over deep nesting for flow records.

Ask: *"Would a senior Go engineer say this is overcomplicated?"* If yes, simplify.

---

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't reformat unrelated files — `gofmt` only on files you touch.
- Don't rename fields or restructure types unless that's the task.
- Match existing patterns (error wrapping style, logging format, context propagation).
- If you notice a bug or dead code nearby, **mention it in a comment** — don't fix it silently.

When your changes create orphans:

- Remove imports/variables/functions that **your** changes made unused.
- Run `go vet ./...` mentally — don't leave unused vars that won't compile.

**Every changed line should trace directly to the request.**

---

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add GeoIP enricher" → "Enricher attaches `src_country`, `dst_country` fields; passes unit test with known IPs"
- "Fix dropped flows" → "Identify the pipeline stage dropping records; add metric; make test reproduce it then fix it"
- "Optimize throughput" → "Benchmark before and after with `go test -bench`; target is stated in the task"

For multi-step tasks, state a brief plan first:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

---

## 5. Go-Specific Rules

- **Never use `init()`** unless integrating with a framework that requires it.
- **Goroutine hygiene**: every goroutine must have a clear owner and shutdown path (context cancellation or done channel).
- **Channels over mutexes** for pipeline stages; mutexes for shared caches (GeoIP, ASN lookups).
- **Enrich in parallel where safe**, but keep per-flow enrichment deterministic and idempotent.
- **Fail open on enrichment errors**: if GeoIP lookup fails, log a metric and continue — never drop the flow.
- Use `slog` or `zerolog` (match whatever the project already uses) — no `fmt.Println` in production paths.
- Proto-generated files in `pb/` are read-only. Extend via wrapper structs, not by editing generated code.

---

## 6. Performance Rules (Network Path)

- No allocations in the hot path if avoidable — reuse buffers, use `sync.Pool`.
- No blocking I/O (DNS, HTTP) in the flow processing goroutine — offload to async workers with a timeout.
- All enrichment caches must have a TTL and max size — unbounded caches will OOM under traffic.
- Benchmark any enricher that touches external data (GeoIP DB, threat feeds) before merging.

---

## 7. Testing Conventions

- **Reproduce before you fix.** For a reported bug, first reproduce it end-to-end against the real pipeline (run the enricher, feed it a real/synthetic flow via `cmd/loadgen` or a raw NetFlow packet, observe the actual output) before writing a regression test. A unit test that passes on a mocked path can miss the real failure mode (see the Wi-Fi-vs-broker throughput trap in the README) — reproduce first, then let the test lock in the fix.
- Unit tests live in `_test.go` files alongside the package.
- Use table-driven tests for enrichers (multiple IP/flow inputs → expected output).
- Integration tests that require external services (Kafka, ES) go in `integration/` and are gated by a build tag: `//go:build integration`.
- Run: `go test ./...` for unit tests, `go test -tags integration ./...` for full suite.

---

## 8. Session & Token Hygiene

**Cost comes from context size per turn, not from idle time.** Leaving a session open costs nothing; every message re-sends the whole conversation, so long sessions get expensive per turn.

- **Keep sessions task-scoped.** Finished a task or switching to something unrelated → `/clear` and start fresh. This project has a populated auto-memory (`MEMORY.md` + memory files), so a fresh session rehydrates the important state automatically.
- **Use `/compact` only to continue the *same* long task** with less overhead. Don't `/compact` *and* start a new session — the new session discards the compacted history anyway.
- **Don't act on idle.** There's no idle-timer trigger; auto-compact only fires when the context window fills. Stepping away ~5 min just expires the prompt cache (one uncached re-read on return), which is unavoidable.
- **Lean on memory, not long chats.** Persist durable project state to the memory files so `/clear` is cheap and safe.

---

## 9. Multi-Agent Workflow

The main session acts as **tech lead**: discuss the problem with the user, decide the approach together, then delegate. The user has standing authorization for this delegation pattern — no need to ask before spawning these agents when the task fits.

- **`engineer`** (Opus, `.claude/agents/engineer.md`) — implements decided, well-scoped coding tasks. Hand it the approach, files, and success criteria.
- **`codex`** (`.claude/agents/codex.md`) — independent second-opinion review of designs/diffs from another angle. Uses OpenAI Codex CLI when installed; otherwise a clearly-labeled Claude fallback review. Read-only.
- **`chores`** (Sonnet 5, `.claude/agents/chores.md`) — repetitive mechanical work (bulk renames, gofmt sweeps, boilerplate from an explicit pattern).

Lead responsibilities: don't delegate design decisions; review subagent output before presenting it to the user; for nontrivial changes, route the engineer's diff through `codex` before calling it done. Trivial one-file edits: just do them inline — spawning costs more than it saves.

**Design pre-review (adopted 2026-07-20):** for *significant* designs — a new subsystem, forensic/evidence semantics, schema or privacy-model changes — route the decided design through `codex` (high/xhigh effort) to challenge it BEFORE delegating to `engineer`. A design flaw caught pre-implementation saves a whole implementation-plus-fix cycle; the tombstone fix's same-second handover flaw (7/20) is the motivating example. Small fixes and mechanical work skip this — the diff review alone is enough.

**Delegation handoff — the hidden token cost of delegating is the engineer re-discovering context you already have.** Each agent starts cold, so hand it, not the problem:
- the *decided approach* (you already solved the design — don't make it re-derive one)
- the exact files + entry points to touch (paths, function/type names)
- explicit success criteria: what to build, and what command proves it works
- only the CLAUDE.md constraints that actually bear on this task

A crisp handoff turns a multi-turn exploration into a single focused pass. If you can't write one, the task isn't ready to delegate — clarify it first (see §1).

---

**These guidelines are working if:** diffs are tight and traceable, enrichers are testable in isolation, and the pipeline never silently drops flows.
