package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func makeRows(n int) []FlowRow {
	r := make([]FlowRow, n)
	for i := range r {
		r[i] = FlowRow{SrcIP: "10.0.0.1", DstIP: "8.8.8.8"}
	}
	return r
}

func TestFlushSuccessEmptiesBuffer(t *testing.T) {
	calls := 0
	w := &BatchWriter{maxSize: 4, maxBuffer: 8, maxAge: time.Second,
		send: func([]FlowRow) ([]FlowRow, error) { calls++; return nil, nil }}
	w.buffer = makeRows(3)

	before := testutil.ToFloat64(chRowsWritten)
	w.flush()

	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
	if len(w.buffer) != 0 {
		t.Fatalf("buffer not drained on success: %d rows left", len(w.buffer))
	}
	if got := testutil.ToFloat64(chRowsWritten) - before; got != 3 {
		t.Fatalf("rows written delta = %v, want 3", got)
	}
}

// The core fail-open guarantee: a failed write must re-queue its rows, never drop them.
func TestFlushReQueuesOnFailure(t *testing.T) {
	w := &BatchWriter{maxSize: 4, maxBuffer: 100, maxAge: time.Second,
		send: func(rows []FlowRow) ([]FlowRow, error) { return rows, errors.New("ch down") }}
	w.buffer = makeRows(3)

	beforeErr := testutil.ToFloat64(chWriteErrors)
	w.flush()

	if len(w.buffer) != 3 {
		t.Fatalf("rows lost on failure: buffer = %d, want 3 re-queued", len(w.buffer))
	}
	if got := testutil.ToFloat64(chWriteErrors) - beforeErr; got != 1 {
		t.Fatalf("write errors delta = %v, want 1", got)
	}
	if !w.retryAfter.After(time.Now()) {
		t.Fatal("retryAfter not set into the future after a failure")
	}
}

// During the back-off window a size-triggered flush must be a no-op (don't hammer a
// dead ClickHouse); once the window passes, the next flush retries.
func TestFlushBackoffSkipsSendUntilWindowPasses(t *testing.T) {
	calls := 0
	w := &BatchWriter{maxSize: 4, maxBuffer: 100, maxAge: 30 * time.Millisecond,
		send: func(rows []FlowRow) ([]FlowRow, error) { calls++; return rows, errors.New("ch down") }}
	w.buffer = makeRows(2)

	w.flush() // attempt 1: fails, arms the back-off
	w.flush() // inside the window: must not call send
	if calls != 1 {
		t.Fatalf("send called during back-off: calls = %d, want 1", calls)
	}

	time.Sleep(40 * time.Millisecond) // let the window pass
	w.flush()
	if calls != 2 {
		t.Fatalf("send not retried after back-off: calls = %d, want 2", calls)
	}
}

// Under a sustained outage the buffer must stay bounded: past the hard cap the oldest
// rows are dropped (and counted) rather than growing until OOM.
func TestFlushDropsOldestWhenBufferCapped(t *testing.T) {
	w := &BatchWriter{maxSize: 4, maxBuffer: 5, maxAge: time.Second}
	w.send = func(rows []FlowRow) ([]FlowRow, error) {
		// Simulate worker goroutines appending 3 new rows while the send is in flight.
		w.mu.Lock()
		w.buffer = append(w.buffer, makeRows(3)...)
		w.mu.Unlock()
		return rows, errors.New("ch down")
	}
	w.buffer = makeRows(4)

	beforeDrop := testutil.ToFloat64(chRowsDropped)
	w.flush() // 4 failed rows re-queued ahead of 3 new arrivals = 7 > cap 5 → drop 2

	if len(w.buffer) != 5 {
		t.Fatalf("buffer = %d, want capped at 5", len(w.buffer))
	}
	if got := testutil.ToFloat64(chRowsDropped) - beforeDrop; got != 2 {
		t.Fatalf("rows dropped delta = %v, want 2", got)
	}
}

// On shutdown the final drain must flush buffered rows even inside a back-off
// window — a transient failure right before shutdown must not strand rows.
func TestFinalDrainIgnoresBackoff(t *testing.T) {
	fail := true
	w := &BatchWriter{maxSize: 4, maxBuffer: 100, maxAge: time.Millisecond,
		send: func(rows []FlowRow) ([]FlowRow, error) {
			if fail {
				return rows, errors.New("ch down")
			}
			return nil, nil
		}}
	w.buffer = makeRows(3)

	w.flush()    // fails, arms the back-off, re-queues 3 rows
	fail = false // ClickHouse recovers
	if lost := w.FinalDrain(5); lost != 0 {
		t.Fatalf("FinalDrain left %d rows, want 0", lost)
	}
	if len(w.buffer) != 0 {
		t.Fatalf("buffer not drained on shutdown: %d rows left", len(w.buffer))
	}
}

// A recovered backlog larger than maxSize must be sent in maxSize chunks, not as
// one oversized insert.
func TestDrainChunksLargeBacklog(t *testing.T) {
	var sizes []int
	w := &BatchWriter{maxSize: 4, maxBuffer: 100, maxAge: time.Second,
		send: func(rows []FlowRow) ([]FlowRow, error) {
			sizes = append(sizes, len(rows))
			return nil, nil
		}}
	w.buffer = makeRows(10)

	w.flush()

	if len(w.buffer) != 0 {
		t.Fatalf("buffer not fully drained: %d rows left", len(w.buffer))
	}
	want := []int{4, 4, 2}
	if len(sizes) != len(want) {
		t.Fatalf("chunk sizes = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("chunk sizes = %v, want %v", sizes, want)
		}
	}
}

// When a send drops malformed rows (returns fewer retryable rows than it was
// given) and then fails, only the retryable rows are re-queued — the malformed
// ones must not loop back into the buffer to fail and be re-counted forever.
func TestDrainReQueuesOnlyRetryableRows(t *testing.T) {
	w := &BatchWriter{maxSize: 10, maxBuffer: 100, maxAge: time.Second,
		send: func(rows []FlowRow) ([]FlowRow, error) {
			// Pretend the last row was malformed and dropped before the send failed.
			return rows[:len(rows)-1], errors.New("ch down")
		}}
	w.buffer = makeRows(3)

	w.flush()

	if len(w.buffer) != 2 {
		t.Fatalf("buffer = %d, want 2 (malformed row excluded from re-queue)", len(w.buffer))
	}
}

// Add must trigger a flush exactly when the buffer reaches maxSize — not before,
// so we don't flush on every flow, and not never, so the count-trigger works.
func TestAddFlushesAtMaxSize(t *testing.T) {
	calls := 0
	w := &BatchWriter{maxSize: 3, maxBuffer: 100, maxAge: time.Second,
		send: func([]FlowRow) ([]FlowRow, error) { calls++; return nil, nil }}

	w.Add(FlowRow{})
	w.Add(FlowRow{})
	if calls != 0 {
		t.Fatalf("flushed before reaching maxSize: calls = %d, want 0", calls)
	}

	w.Add(FlowRow{}) // third row hits maxSize → flush
	if calls != 1 {
		t.Fatalf("size-trigger did not flush: calls = %d, want 1", calls)
	}
	if len(w.buffer) != 0 {
		t.Fatalf("buffer not drained after size-trigger: %d rows left", len(w.buffer))
	}
}

// When ClickHouse never recovers, FinalDrain must exhaust its attempts and report
// the rows it couldn't write rather than blocking shutdown forever.
func TestFinalDrainReturnsRemainingWhenAllAttemptsFail(t *testing.T) {
	calls := 0
	w := &BatchWriter{maxSize: 4, maxBuffer: 100, maxAge: time.Millisecond,
		send: func(rows []FlowRow) ([]FlowRow, error) { calls++; return rows, errors.New("ch down") }}
	w.buffer = makeRows(3)

	if lost := w.FinalDrain(3); lost != 3 {
		t.Fatalf("FinalDrain = %d, want 3 (all attempts failed)", lost)
	}
	if calls != 3 {
		t.Fatalf("send attempts = %d, want 3", calls)
	}
	if len(w.buffer) != 3 {
		t.Fatalf("rows lost: buffer = %d, want 3 preserved for the operator", len(w.buffer))
	}
}

// Many workers calling Add concurrently must not race the size-triggered flush or
// the shutdown drain, and every row must end up sent (run with -race). Guards the
// mutex discipline in Add/drain/FinalDrain.
func TestConcurrentAddNoRace(t *testing.T) {
	var mu sync.Mutex
	sent := 0
	w := &BatchWriter{maxSize: 8, maxBuffer: 1_000_000, maxAge: time.Millisecond,
		send: func(rows []FlowRow) ([]FlowRow, error) {
			mu.Lock()
			sent += len(rows)
			mu.Unlock()
			return nil, nil
		}}

	const workers, perWorker = 8, 2000
	var wg sync.WaitGroup
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				w.Add(FlowRow{SrcIP: "10.0.0.1"})
			}
		}()
	}
	wg.Wait()

	if lost := w.FinalDrain(3); lost != 0 {
		t.Fatalf("FinalDrain left %d rows", lost)
	}
	mu.Lock()
	total := sent
	mu.Unlock()
	if total != workers*perWorker {
		t.Fatalf("rows sent = %d, want %d (rows lost under concurrency)", total, workers*perWorker)
	}
}

// The enricher bootstraps its own tables via applySchema (NewBatchWriter), so
// schemaStatements — not schema.sql — is what a fresh ClickHouse volume
// actually gets. Both files carried a SHORT ORDER BY on the identity tables:
// ReplacingMergeTree then collapses two genuinely distinct same-second events
// that differ only in an omitted column, which is raw evidence loss in the
// forensic source of truth (a same-second Interim-Update pair differing only by
// user_token would reach cmd/trace as ONE row, and it would confidently report
// a single user instead of ambiguity).
//
// Every CREATE here is IF NOT EXISTS, so a wrong key is invisible on an
// existing box and only bites on a rebuild. This test pins the two keys against
// their tables' full column lists so schema.sql and this DDL cannot drift apart
// silently again.
func TestSchemaIdentityOrderByIsFullRow(t *testing.T) {
	tests := []struct {
		table   string
		columns []string
		wantKey string
	}{
		{
			table:   "identity_dhcp_events",
			columns: []string{"event_time", "event_id", "ip", "mac_token", "host_token"},
			wantKey: "ORDER BY (ip, event_time, event_id, mac_token, host_token)",
		},
		{
			table:   "identity_radius_events",
			columns: []string{"event_time", "acct_status", "session_id", "user_token", "mac_token", "nas_ip"},
			wantKey: "ORDER BY (mac_token, event_time, session_id, acct_status, user_token, nas_ip)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.table, func(t *testing.T) {
			var ddl string
			for _, stmt := range schemaStatements {
				if strings.Contains(stmt, "CREATE TABLE IF NOT EXISTS "+tc.table+" ") {
					ddl = stmt
					break
				}
			}
			if ddl == "" {
				t.Fatalf("no CREATE TABLE statement for %s in schemaStatements", tc.table)
			}
			if !strings.Contains(ddl, tc.wantKey) {
				t.Fatalf("%s: bootstrap DDL must use the full-row ORDER BY\nwant: %s\ngot DDL:\n%s",
					tc.table, tc.wantKey, ddl)
			}
			// Independently of the literal above: every column the table
			// declares must appear in the key, or FINAL can collapse distinct
			// rows. This is the invariant, not the exact string.
			key := ddl[strings.Index(ddl, "ORDER BY ("):]
			key = key[:strings.Index(key, ")")+1]
			for _, col := range tc.columns {
				if !strings.Contains(key, col) {
					t.Errorf("%s: column %q missing from ORDER BY %s — distinct same-second events differing only in %q would collapse under FINAL",
						tc.table, col, key, col)
				}
			}
		})
	}
}
