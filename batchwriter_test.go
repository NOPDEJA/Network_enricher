package main

import (
	"errors"
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
