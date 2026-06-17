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
		send: func([]FlowRow) error { calls++; return nil }}
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
		send: func([]FlowRow) error { return errors.New("ch down") }}
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
		send: func([]FlowRow) error { calls++; return errors.New("ch down") }}
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
	w.send = func([]FlowRow) error {
		// Simulate worker goroutines appending 3 new rows while the send is in flight.
		w.mu.Lock()
		w.buffer = append(w.buffer, makeRows(3)...)
		w.mu.Unlock()
		return errors.New("ch down")
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
