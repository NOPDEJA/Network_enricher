package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

var dnsBase = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

// newClockedDNSStore returns a store with a test-controlled clock. No ClickHouse.
func newClockedDNSStore(t *testing.T) (*DNSStore, *time.Time) {
	t.Helper()
	s := NewDNSStore("", time.UTC, nil)
	clk := new(time.Time)
	*clk = dnsBase
	s.now = func() time.Time { return *clk }
	return s, clk
}

// TTL handling: an answer is trusted until eventTime + min(TTL, 1h) with a 60s
// floor. Covers a normal TTL expiring, the 1h cap, and the 60s floor on a tiny
// TTL that must still cover the flow right after the query.
func TestDNSTTLBounds(t *testing.T) {
	t.Run("normal ttl expires", func(t *testing.T) {
		s, clk := newClockedDNSStore(t)
		s.applyDNS(DnsEvent{EventTime: dnsBase, ClientIP: "10.0.0.5", QName: "a.example.com", QType: "A", AnswerIP: "93.0.0.1", TTL: 120})
		*clk = dnsBase.Add(90 * time.Second)
		if h := s.Lookup("10.0.0.5", "93.0.0.1"); h != "a.example.com" {
			t.Errorf("within ttl: %q, want a.example.com", h)
		}
		*clk = dnsBase.Add(3 * time.Minute) // past 120s
		if h := s.Lookup("10.0.0.5", "93.0.0.1"); h != "" {
			t.Errorf("past ttl: %q, want empty", h)
		}
	})

	t.Run("tiny ttl is floored to 60s", func(t *testing.T) {
		s, clk := newClockedDNSStore(t)
		s.applyDNS(DnsEvent{EventTime: dnsBase, ClientIP: "10.0.0.6", QName: "b.example.com", QType: "A", AnswerIP: "93.0.0.2", TTL: 0})
		*clk = dnsBase.Add(45 * time.Second) // < 60s floor
		if h := s.Lookup("10.0.0.6", "93.0.0.2"); h != "b.example.com" {
			t.Errorf("within floor: %q, want b.example.com", h)
		}
		*clk = dnsBase.Add(75 * time.Second) // past floor
		if h := s.Lookup("10.0.0.6", "93.0.0.2"); h != "" {
			t.Errorf("past floor: %q, want empty", h)
		}
	})

	t.Run("huge ttl is capped at 1h", func(t *testing.T) {
		s, clk := newClockedDNSStore(t)
		s.applyDNS(DnsEvent{EventTime: dnsBase, ClientIP: "10.0.0.7", QName: "c.example.com", QType: "A", AnswerIP: "93.0.0.3", TTL: 86400})
		*clk = dnsBase.Add(2 * time.Hour) // past 1h cap
		if h := s.Lookup("10.0.0.7", "93.0.0.3"); h != "" {
			t.Errorf("past cap: %q, want empty", h)
		}
	})
}

// Both flow orientations resolve through enrich(): the client's resolution of
// the destination tags dst_hostname, and the reverse tags src_hostname.
func TestDNSBothOrientations(t *testing.T) {
	s, clk := newClockedDNSStore(t)
	// Client 10.0.0.5 resolved www.example.com -> 93.184.216.34.
	s.applyDNS(DnsEvent{EventTime: dnsBase, ClientIP: "10.0.0.5", QName: "www.example.com", QType: "A", AnswerIP: "93.184.216.34", TTL: 300})
	*clk = dnsBase.Add(1 * time.Minute)

	// Outbound half: src is the client, dst is the resolved address -> dst_hostname.
	out := enrich(FlowMessage{SrcAddr: "10.0.0.5", DstAddr: "93.184.216.34"}, nil, nil, nil, nil, s)
	if out.DstHostname != "www.example.com" {
		t.Errorf("outbound dst_hostname = %q, want www.example.com", out.DstHostname)
	}
	if out.SrcHostname != "" {
		t.Errorf("outbound src_hostname = %q, want empty", out.SrcHostname)
	}

	// Return half: same conversation reversed -> the address is now the source,
	// so its hostname lands in src_hostname.
	in := enrich(FlowMessage{SrcAddr: "93.184.216.34", DstAddr: "10.0.0.5"}, nil, nil, nil, nil, s)
	if in.SrcHostname != "www.example.com" {
		t.Errorf("return src_hostname = %q, want www.example.com", in.SrcHostname)
	}
	if in.DstHostname != "" {
		t.Errorf("return dst_hostname = %q, want empty", in.DstHostname)
	}
}

// Fail open: an unresolved pair tags nothing and the flow passes through
// untouched; a nil DNSStore is inert.
func TestDNSFailOpen(t *testing.T) {
	s, _ := newClockedDNSStore(t)
	if h := s.Lookup("10.0.0.1", "8.8.8.8"); h != "" {
		t.Errorf("unknown pair = %q, want empty", h)
	}
	in := FlowMessage{SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", Bytes: 1500}
	e := enrich(in, nil, nil, nil, nil, s)
	if e.SrcHostname != "" || e.DstHostname != "" {
		t.Error("unresolved pair should stamp no hostname")
	}
	if e.SrcAddr != in.SrcAddr || e.DstAddr != in.DstAddr || e.Bytes != in.Bytes {
		t.Error("flow fields must pass through untouched")
	}
}

// Hard cap: inserting past maxSize evicts the oldest entry (by deadline) and
// counts an eviction; the newest entries survive.
func TestDNSCapEviction(t *testing.T) {
	s, _ := newClockedDNSStore(t)
	s.maxSize = 4

	before := testutil.ToFloat64(dnsEvictions)
	// Five distinct client/answer pairs, each newer than the last (larger TTL =>
	// later deadline), so the first inserted is the oldest.
	for i := 0; i < 5; i++ {
		s.applyDNS(DnsEvent{
			EventTime: dnsBase.Add(time.Duration(i) * time.Second),
			ClientIP:  "10.0.0.1",
			QName:     "h.example.com",
			QType:     "A",
			AnswerIP:  "93.0.0." + string(rune('1'+i)),
			TTL:       uint32(300 + i), // strictly increasing deadlines
		})
	}

	if got := len(s.entries); got > s.maxSize {
		t.Errorf("map size = %d, want <= %d", got, s.maxSize)
	}
	if delta := testutil.ToFloat64(dnsEvictions) - before; delta < 1 {
		t.Errorf("eviction count delta = %v, want >= 1", delta)
	}
	// The oldest (i=0) should have been evicted; the newest (i=4) must survive.
	if _, ok := s.entries[dnsKey{"10.0.0.1", "93.0.0.1"}]; ok {
		t.Error("oldest entry should have been evicted under the cap")
	}
	if _, ok := s.entries[dnsKey{"10.0.0.1", "93.0.0.5"}]; !ok {
		t.Error("newest entry must survive")
	}
}

// Newest-event-wins: a replayed older resolution must not overwrite a newer one
// for the same (client, answer) pair.
func TestDNSNewestWins(t *testing.T) {
	s, clk := newClockedDNSStore(t)
	s.applyDNS(DnsEvent{EventTime: dnsBase.Add(2 * time.Minute), ClientIP: "10.0.0.5", QName: "new.example.com", QType: "A", AnswerIP: "1.1.1.1", TTL: 300})
	// Older replayed event for the same pair, different name.
	s.applyDNS(DnsEvent{EventTime: dnsBase.Add(1 * time.Minute), ClientIP: "10.0.0.5", QName: "old.example.com", QType: "A", AnswerIP: "1.1.1.1", TTL: 300})
	*clk = dnsBase.Add(3 * time.Minute)
	if h := s.Lookup("10.0.0.5", "1.1.1.1"); h != "new.example.com" {
		t.Errorf("hostname = %q, want new.example.com (older replay must not win)", h)
	}
}

// Deterministic tie-break: two events for the same (client, answer) pair with
// equal EventTime but different hostnames must resolve to the same final state
// regardless of arrival order (the lexicographically greater hostname wins).
func TestDNSEqualTimeTieBreak(t *testing.T) {
	apple := DnsEvent{EventTime: dnsBase, ClientIP: "10.0.0.5", QName: "apple.example.com", QType: "A", AnswerIP: "1.1.1.1", TTL: 300}
	zebra := DnsEvent{EventTime: dnsBase, ClientIP: "10.0.0.5", QName: "zebra.example.com", QType: "A", AnswerIP: "1.1.1.1", TTL: 300}

	for _, order := range [][2]DnsEvent{{apple, zebra}, {zebra, apple}} {
		s, clk := newClockedDNSStore(t)
		s.applyDNS(order[0])
		s.applyDNS(order[1])
		*clk = dnsBase.Add(time.Minute)
		if h := s.Lookup("10.0.0.5", "1.1.1.1"); h != "zebra.example.com" {
			t.Errorf("order %q,%q -> %q, want zebra.example.com (greater hostname wins)", order[0].QName, order[1].QName, h)
		}
	}
}

// Ingest routes parsed events into the live map and skips malformed lines with
// the parse-error metric, without panicking.
func TestDNSIngest(t *testing.T) {
	s, clk := newClockedDNSStore(t)
	beforeErr := testutil.ToFloat64(dnsParseErrors)

	s.ingestDNS("08-Jul-2026 12:00:00.000 client 10.0.0.5#5 (good.example.com): response: good.example.com IN A NOERROR good.example.com. 300 IN A 5.5.5.5")
	s.ingestDNS("99-Xxx-9999 99:99:99.999 client 10.0.0.5#5 (bad): query: bad IN A + (x)") // bad timestamp

	if delta := testutil.ToFloat64(dnsParseErrors) - beforeErr; delta != 1 {
		t.Errorf("parse error delta = %v, want 1", delta)
	}
	*clk = dnsBase // event was at 12:00:00, base is 12:00:00
	if h := s.Lookup("10.0.0.5", "5.5.5.5"); h != "good.example.com" {
		t.Errorf("ingested hostname = %q, want good.example.com", h)
	}
}
