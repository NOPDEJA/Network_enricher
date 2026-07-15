package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// feedDnstap drives a slice of lines through one parser, returning every emitted
// event and the count of parse errors — the shape the poller sees.
func feedDnstap(t *testing.T, lines []string) ([]DnsEvent, int) {
	t.Helper()
	p := newDnstapDNSParser()
	var got []DnsEvent
	var errs int
	for _, line := range lines {
		evs, err := p.feed(line)
		if err != nil {
			errs++
			continue
		}
		got = append(got, evs...)
	}
	return got, errs
}

// findEvent returns the first event matching (qname, qtype, answerIP), or nil.
func findEvent(evs []DnsEvent, qname, qtype, answerIP string) *DnsEvent {
	for i := range evs {
		e := evs[i]
		if e.QName == qname && e.QType == qtype && e.AnswerIP == answerIP {
			return &evs[i]
		}
	}
	return nil
}

// countAnswered returns how many events for qname carry a non-empty AnswerIP.
func countAnswered(evs []DnsEvent, qname string) int {
	n := 0
	for _, e := range evs {
		if e.QName == qname && e.AnswerIP != "" {
			n++
		}
	}
	return n
}

// Golden test over the REAL captured dnstap-read -y sample. Asserts representative
// events, that every event is client-side (all FORWARDER_* blocks skipped), zero
// parse errors, and all timestamps land on 2026-07-15 UTC.
func TestDnstapFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/dnstap_sample.yaml")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	got, errs := feedDnstap(t, lines)

	// (c) zero parse errors across the whole fixture.
	if errs != 0 {
		t.Errorf("parse errors = %d, want 0", errs)
	}

	// Total: 7 CLIENT_QUERY (query-only) + 14 CLIENT_RESPONSE events (8 www.google.com
	// A + google A + google AAAA + 2 github A + 2 no-answer fallbacks). A CLIENT_QUERY
	// and its CLIENT_RESPONSE share the client port (same transaction), so assertions
	// key off answer CONTENT, not port.
	if len(got) != 21 {
		t.Fatalf("total events = %d, want 21: %+v", len(got), got)
	}

	// (a) representative events.
	// google.com A answer TTL 49 -> 142.250.66.110.
	if e := findEvent(got, "google.com", "A", "142.250.66.110"); e == nil {
		t.Error("missing google.com A -> 142.250.66.110")
	} else if e.TTL != 49 {
		t.Errorf("google.com A TTL = %d, want 49", e.TTL)
	}
	// google.com AAAA TTL 28.
	if e := findEvent(got, "google.com", "AAAA", "2404:6800:4016:808::200e"); e == nil {
		t.Error("missing google.com AAAA -> 2404:6800:4016:808::200e")
	} else if e.TTL != 28 {
		t.Errorf("google.com AAAA TTL = %d, want 28", e.TTL)
	}
	// www.google.com CLIENT_RESPONSE is ONE block. NOTE: the real fixture carries
	// EIGHT A records (TTL 215), not the four the task text guessed — the sample
	// wins (see report). All answered events share QName www.google.com, TTL 215.
	if n := countAnswered(got, "www.google.com"); n != 8 {
		t.Errorf("www.google.com answered events = %d, want 8 (fixture has 8 A records)", n)
	}
	for _, e := range got {
		if e.QName == "www.google.com" && e.AnswerIP != "" && (e.QType != "A" || e.TTL != 215) {
			t.Errorf("www.google.com answer = %+v, want QType A TTL 215", e)
		}
	}
	// www.github.com CNAME+A: the CNAME emits nothing; the A (github.com owner)
	// emits an event carrying the QUESTION qname www.github.com. Two blocks exist
	// (TTL 49 and TTL 23), so two answered events, and NO CNAME-typed event anywhere.
	if n := countAnswered(got, "www.github.com"); n != 2 {
		t.Errorf("www.github.com answered events = %d, want 2 (CNAME emits nothing)", n)
	}
	if e := findEvent(got, "www.github.com", "A", "20.205.243.166"); e == nil {
		t.Error("missing www.github.com A -> 20.205.243.166")
	}
	var githubTTL23 bool
	for _, e := range got {
		if e.QType == "CNAME" {
			t.Errorf("a CNAME record became an event: %+v", e)
		}
		if e.QName == "www.github.com" && e.AnswerIP == "20.205.243.166" && e.TTL == 23 {
			githubTTL23 = true
		}
	}
	if !githubTTL23 {
		t.Error("missing the TTL-23 www.github.com A event")
	}
	// NXDOMAIN block: a no-answer fallback (QName from question, empty AnswerIP). The
	// AUTHORITY_SECTION SOA must NOT become an event — so NO answered event exists.
	if e := findEvent(got, "dnstap-fixture-test.invalid", "A", ""); e == nil {
		t.Error("missing NXDOMAIN no-answer fallback for dnstap-fixture-test.invalid")
	}
	if n := countAnswered(got, "dnstap-fixture-test.invalid"); n != 0 {
		t.Errorf("dnstap-fixture-test.invalid answered events = %d, want 0 (SOA must not leak)", n)
	}
	// PTR block: PTR is not an address type, so a no-answer fallback and no answered
	// event.
	if e := findEvent(got, "8.8.8.8.in-addr.arpa", "PTR", ""); e == nil {
		t.Error("missing PTR no-answer fallback for 8.8.8.8.in-addr.arpa")
	}
	if n := countAnswered(got, "8.8.8.8.in-addr.arpa"); n != 0 {
		t.Errorf("8.8.8.8.in-addr.arpa answered events = %d, want 0 (PTR not tagged)", n)
	}

	// (b) every event is client-side: ClientIP 127.0.0.1 and a nonzero port, proving
	// all FORWARDER_* blocks (query_address 0.0.0.0) were skipped.
	for _, e := range got {
		if e.ClientIP != "127.0.0.1" {
			t.Errorf("event %+v has ClientIP %q, want 127.0.0.1 (forwarder leg leaked?)", e, e.ClientIP)
		}
		if e.ClientPort == 0 {
			t.Errorf("event %+v has zero ClientPort", e)
		}
	}

	// (d) all EventTimes are 2026-07-15 UTC.
	for _, e := range got {
		y, m, d := e.EventTime.UTC().Date()
		if y != 2026 || m != time.July || d != 15 {
			t.Errorf("event %+v EventTime = %v, want 2026-07-15 UTC", e, e.EventTime)
		}
	}
}

// A minimal well-formed block builder for synthetic tests.
func dnstapBlock(kind, timeField, name, qtype string, extra ...string) []string {
	lines := []string{
		"type: MESSAGE",
		"identity: test",
		"version: BIND 9.20",
		"message:",
		"  type: " + kind,
		"  " + timeField + ": !!timestamp 2026-07-15T08:42:54Z",
		"  query_address: \"127.0.0.1\"",
		"  query_port: 40823",
		"  " + strings.TrimSuffix(timeField, "_time") + "_message_data:",
		"    status: NOERROR",
		"    QUESTION_SECTION:",
		"      - '" + name + " IN " + qtype + "'",
	}
	lines = append(lines, extra...)
	lines = append(lines, "---")
	return lines
}

// Synthetic edge cases.
func TestDnstapSynthetic(t *testing.T) {
	// Truncation resync: a partial block (never terminated) followed by a fresh
	// complete block starting at a col-0 `type:` WITHOUT a preceding `---`. The
	// partial must emit nothing (its state is discarded); the fresh block parses.
	t.Run("truncation resync discards the partial block", func(t *testing.T) {
		var lines []string
		// Partial: a CLIENT_QUERY cut off after query_time (no question yet).
		lines = append(lines,
			"type: MESSAGE",
			"  type: CLIENT_QUERY",
			"  query_time: !!timestamp 2026-07-15T08:42:54Z",
		)
		// A fresh block starts directly at col-0 type: (truncation resync).
		lines = append(lines, dnstapBlock("CLIENT_QUERY", "query_time", "example.com.", "A")...)
		got, _ := feedDnstap(t, lines)
		if len(got) != 1 {
			t.Fatalf("events = %+v, want exactly the one fresh-block query", got)
		}
		if got[0].QName != "example.com" || got[0].QType != "A" || got[0].AnswerIP != "" {
			t.Errorf("fresh event = %+v, want example.com A query-only", got[0])
		}
	})

	// Literal-block trap: a response_message |-body carrying a dig-format answer
	// line must NOT produce an event. With no structured ANSWER_SECTION the block
	// yields exactly one no-answer fallback.
	t.Run("literal block dig-answer is ignored", func(t *testing.T) {
		lines := dnstapBlock("CLIENT_RESPONSE", "response_time", "example.com.", "A",
			"  response_message: |",
			"    ;; ANSWER SECTION:",
			"    example.com.		300	IN	A	1.2.3.4",
		)
		got, errs := feedDnstap(t, lines)
		if errs != 0 {
			t.Fatalf("errs = %d, want 0", errs)
		}
		if len(got) != 1 {
			t.Fatalf("events = %+v, want 1 no-answer fallback", got)
		}
		if got[0].AnswerIP != "" {
			t.Errorf("event AnswerIP = %q, want empty (dig-body answer must be ignored)", got[0].AnswerIP)
		}
	})

	// Missing required field: a CLIENT_QUERY with no QUESTION section is one counted
	// error at the block terminator, zero events.
	t.Run("missing question is one counted error", func(t *testing.T) {
		lines := []string{
			"type: MESSAGE",
			"message:",
			"  type: CLIENT_QUERY",
			"  query_time: !!timestamp 2026-07-15T08:42:54Z",
			"  query_address: \"127.0.0.1\"",
			"  query_port: 40823",
			"---",
		}
		got, errs := feedDnstap(t, lines)
		if len(got) != 0 {
			t.Errorf("events = %+v, want 0", got)
		}
		if errs != 1 {
			t.Errorf("errs = %d, want 1", errs)
		}
	})

	// Quote-stripping: single quotes on question AND answer items are removed before
	// field-splitting, so net.ParseIP sees a clean literal.
	t.Run("quotes stripped from question and answer", func(t *testing.T) {
		lines := dnstapBlock("CLIENT_RESPONSE", "response_time", "www.example.com.", "A",
			"    ANSWER_SECTION:",
			"      - 'www.example.com. 42 IN A 5.6.7.8'",
		)
		got, _ := feedDnstap(t, lines)
		e := findEvent(got, "www.example.com", "A", "5.6.7.8")
		if e == nil {
			t.Fatalf("events = %+v, want www.example.com A 5.6.7.8 (quotes stripped)", got)
		}
		if e.TTL != 42 {
			t.Errorf("TTL = %d, want 42", e.TTL)
		}
	})

	// RFC3339 fractional seconds are accepted.
	t.Run("fractional-seconds timestamp", func(t *testing.T) {
		lines := []string{
			"type: MESSAGE",
			"message:",
			"  type: CLIENT_QUERY",
			"  query_time: !!timestamp 2026-07-15T08:42:54.123456Z",
			"  query_address: \"127.0.0.1\"",
			"  query_port: 40823",
			"  query_message_data:",
			"    QUESTION_SECTION:",
			"      - 'example.com. IN A'",
			"---",
		}
		got, errs := feedDnstap(t, lines)
		if errs != 0 || len(got) != 1 {
			t.Fatalf("events = %+v errs = %d, want 1 event 0 errs", got, errs)
		}
		if got[0].EventTime.Nanosecond() == 0 {
			t.Errorf("EventTime = %v, want sub-second precision preserved", got[0].EventTime)
		}
	})

	// AAAA with a v4 rdata is skipped (family mismatch) -> no-answer fallback.
	t.Run("AAAA with v4 rdata is skipped", func(t *testing.T) {
		lines := dnstapBlock("CLIENT_RESPONSE", "response_time", "bad.example.com.", "AAAA",
			"    ANSWER_SECTION:",
			"      - 'bad.example.com. 30 IN AAAA 1.2.3.4'",
		)
		got, _ := feedDnstap(t, lines)
		if len(got) != 1 {
			t.Fatalf("events = %+v, want 1 no-answer fallback", got)
		}
		if got[0].AnswerIP != "" {
			t.Errorf("AnswerIP = %q, want empty (v4 literal on AAAA must be skipped)", got[0].AnswerIP)
		}
	})
}
