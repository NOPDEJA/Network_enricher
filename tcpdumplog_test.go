package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// tcpBase is the date the tcpdump fixture is anchored to (tcpdump prints no date).
var tcpBase = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)

// feedPacket drives one full packet (UDP header line, then its indented payload)
// through the stateful parser and returns the payload's events. The header must
// be a silent skip; anything else is a test failure.
func feedPacket(t *testing.T, p *tcpdumpDNSParser, header, payload string) []DnsEvent {
	t.Helper()
	evs, err := p.feed(header)
	if err != nil || len(evs) != 0 {
		t.Fatalf("header %q: len=%d err=%v, want silent skip", header, len(evs), err)
	}
	evs, err = p.feed(payload)
	if err != nil {
		t.Fatalf("payload %q: unexpected error %v", payload, err)
	}
	return evs
}

// udpHdr is a minimal UDP header line at a fixed time-of-day; the addresses and
// DNS payload live on the following indented line.
const udpHdr = "15:39:41.068677 IP (tos 0x0, ttl 128, id 1, offset 0, flags [none], proto UDP (17), length 63)"

// Golden test over the synthesized fixture with the resolver at 10.0.0.3: the two
// queries, the client-facing responses (single A, CNAME chain -> final A, four
// AAAA, PTR fallback, CNAME-only fallback), the upstream leg dropped, the
// NXDomain/ServFail zero-answer responses skipped, and the TCP packet skipped —
// nothing counted as an error.
func TestTcpdumpFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/dns/tcpdump.txt")
	if err != nil {
		t.Fatal(err)
	}
	p := newTcpdumpDNSParser(time.UTC, tcpBase, "10.0.0.3")

	var got []DnsEvent
	var errs int
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		evs, err := p.feed(line)
		if err != nil {
			errs++
			continue
		}
		got = append(got, evs...)
	}
	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}

	want := []DnsEvent{
		{QName: "example.com", QType: "A", AnswerIP: "", ClientIP: "10.0.0.66", ClientPort: 51578},
		{QName: "spclient.wg.example.com", QType: "HTTPS", AnswerIP: "", ClientIP: "10.0.0.19", ClientPort: 53844},
		{QName: "example.com", QType: "A", AnswerIP: "93.184.216.34", ClientIP: "10.0.0.66", ClientPort: 51578},
		{QName: "tps.example.com", QType: "A", AnswerIP: "93.184.216.34", ClientIP: "10.0.0.250", ClientPort: 64205},
		{QName: "xyp.example.com", QType: "AAAA", AnswerIP: "240e:979:e03:2000:0:3:0:11e", ClientIP: "10.0.0.202", ClientPort: 63989},
		{QName: "xyp.example.com", QType: "AAAA", AnswerIP: "240e:979:e03:2000:0:3:0:279", ClientIP: "10.0.0.202", ClientPort: 63989},
		{QName: "xyp.example.com", QType: "AAAA", AnswerIP: "240e:940:a03:600:d919:2a10:8ee7:1ebd", ClientIP: "10.0.0.202", ClientPort: 63989},
		{QName: "xyp.example.com", QType: "AAAA", AnswerIP: "240e:940:a03:600:d919:2a10:8ee7:1ebf", ClientIP: "10.0.0.202", ClientPort: 63989},
		{QName: "_ipps._tcp.example.network", QType: "PTR", AnswerIP: "", ClientIP: "10.0.0.196", ClientPort: 57668},
		{QName: "go.example.com", QType: "CNAME", AnswerIP: "", ClientIP: "10.0.0.130", ClientPort: 55603},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d events, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.ClientIP != w.ClientIP || g.ClientPort != w.ClientPort || g.QName != w.QName ||
			g.QType != w.QType || g.AnswerIP != w.AnswerIP {
			t.Errorf("event %d = %+v, want %+v", i, g, w)
		}
		if g.TTL != 0 {
			t.Errorf("event %d TTL = %d, want 0 (tcpdump carries no TTL)", i, g.TTL)
		}
	}
}

// Query lines: the QTYPE? marker and qname are found past the txid and any flag
// characters / bracketed options ([1au]); QName is normalized; a query yields one
// query-only event with an empty answer.
func TestTcpdumpQueryLines(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantQName  string
		wantQType  string
		wantClient string
		wantPort   uint16
	}{
		{"plain A query", "    10.0.0.66.51578 > 10.0.0.3.53: 31291+ A? example.com. (35)", "example.com", "A", "10.0.0.66", 51578},
		{"HTTPS with % and [1au]", "    10.0.0.19.53844 > 10.0.0.3.53: 61431+% [1au] HTTPS? SPClient.WG.Example.com. (41)", "spclient.wg.example.com", "HTTPS", "10.0.0.19", 53844},
		{"AAAA query", "    10.0.0.42.40000 > 10.0.0.3.53: 7+ AAAA? ipv6.example.org. (33)", "ipv6.example.org", "AAAA", "10.0.0.42", 40000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
			evs := feedPacket(t, p, udpHdr, tc.payload)
			if len(evs) != 1 {
				t.Fatalf("events = %d, want 1", len(evs))
			}
			e := evs[0]
			if e.QName != tc.wantQName || e.QType != tc.wantQType || e.ClientIP != tc.wantClient ||
				e.ClientPort != tc.wantPort || e.AnswerIP != "" || e.TTL != 0 {
				t.Errorf("event = %+v", e)
			}
		})
	}
}

// Response lines: single A, CNAME chain (QName is the FIRST owner, answer is the
// final A), multi-AAAA (one event per address), PTR/CNAME-only fallback (a single
// no-answer event), and zero-answer NXDomain/ServFail (silent skip — the query
// line already recorded the ask).
func TestTcpdumpResponseLines(t *testing.T) {
	single := "    10.0.0.3.53 > 10.0.0.66.51578: 31291 1/0/0 example.com. A 93.184.216.34 (55)"
	cname := "    10.0.0.3.53 > 10.0.0.250.64205: 51511 4/0/0 tps.example.com. CNAME tps-geo.cdn.example.net., tps-geo.cdn.example.net. CNAME edge.example.org., edge.example.org. CNAME final.example.com., final.example.com. A 93.184.216.34 (140)"
	multiAAAA := "    10.0.0.3.53 > 10.0.0.202.63989: 30123 4/0/0 xyp.example.com. AAAA 240e:979:e03:2000:0:3:0:11e, xyp.example.com. AAAA 240e:979:e03:2000:0:3:0:279 (148)"
	ptr := "    10.0.0.3.53 > 10.0.0.196.57668: 54052 1/0/0 _ipps._tcp.example.network. PTR toshiba._ipps._tcp.example.network. (91)"
	cnameOnly := "    10.0.0.3.53 > 10.0.0.130.55603: 1207| 5/0/0 go.example.com. CNAME a.example.net., a.example.net. CNAME b.example.org. (412)"
	nxdomain := "    10.0.0.3.53 > 10.0.0.66.51578: 31291 NXDomain* 0/1/0 (92)"
	servfail := "    10.0.0.3.53 > 10.0.0.240.46340: 58805 ServFail 0/0/1 (80)"

	t.Run("single A", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		evs := feedPacket(t, p, udpHdr, single)
		if len(evs) != 1 || evs[0].QName != "example.com" || evs[0].QType != "A" || evs[0].AnswerIP != "93.184.216.34" {
			t.Fatalf("events = %+v", evs)
		}
	})
	t.Run("CNAME chain keeps first owner and final A", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		evs := feedPacket(t, p, udpHdr, cname)
		if len(evs) != 1 || evs[0].QName != "tps.example.com" || evs[0].AnswerIP != "93.184.216.34" {
			t.Fatalf("events = %+v", evs)
		}
	})
	t.Run("multi AAAA yields one event per address", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		evs := feedPacket(t, p, udpHdr, multiAAAA)
		if len(evs) != 2 {
			t.Fatalf("events = %d, want 2: %+v", len(evs), evs)
		}
		for _, e := range evs {
			if e.QName != "xyp.example.com" || e.QType != "AAAA" {
				t.Errorf("event = %+v", e)
			}
		}
		if evs[0].AnswerIP != "240e:979:e03:2000:0:3:0:11e" || evs[1].AnswerIP != "240e:979:e03:2000:0:3:0:279" {
			t.Errorf("answers = %q, %q", evs[0].AnswerIP, evs[1].AnswerIP)
		}
	})
	t.Run("PTR answer falls back to a no-answer event", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		evs := feedPacket(t, p, udpHdr, ptr)
		if len(evs) != 1 || evs[0].QName != "_ipps._tcp.example.network" || evs[0].QType != "PTR" || evs[0].AnswerIP != "" {
			t.Fatalf("events = %+v", evs)
		}
	})
	t.Run("truncated txid, CNAME-only falls back", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		evs := feedPacket(t, p, udpHdr, cnameOnly)
		if len(evs) != 1 || evs[0].QName != "go.example.com" || evs[0].QType != "CNAME" || evs[0].AnswerIP != "" {
			t.Fatalf("events = %+v", evs)
		}
	})
	t.Run("NXDomain zero-answer is a silent skip", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		if evs := feedPacket(t, p, udpHdr, nxdomain); len(evs) != 0 {
			t.Fatalf("events = %+v, want silent skip", evs)
		}
	})
	t.Run("ServFail zero-answer is a silent skip", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		if evs := feedPacket(t, p, udpHdr, servfail); len(evs) != 0 {
			t.Fatalf("events = %+v, want silent skip", evs)
		}
	})
}

// The upstream leg to the public forwarder (client == resolver, in either
// direction) is dropped so the client-facing copy isn't double-counted.
func TestTcpdumpUpstreamLegFilter(t *testing.T) {
	// Query leg: resolver 10.0.0.3 asks the public forwarder 1.1.1.1.
	t.Run("query leg dropped", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "10.0.0.3")
		if evs := feedPacket(t, p, udpHdr, "    10.0.0.3.42109 > 1.1.1.1.53: 42716+% [1au] A? ncc.example.com. (54)"); len(evs) != 0 {
			t.Fatalf("events = %+v, want dropped", evs)
		}
	})
	// Response leg: the public forwarder answers the resolver.
	t.Run("response leg dropped", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "10.0.0.3")
		if evs := feedPacket(t, p, udpHdr, "    1.1.1.1.53 > 10.0.0.3.42109: 42716 1/0/0 ncc.example.com. A 93.184.216.34 (70)"); len(evs) != 0 {
			t.Fatalf("events = %+v, want dropped", evs)
		}
	})
	// Without a resolverIP the same query is kept (filter disabled).
	t.Run("filter off keeps the leg", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		if evs := feedPacket(t, p, udpHdr, "    10.0.0.3.42109 > 1.1.1.1.53: 42716+ A? ncc.example.com. (54)"); len(evs) != 1 {
			t.Fatalf("events = %+v, want 1 (filter disabled)", evs)
		}
	})
}

// Structural skips: a non-UDP header clears pending so its payload is skipped, an
// indented line with no pending header is skipped, and a non-header unindented
// line is skipped — none of these are counted as parse errors.
func TestTcpdumpStructuralSkips(t *testing.T) {
	t.Run("non-UDP packet is skipped whole", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		tcpHdr := "15:39:43.000000 IP (tos 0x0, ttl 64, id 10, offset 0, flags [DF], proto TCP (6), length 52)"
		if evs, err := p.feed(tcpHdr); err != nil || len(evs) != 0 {
			t.Fatalf("tcp header: len=%d err=%v", len(evs), err)
		}
		// Its payload has no pending header to attach to -> silent skip, no error.
		if evs, err := p.feed("    10.0.0.5.12345 > 10.0.0.3.53: Flags [S], seq 0, win 64240, length 0"); err != nil || len(evs) != 0 {
			t.Fatalf("tcp payload: len=%d err=%v, want silent skip", len(evs), err)
		}
	})
	t.Run("indented line without a pending header is skipped", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		if evs, err := p.feed("    10.0.0.66.51578 > 10.0.0.3.53: 31291+ A? example.com. (35)"); err != nil || len(evs) != 0 {
			t.Fatalf("orphan payload: len=%d err=%v, want silent skip", len(evs), err)
		}
	})
	t.Run("unindented non-header line is skipped", func(t *testing.T) {
		p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
		if evs, err := p.feed("reading from file capture.pcap, link-type EN10MB"); err != nil || len(evs) != 0 {
			t.Fatalf("banner line: len=%d err=%v, want silent skip", len(evs), err)
		}
	})
}

// A file that ends mid-line (tcpdump killed while writing a header) must not
// error-storm, and once the completed line is re-delivered by a later scan it
// produces exactly one packet — no duplicate or garbage event from the fragment.
func TestTcpdumpMidLineEOF(t *testing.T) {
	p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
	// The scanner holds back a partial final line, but if a truncated header ever
	// reaches feed it must be a harmless skip (no "proto UDP" -> no pending state).
	if evs, err := p.feed("15:50:06.633913 IP (to"); err != nil || len(evs) != 0 {
		t.Fatalf("truncated header: len=%d err=%v, want silent skip", len(evs), err)
	}
	// The next scan re-delivers the now-complete packet; it parses cleanly and the
	// stale fragment left no pending state to corrupt it.
	evs := feedPacket(t, p, udpHdr, "    10.0.0.66.51578 > 10.0.0.3.53: 31291+ A? example.com. (35)")
	if len(evs) != 1 || evs[0].QName != "example.com" {
		t.Fatalf("events = %+v, want the single clean query", evs)
	}
}

// Midnight rollover: a packet whose time-of-day is >1h earlier than the previous
// one has wrapped past midnight, so its event lands on the next calendar day.
func TestTcpdumpMidnightRollover(t *testing.T) {
	p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
	late := "23:59:59.000000 IP (tos 0x0, ttl 128, id 1, offset 0, flags [none], proto UDP (17), length 63)"
	early := "00:00:01.000000 IP (tos 0x0, ttl 128, id 2, offset 0, flags [none], proto UDP (17), length 63)"

	before := feedPacket(t, p, late, "    10.0.0.5.5000 > 10.0.0.3.53: 1+ A? a.example.com. (30)")
	after := feedPacket(t, p, early, "    10.0.0.5.5001 > 10.0.0.3.53: 2+ A? b.example.com. (30)")
	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("before=%d after=%d, want 1 each", len(before), len(after))
	}
	d0 := before[0].EventTime
	d1 := after[0].EventTime
	if !d1.After(d0) {
		t.Errorf("post-midnight event %v not after pre-midnight %v", d1, d0)
	}
	wantDay := d0.AddDate(0, 0, 1).YearDay()
	if d1.YearDay() != wantDay {
		t.Errorf("post-midnight YearDay = %d, want %d (rolled to next day)", d1.YearDay(), wantDay)
	}
}

// TZ is honored: the same packet anchored to the same date differs by exactly 7h
// between UTC and Asia/Bangkok, mirroring the BIND parser's timezone test.
func TestTcpdumpTimezoneShift(t *testing.T) {
	bangkok, err := time.LoadLocation("Asia/Bangkok")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	payload := "    10.0.0.66.51578 > 10.0.0.3.53: 31291+ A? example.com. (35)"

	pu := newTcpdumpDNSParser(time.UTC, time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC), "")
	utc := feedPacket(t, pu, udpHdr, payload)
	pb := newTcpdumpDNSParser(bangkok, time.Date(2026, 7, 13, 0, 0, 0, 0, bangkok), "")
	bkk := feedPacket(t, pb, udpHdr, payload)
	if len(utc) != 1 || len(bkk) != 1 {
		t.Fatalf("utc=%d bkk=%d, want 1 each", len(utc), len(bkk))
	}
	if diff := utc[0].EventTime.Sub(bkk[0].EventTime); diff != 7*time.Hour {
		t.Errorf("utc - bangkok = %v, want 7h", diff)
	}
}

// Malformed payloads that reach the parser must land in the right bucket without
// panicking: a query with a QTYPE? marker but no following name is a counted
// error; a payload with no "SRC > DST:" shape or no port-53 endpoint is a skip.
func TestTcpdumpPayloadEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantCount int
		wantErr   bool
	}{
		{"query with marker but no qname is an error", "    10.0.0.66.51578 > 10.0.0.3.53: 31291+ A?", 0, true},
		{"neither endpoint on port 53 is skipped", "    10.0.0.66.51578 > 10.0.0.3.443: 31291+ A? example.com. (35)", 0, false},
		{"no SRC > DST shape is skipped", "    just some indented noise", 0, false},
		{"bad port is skipped", "    10.0.0.66.xx > 10.0.0.3.53: 31291+ A? example.com. (35)", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTcpdumpDNSParser(time.UTC, tcpBase, "")
			// Prime a pending header so the payload is actually parsed.
			if _, err := p.feed(udpHdr); err != nil {
				t.Fatalf("header err = %v", err)
			}
			evs, err := p.feed(tc.payload)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error=%v", err, tc.wantErr)
			}
			if len(evs) != tc.wantCount {
				t.Errorf("events = %d, want %d", len(evs), tc.wantCount)
			}
		})
	}
}
