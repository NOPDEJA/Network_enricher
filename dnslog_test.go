package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Golden test over the fixture: the two query lines, the two response lines with
// A/AAAA answers (one carrying two A records → two events), the NXDOMAIN response
// (query-only event, empty answer), and the lame-server line skipped — nothing
// counted as an error. Hostnames land lowercase with the trailing dot stripped.
func TestParseDNSFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/dns/named.log")
	if err != nil {
		t.Fatal(err)
	}

	var got []DnsEvent
	var errs, skips int
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		evs, err := parseDNSLine(line, time.UTC)
		switch {
		case err != nil:
			errs++
		case len(evs) == 0:
			skips++
		default:
			got = append(got, evs...)
		}
	}

	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}
	if skips != 1 {
		t.Errorf("silent skips = %d, want 1 (lame-server line)", skips)
	}

	want := []DnsEvent{
		{QName: "www.example.com", QType: "A", AnswerIP: "", TTL: 0, ClientIP: "10.0.0.5"},
		{QName: "www.example.com", QType: "A", AnswerIP: "93.184.216.34", TTL: 300, ClientIP: "10.0.0.5"},
		{QName: "www.example.com", QType: "A", AnswerIP: "93.184.216.35", TTL: 300, ClientIP: "10.0.0.5"},
		{QName: "ipv6.example.org", QType: "AAAA", AnswerIP: "2606:2800:220:1:248:1893:25c8:1946", TTL: 120, ClientIP: "10.0.0.8"},
		{QName: "nope.invalid", QType: "", AnswerIP: "", TTL: 0, ClientIP: "10.0.0.9"},
		{QName: "mixedcase.example.com", QType: "A", AnswerIP: "", TTL: 0, ClientIP: "10.0.0.5"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d events, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.ClientIP != w.ClientIP || g.QName != w.QName || g.QType != w.QType ||
			g.AnswerIP != w.AnswerIP || g.TTL != w.TTL {
			t.Errorf("event %d = %+v, want %+v", i, g, w)
		}
	}
}

// Malformed / adversarial input must never panic and must land in the right
// bucket (error vs silent skip vs parsed).
func TestParseDNSLineEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantCount int
		wantErr   bool
	}{
		{"blank line is skipped", "   ", 0, false},
		{"non-query category is skipped", "08-Jul-2026 09:18:00.000 lame-server resolving 'x/A': 8.8.8.8#53", 0, false},
		{"garbage is skipped", "!!! not a log line at all $$$", 0, false},
		{"query with no timestamp is an error", "client 10.0.0.5#5 (h): query: h IN A", 0, true},
		{"query with bad timestamp is an error", "99-Xxx-9999 99:99:99.999 client 10.0.0.5#5 (h): query: h IN A + (10.0.0.1)", 0, true},
		{"well-formed query parses to one event", "08-Jul-2026 09:15:00.123 client 10.0.0.5#54321 (h.example.com): query: h.example.com IN A +E(0)K (10.0.0.1)", 1, false},
		{"response with one A parses to one event", "08-Jul-2026 09:15:00.456 client 10.0.0.5#54321 (h.example.com): response: h.example.com IN A NOERROR h.example.com. 300 IN A 1.2.3.4", 1, false},
		{"response marker without a client prefix is an error", "08-Jul-2026 09:15:00.456 garbled line: response: something here", 0, true},
		{"response-like fragment without the full marker is skipped", "08-Jul-2026 09:15:00.456 client 10.0.0.5#54321 (h): response:", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := parseDNSLine(tc.line, time.UTC)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error=%v", err, tc.wantErr)
			}
			if len(evs) != tc.wantCount {
				t.Errorf("events = %d, want %d", len(evs), tc.wantCount)
			}
		})
	}
}

// The DNS parser honors LOG_TZ the same way the identity parsers do: the same
// line under UTC vs Asia/Bangkok differs by exactly 7h.
func TestParseDNSTimezoneShift(t *testing.T) {
	bangkok, err := time.LoadLocation("Asia/Bangkok")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	line := "08-Jul-2026 09:15:00.123 client 10.0.0.5#54321 (www.example.com): query: www.example.com IN A +E(0)K (10.0.0.1)"
	utc, err := parseDNSLine(line, time.UTC)
	if err != nil || len(utc) != 1 {
		t.Fatalf("utc len=%d err=%v", len(utc), err)
	}
	bkk, err := parseDNSLine(line, bangkok)
	if err != nil || len(bkk) != 1 {
		t.Fatalf("bkk len=%d err=%v", len(bkk), err)
	}
	if diff := utc[0].EventTime.Sub(bkk[0].EventTime); diff != 7*time.Hour {
		t.Errorf("utc - bangkok = %v, want 7h", diff)
	}
}
