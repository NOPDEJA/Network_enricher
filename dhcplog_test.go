package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Golden test: the fixture's preamble, header, blank lines, and the event-24
// row must all be skipped structurally, leaving exactly the assign/renew/release
// lease events — with nothing counted as an error.
func TestParseDHCPFixture(t *testing.T) {
	tok := newTestTokenizer(t, "golden-key")
	data, err := os.ReadFile("testdata/dhcp/DhcpSrvLog-Wed.log")
	if err != nil {
		t.Fatal(err)
	}

	var got []DhcpEvent
	var errs int
	for _, line := range strings.Split(string(data), "\n") {
		ev, ok, err := parseDHCPLine(line, tok, time.UTC)
		if err != nil {
			errs++
			continue
		}
		if ok {
			got = append(got, ev)
		}
	}

	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}
	want := []struct {
		id   uint16
		when time.Time
	}{
		{10, mustTime(t, dhcpTimeLayout, "07/08/26 09:16:00")},
		{11, mustTime(t, dhcpTimeLayout, "07/08/26 09:45:00")},
		{12, mustTime(t, dhcpTimeLayout, "07/08/26 10:05:00")},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d events, want %d", len(got), len(want))
	}
	wantMAC := tok.MACToken("AABBCCDDEEFF")
	wantHost := tok.HostToken("laptop-01.muic.local")
	for i, w := range want {
		g := got[i]
		if g.EventID != w.id || !g.EventTime.Equal(w.when) {
			t.Errorf("event %d = (%d,%s), want (%d,%s)", i, g.EventID, g.EventTime, w.id, w.when)
		}
		if g.IP != "10.10.20.30" || g.MACToken != wantMAC || g.HostToken != wantHost {
			t.Errorf("event %d field mismatch: ip=%q mac=%q host=%q", i, g.IP, g.MACToken, g.HostToken)
		}
	}
}

func TestParseDHCPLineEdgeCases(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	tests := []struct {
		name    string
		line    string
		wantOK  bool
		wantErr bool
	}{
		{"preamble text is skipped", "Microsoft DHCP Service Activity Log", false, false},
		{"header row is skipped", "ID,Date,Time,Description,IP Address,Host Name,MAC Address", false, false},
		{"blank line is skipped", "   ", false, false},
		{"non-lease event id is skipped", "01,07/08/26,09:00:00,Log stopped", false, false},
		{"assign parses", "10,07/08/26,09:16:00,Assign,10.10.20.30,host,AABBCCDDEEFF,,1,6,0,,", true, false},
		{"lease row too short is an error", "10,07/08/26,09:16:00,Assign", false, true},
		{"lease row with bad date is an error", "11,99/99/99,09:16:00,Renew,10.0.0.1,host,AABBCCDDEEFF,", false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := parseDHCPLine(tc.line, tok, time.UTC)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error=%v", err, tc.wantErr)
			}
		})
	}
}
