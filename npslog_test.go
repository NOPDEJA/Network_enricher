package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T, layout, v string) time.Time {
	t.Helper()
	ts, err := time.Parse(layout, v)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// Golden test: the fixture holds a Start, an Interim-Update, a Stop, one auth
// event (no Acct-Status-Type), and one Accounting-On (status 7). Only the three
// session events parse; the other two are silent skips; nothing errors.
func TestParseNPSFixture(t *testing.T) {
	tok := newTestTokenizer(t, "golden-key")
	data, err := os.ReadFile("testdata/nps/IN2607.log")
	if err != nil {
		t.Fatal(err)
	}

	var got []RadiusEvent
	var errs, skips int
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		ev, ok, err := parseNPSLine(line, tok, time.UTC)
		switch {
		case err != nil:
			errs++
		case !ok:
			skips++
		default:
			got = append(got, ev)
		}
	}

	if errs != 0 {
		t.Errorf("errors = %d, want 0", errs)
	}
	if skips != 2 {
		t.Errorf("silent skips = %d, want 2 (auth event + Accounting-On)", skips)
	}
	want := []struct {
		status  string
		session string
		when    time.Time
	}{
		// The fixture's Start carries ".100"; parse truncates to whole seconds to
		// match the DateTime column (see TestParseNPSTruncatesToSecond), so the
		// expected times use the second-resolution layout.
		{"Start", "SESSION-A", mustTime(t, dtsTimeLayouts[1], "07/08/2026 09:15:00")},
		{"Interim-Update", "SESSION-A", mustTime(t, dtsTimeLayouts[1], "07/08/2026 09:20:00")},
		{"Stop", "SESSION-A", mustTime(t, dtsTimeLayouts[1], "07/08/2026 10:00:00")},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d events, want %d", len(got), len(want))
	}
	wantMAC := tok.MACToken("AA-BB-CC-DD-EE-FF")
	wantUser := tok.UserToken("MUIC\\jdoe")
	for i, w := range want {
		g := got[i]
		if g.AcctStatus != w.status || g.SessionID != w.session || !g.EventTime.Equal(w.when) {
			t.Errorf("event %d = (%s,%s,%s), want (%s,%s,%s)",
				i, g.AcctStatus, g.SessionID, g.EventTime, w.status, w.session, w.when)
		}
		if g.MACToken != wantMAC || g.UserToken != wantUser {
			t.Errorf("event %d tokens mismatch", i)
		}
	}
}

func TestParseNPSLineEdgeCases(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	tests := []struct {
		name    string
		line    string
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "auth event without acct-status is skipped, not an error",
			line:   `<Event><Timestamp data_type="4">07/08/2026 09:00:00.000</Timestamp><User-Name data_type="1">jdoe</User-Name><Packet-Type data_type="0">1</Packet-Type></Event>`,
			wantOK: false, wantErr: false,
		},
		{
			name:   "accounting-on (status 7) is skipped, not an error",
			line:   `<Event><Timestamp data_type="4">07/08/2026 09:00:00.000</Timestamp><Acct-Status-Type data_type="0">7</Acct-Status-Type></Event>`,
			wantOK: false, wantErr: false,
		},
		{
			name:   "empty line is skipped",
			line:   "   ",
			wantOK: false, wantErr: false,
		},
		{
			name:   "malformed XML is an error",
			line:   `<Event><Acct-Status-Type data_type="0">1</Acct-Status`,
			wantOK: false, wantErr: true,
		},
		{
			name:   "accounting event missing timestamp is an error",
			line:   `<Event><Acct-Status-Type data_type="0">1</Acct-Status-Type><Acct-Session-Id data_type="1">S1</Acct-Session-Id></Event>`,
			wantOK: false, wantErr: true,
		},
		{
			name:   "textual acct-status spelling is accepted",
			line:   `<Event><Timestamp data_type="4">07/08/2026 09:00:00.000</Timestamp><Acct-Status-Type data_type="1">Stop</Acct-Status-Type></Event>`,
			wantOK: true, wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := parseNPSLine(tc.line, tok, time.UTC)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error=%v", err, tc.wantErr)
			}
		})
	}
}

// NPS's default DTS Timestamp carries milliseconds, but
// identity_radius_events.event_time is DateTime (whole seconds) AND part of the
// table's ORDER BY. If the parser kept the sub-second part, the live store would
// order two same-second events by a precision that never reaches ClickHouse,
// and cmd/trace — reading the truncated values back — would resolve the same tie
// differently. Truncate at parse so both sides see identical timestamps.
func TestParseNPSTruncatesToSecond(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	tests := []struct {
		name string
		ts   string
		want time.Time
	}{
		{
			name: "milliseconds are dropped, not rounded up",
			ts:   "07/08/2026 09:15:00.999",
			want: time.Date(2026, 7, 8, 9, 15, 0, 0, time.UTC),
		},
		{
			name: "milliseconds are dropped, not rounded down to the wrong second",
			ts:   "07/08/2026 09:15:01.001",
			want: time.Date(2026, 7, 8, 9, 15, 1, 0, time.UTC),
		},
		{
			name: "a millisecond-less timestamp is unaffected",
			ts:   "07/08/2026 09:15:02",
			want: time.Date(2026, 7, 8, 9, 15, 2, 0, time.UTC),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := `<Event><Timestamp data_type="4">` + tc.ts +
				`</Timestamp><Acct-Status-Type data_type="0">1</Acct-Status-Type>` +
				`<Acct-Session-Id data_type="1">S1</Acct-Session-Id></Event>`
			ev, ok, err := parseNPSLine(line, tok, time.UTC)
			if err != nil || !ok {
				t.Fatalf("parseNPSLine: ok=%v err=%v", ok, err)
			}
			if !ev.EventTime.Equal(tc.want) {
				t.Fatalf("EventTime = %s, want %s", ev.EventTime, tc.want)
			}
			if ev.EventTime.Nanosecond() != 0 {
				t.Fatalf("EventTime has a sub-second component: %d ns", ev.EventTime.Nanosecond())
			}
		})
	}
}
