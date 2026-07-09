package main

import (
	"testing"
	"time"
)

// The LOG_TZ knob must change how a naive log timestamp is anchored: the same
// line parsed as Asia/Bangkok (UTC+7) is 7h earlier in absolute (UTC) terms
// than parsed as UTC. Covers all three parsers that take a *time.Location.
func TestLogTimezoneShift(t *testing.T) {
	bangkok, err := time.LoadLocation("Asia/Bangkok")
	if err != nil {
		t.Fatalf("LoadLocation(Asia/Bangkok): %v (is _ \"time/tzdata\" imported?)", err)
	}
	tok := newTestTokenizer(t, "tz-key")

	const sevenHours = 7 * time.Hour

	t.Run("dhcp", func(t *testing.T) {
		line := "10,07/08/26,09:16:00,Assign,10.10.20.30,host,AABBCCDDEEFF,,1,6,0,,"
		utcEv, ok, err := parseDHCPLine(line, tok, time.UTC)
		if err != nil || !ok {
			t.Fatalf("utc parse ok=%v err=%v", ok, err)
		}
		bkkEv, ok, err := parseDHCPLine(line, tok, bangkok)
		if err != nil || !ok {
			t.Fatalf("bkk parse ok=%v err=%v", ok, err)
		}
		if diff := utcEv.EventTime.Sub(bkkEv.EventTime); diff != sevenHours {
			t.Errorf("utc - bangkok = %v, want %v", diff, sevenHours)
		}
	})

	t.Run("nps", func(t *testing.T) {
		line := `<Event><Timestamp data_type="4">07/08/2026 09:15:00.100</Timestamp>` +
			`<Calling-Station-Id data_type="1">AA-BB-CC-DD-EE-FF</Calling-Station-Id>` +
			`<Acct-Status-Type data_type="0">1</Acct-Status-Type>` +
			`<Acct-Session-Id data_type="1">S1</Acct-Session-Id></Event>`
		utcEv, ok, err := parseNPSLine(line, tok, time.UTC)
		if err != nil || !ok {
			t.Fatalf("utc parse ok=%v err=%v", ok, err)
		}
		bkkEv, ok, err := parseNPSLine(line, tok, bangkok)
		if err != nil || !ok {
			t.Fatalf("bkk parse ok=%v err=%v", ok, err)
		}
		if diff := utcEv.EventTime.Sub(bkkEv.EventTime); diff != sevenHours {
			t.Errorf("utc - bangkok = %v, want %v", diff, sevenHours)
		}
	})
}
