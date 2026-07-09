package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

var identBase = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

// newClockedStore returns a store with a test-controlled clock (*time.Time) so
// deadline behavior is deterministic. No ClickHouse conn.
func newClockedStore(t *testing.T, maxLease, maxSession time.Duration) (*IdentityStore, *time.Time) {
	t.Helper()
	tok := newTestTokenizer(t, "identity-test-key")
	s := NewIdentityStore(tok, "", "", time.UTC, time.UTC, maxLease, maxSession, nil)
	clk := new(time.Time)
	*clk = identBase
	s.now = func() time.Time { return *clk }
	return s, clk
}

// DHCP lease intervals: tagged inside the lease, untagged after release, a
// reassignment to a new MAC wins, and a lease older than maxLease expires.
func TestDHCPLeaseIntervals(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	mac1 := s.tok.MACToken("11:11:11:11:11:11")
	mac2 := s.tok.MACToken("22:22:22:22:22:22")

	t.Run("inside lease is tagged", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.5", MACToken: mac1})
		*clk = identBase.Add(1 * time.Hour)
		if mac, _ := s.Lookup("10.0.0.5"); mac != mac1 {
			t.Errorf("mac = %q, want %q (inside lease)", mac, mac1)
		}
	})

	t.Run("after release is untagged", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(2 * time.Hour), EventID: 12, IP: "10.0.0.5", MACToken: mac1})
		*clk = identBase.Add(3 * time.Hour)
		if mac, _ := s.Lookup("10.0.0.5"); mac != "" {
			t.Errorf("mac = %q, want empty (after release)", mac)
		}
	})

	t.Run("reassignment to a new MAC wins", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.9", MACToken: mac1})
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(1 * time.Hour), EventID: 10, IP: "10.0.0.9", MACToken: mac2})
		*clk = identBase.Add(2 * time.Hour)
		if mac, _ := s.Lookup("10.0.0.9"); mac != mac2 {
			t.Errorf("mac = %q, want %q (new binding wins)", mac, mac2)
		}
	})

	t.Run("lease older than maxLease expires", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.7", MACToken: mac1})
		*clk = identBase.Add(25 * time.Hour)
		if mac, _ := s.Lookup("10.0.0.7"); mac != "" {
			t.Errorf("mac = %q, want empty (lease expired)", mac)
		}
	})
}

// RADIUS sessions: a Start opens the window, a Stop closes it (lease still tags
// the device), a re-auth with a new session keeps the user resolvable, and a
// session with no Stop expires after the idle bound while the lease survives.
func TestRADIUSSessions(t *testing.T) {
	t.Run("start opens, stop closes, re-auth reopens", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.1.2", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})

		*clk = identBase.Add(1 * time.Hour)
		if m, u := s.Lookup("10.0.1.2"); m != mac || u != user {
			t.Fatalf("during session: (%q,%q), want (%q,%q)", m, u, mac, user)
		}

		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(2 * time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac})
		*clk = identBase.Add(3 * time.Hour)
		if m, u := s.Lookup("10.0.1.2"); m != mac || u != "" {
			t.Fatalf("after stop: (%q,%q), want (%q, empty) — device still tagged, user gone", m, u, mac)
		}

		// Re-auth: brand new session, same MAC, user resolvable again.
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(4 * time.Hour), AcctStatus: "Start", SessionID: "S2", UserToken: user, MACToken: mac})
		*clk = identBase.Add(5 * time.Hour)
		if m, u := s.Lookup("10.0.1.2"); m != mac || u != user {
			t.Fatalf("after re-auth: (%q,%q), want (%q,%q)", m, u, mac, user)
		}
	})

	t.Run("a stale stop does not close a newer session", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.1.3", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S2", UserToken: user, MACToken: mac})
		// Late Stop for the previous session S1 must not tear down S2.
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac})
		*clk = identBase.Add(2 * time.Hour)
		if m, u := s.Lookup("10.0.1.3"); m != mac || u != user {
			t.Fatalf("(%q,%q), want (%q,%q) — stale Stop ignored", m, u, mac, user)
		}
	})

	t.Run("session with no stop expires after idle bound, lease survives", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 1*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.1.4", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
		*clk = identBase.Add(2 * time.Hour) // past 1h idle bound
		if m, u := s.Lookup("10.0.1.4"); m != mac || u != "" {
			t.Fatalf("(%q,%q), want (%q, empty) — session idled out, device still leased", m, u, mac)
		}
	})
}

// Roam: a device moving to a new IP mid-session keeps the same user token,
// because the join hop is the MAC, not the address.
func TestRoamSameMACSameUser(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	mac := s.tok.MACToken("de:ad:be:ef:00:01")
	user := s.tok.UserToken("student01")

	s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
	s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.1.0.10", MACToken: mac})
	*clk = identBase.Add(1 * time.Hour)
	if _, u := s.Lookup("10.1.0.10"); u != user {
		t.Fatalf("pre-roam user = %q, want %q", u, user)
	}

	// Roam to a new subnet: new lease, same MAC, session unchanged.
	s.applyDHCP(DhcpEvent{EventTime: identBase.Add(2 * time.Hour), EventID: 10, IP: "10.2.0.20", MACToken: mac})
	*clk = identBase.Add(3 * time.Hour)
	if m, u := s.Lookup("10.2.0.20"); m != mac || u != user {
		t.Fatalf("post-roam (%q,%q), want (%q,%q)", m, u, mac, user)
	}
}

// Fail open: an unknown IP resolves to empty tokens, and enrich() returns the
// flow untouched rather than dropping it.
func TestIdentityFailOpen(t *testing.T) {
	s, _ := newClockedStore(t, 24*time.Hour, 24*time.Hour)

	if m, u := s.Lookup("203.0.113.99"); m != "" || u != "" {
		t.Errorf("unknown IP = (%q,%q), want empty", m, u)
	}

	in := FlowMessage{SrcAddr: "203.0.113.99", DstAddr: "8.8.8.8", Bytes: 1500}
	e := enrich(in, nil, nil, nil, s)
	if e.SrcMACToken != "" || e.SrcUserToken != "" || e.DstMACToken != "" || e.DstUserToken != "" {
		t.Error("unknown addresses should stamp no tokens")
	}
	if e.SrcAddr != in.SrcAddr || e.DstAddr != in.DstAddr || e.Bytes != in.Bytes {
		t.Error("flow fields must pass through untouched")
	}
}

// enrich() stamps tokens for a resolvable source address and leaves the
// external destination empty.
func TestEnrichStampsIdentity(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	mac := s.tok.MACToken("11:22:33:44:55:66")
	user := s.tok.UserToken("prof.smith")
	s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.10.20.30", MACToken: mac})
	s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
	*clk = identBase.Add(30 * time.Minute)

	e := enrich(FlowMessage{SrcAddr: "10.10.20.30", DstAddr: "8.8.8.8"}, nil, nil, nil, s)
	if e.SrcMACToken != mac || e.SrcUserToken != user {
		t.Errorf("src tokens = (%q,%q), want (%q,%q)", e.SrcMACToken, e.SrcUserToken, mac, user)
	}
	if e.DstMACToken != "" || e.DstUserToken != "" {
		t.Errorf("dst tokens = (%q,%q), want empty", e.DstMACToken, e.DstUserToken)
	}
}

// A Stop record missing its Acct-Session-Id (SessionID == "") must not tear down
// a live named session on the same MAC — it may only close a binding whose
// stored session ID is also empty.
func TestStopEmptySessionDoesNotCloseNamedSession(t *testing.T) {
	s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
	mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
	user := s.tok.UserToken("jdoe")
	s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.1", MACToken: mac})
	s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})

	s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Stop", SessionID: "", UserToken: user, MACToken: mac})
	*clk = identBase.Add(2 * time.Hour)
	if m, u := s.Lookup("10.0.0.1"); m != mac || u != user {
		t.Fatalf("(%q,%q), want (%q,%q) — empty-session Stop must not close a named session", m, u, mac, user)
	}
}

// Newest-event-wins for RADIUS: a stale older Interim from a prior session must
// not clobber a newer active session, while an Interim whose Start we never saw
// still bootstraps state.
func TestRADIUSNewestWins(t *testing.T) {
	t.Run("older interim from a prior session does not clobber a newer one", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		userA := s.tok.UserToken("alice")
		userB := s.tok.UserToken("bob")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.2", MACToken: mac})
		// Newer session S2/bob is active.
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(2 * time.Hour), AcctStatus: "Start", SessionID: "S2", UserToken: userB, MACToken: mac})
		// A stale, out-of-order Interim for the prior session S1/alice arrives after.
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Interim-Update", SessionID: "S1", UserToken: userA, MACToken: mac})
		*clk = identBase.Add(3 * time.Hour)
		if _, u := s.Lookup("10.0.0.2"); u != userB {
			t.Fatalf("user = %q, want %q — stale older Interim must not clobber the newer session", u, userB)
		}
	})

	t.Run("a newer-session interim without a seen start bootstraps", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("carol")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.3", MACToken: mac})
		// Only an Interim is seen (the Start was missed, e.g. enricher started mid-session).
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Interim-Update", SessionID: "S9", UserToken: user, MACToken: mac})
		*clk = identBase.Add(2 * time.Hour)
		if _, u := s.Lookup("10.0.0.3"); u != user {
			t.Fatalf("user = %q, want %q — a newer-session Interim must bootstrap state", u, user)
		}
	})
}

// Newest-event-wins for DHCP: an older event replayed (restart re-read, or a
// multi-file scan applying files out of order) must not roll state back.
func TestDHCPNewestWins(t *testing.T) {
	s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
	mac1 := s.tok.MACToken("11:11:11:11:11:11")
	mac2 := s.tok.MACToken("22:22:22:22:22:22")

	// Newer assign binds the IP to mac2; an older assign (replay) to mac1 arrives after.
	s.applyDHCP(DhcpEvent{EventTime: identBase.Add(2 * time.Hour), EventID: 10, IP: "10.0.0.4", MACToken: mac2})
	s.applyDHCP(DhcpEvent{EventTime: identBase.Add(1 * time.Hour), EventID: 10, IP: "10.0.0.4", MACToken: mac1})
	*clk = identBase.Add(3 * time.Hour)
	if m, _ := s.Lookup("10.0.0.4"); m != mac2 {
		t.Fatalf("mac = %q, want %q — older replayed assign must not overwrite newer state", m, mac2)
	}

	// A stale release older than the current binding must not close the lease.
	s.applyDHCP(DhcpEvent{EventTime: identBase.Add(1 * time.Hour), EventID: 12, IP: "10.0.0.4", MACToken: mac2})
	if m, _ := s.Lookup("10.0.0.4"); m != mac2 {
		t.Fatalf("mac = %q, want %q — stale older release must not close a newer lease", m, mac2)
	}
}

// Shutdown drain: events still buffered when the poller stopped are sent by
// FinalFlush; if ClickHouse never recovers, FinalFlush reports the lost count.
func TestFinalFlushDrainsBufferedEvents(t *testing.T) {
	s, _ := newClockedStore(t, time.Hour, time.Hour)
	sentDHCP, sentRadius := 0, 0
	w := &chEventWriter{maxBuffer: 100}
	w.sendDHCPFn = func(rows []DhcpEvent) error { sentDHCP += len(rows); return nil }
	w.sendRadiusFn = func(rows []RadiusEvent) error { sentRadius += len(rows); return nil }
	s.ch = w

	w.addDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.1", MACToken: "m"})
	w.addRadius(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", MACToken: "m"})

	if lost := s.FinalFlush(3); lost != 0 {
		t.Fatalf("FinalFlush lost %d events, want 0", lost)
	}
	if sentDHCP != 1 || sentRadius != 1 {
		t.Fatalf("sent dhcp=%d radius=%d, want 1/1", sentDHCP, sentRadius)
	}

	// A permanently-failing ClickHouse: FinalFlush exhausts attempts and reports loss.
	chDown := errors.New("clickhouse down")
	fw := &chEventWriter{maxBuffer: 100}
	fw.sendDHCPFn = func([]DhcpEvent) error { return chDown }
	fw.sendRadiusFn = func([]RadiusEvent) error { return chDown }
	fw.addDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.2", MACToken: "m"})
	s.ch = fw
	if lost := s.FinalFlush(2); lost != 1 {
		t.Fatalf("FinalFlush = %d, want 1 (all attempts failed)", lost)
	}
}

// The poller has no supervisor, so a panic while parsing untrusted input must be
// caught by scan()'s recover: the process keeps ingesting and the panic is
// counted rather than silently killing identity for the process lifetime.
func TestScanRecoversFromPanic(t *testing.T) {
	dir := t.TempDir()
	line := `<Event><Timestamp data_type="4">07/08/2026 09:15:00.100</Timestamp>` +
		`<User-Name data_type="1">MUIC\jdoe</User-Name>` +
		`<Calling-Station-Id data_type="1">AA-BB-CC-DD-EE-FF</Calling-Station-Id>` +
		`<Acct-Status-Type data_type="0">1</Acct-Status-Type>` +
		`<Acct-Session-Id data_type="1">S1</Acct-Session-Id></Event>` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "in.log"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := newClockedStore(t, time.Hour, time.Hour)
	s.npsDir = dir
	s.tok = nil // tokenizing with a nil Tokenizer panics inside the scan

	before := testutil.ToFloat64(identityScanPanics)
	s.scan() // must not propagate the panic
	if delta := testutil.ToFloat64(identityScanPanics) - before; delta != 1 {
		t.Fatalf("scan panic metric delta = %v, want 1", delta)
	}
}

// Malformed lines are skipped with the error metric incremented, and the parser
// keeps going — the good events before and after the bad one still land.
func TestIngestContinuesPastMalformed(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	*clk = identBase.Add(1 * time.Hour)

	before := testutil.ToFloat64(identityParseErrors.WithLabelValues(sourceDHCP))
	lines := []string{
		"10,07/08/26,12:00:00,Assign,10.5.5.5,host-a,AABBCCDDEEFF,,1,6,0,,", // good
		"10,07/08/26,BADTIME,Assign,10.5.5.6,host-b,AABBCCDDEEFF,,1,6,0,,",  // malformed (bad time)
		"11,07/08/26,12:05:00,Renew,10.5.5.7,host-c,112233445566,,1,6,0,,",  // good
	}
	for _, l := range lines {
		s.ingestDHCP(l)
	}

	if delta := testutil.ToFloat64(identityParseErrors.WithLabelValues(sourceDHCP)) - before; delta != 1 {
		t.Errorf("dhcp parse errors delta = %v, want 1", delta)
	}
	if mac, _ := s.Lookup("10.5.5.5"); mac == "" {
		t.Error("good event before the malformed line was not applied")
	}
	if mac, _ := s.Lookup("10.5.5.7"); mac == "" {
		t.Error("good event after the malformed line was not applied")
	}
	if mac, _ := s.Lookup("10.5.5.6"); mac != "" {
		t.Error("malformed line must not create a binding")
	}
}
