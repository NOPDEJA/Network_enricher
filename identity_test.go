package main

import (
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
	s := NewIdentityStore(tok, "", "", maxLease, maxSession, nil)
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
