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
	s := NewIdentityStore(tok, "", "", "", time.UTC, time.UTC, maxLease, maxSession, nil)
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

// A Kea lease carries its real expiry in Deadline, which must clamp the trust
// window when it lands sooner than maxLease — trusting a lease past its actual
// expiry is a false-attribution window. maxLease still hard-caps a Deadline that
// lands later, and a zero Deadline (the Windows audit log) is unchanged.
func TestLeaseDeadlineClamp(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")

	t.Run("real expiry sooner than maxLease wins", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.1.1", MACToken: mac,
			Deadline: identBase.Add(1 * time.Hour)})
		*clk = identBase.Add(30 * time.Minute)
		if m, _ := s.Lookup("10.0.1.1"); m != mac {
			t.Errorf("mac = %q, want %q (before the real expiry)", m, mac)
		}
		*clk = identBase.Add(90 * time.Minute)
		if m, _ := s.Lookup("10.0.1.1"); m != "" {
			t.Errorf("mac = %q, want empty (past the real expiry)", m)
		}
	})

	t.Run("maxLease still caps a longer real expiry", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.1.2", MACToken: mac,
			Deadline: identBase.Add(72 * time.Hour)})
		*clk = identBase.Add(25 * time.Hour)
		if m, _ := s.Lookup("10.0.1.2"); m != "" {
			t.Errorf("mac = %q, want empty (maxLease is the hard cap)", m)
		}
	})

	t.Run("zero deadline keeps maxLease behavior", func(t *testing.T) {
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.1.3", MACToken: mac})
		*clk = identBase.Add(90 * time.Minute)
		if m, _ := s.Lookup("10.0.1.3"); m != mac {
			t.Errorf("mac = %q, want %q (windows event, maxLease horizon)", m, mac)
		}
		*clk = identBase.Add(25 * time.Hour)
		if m, _ := s.Lookup("10.0.1.3"); m != "" {
			t.Errorf("mac = %q, want empty (past maxLease)", m)
		}
	})
}

// Kea rows ingest through the same fold as the Windows audit log, under the
// "kea" metric label, and a malformed lease row is counted and skipped rather
// than killing the poller.
func TestIngestKea(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	*clk = time.Unix(1783001000, 0).UTC()

	before := testutil.ToFloat64(identityParseErrors.WithLabelValues(sourceKea))
	lines := []string{
		"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id",
		"10.0.2.1,aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,host-a,0,,0", // good assign
		"10.0.2.2,11:22:33:44:55:66,,BAD,1783003600,1,0,0,host-b,0,,0",  // malformed
		"10.0.2.3,11:22:33:44:55:66,,3600,1783003600,1,0,0,host-c,0,,0", // good assign
	}
	for _, l := range lines {
		s.ingestKea(l)
	}

	if delta := testutil.ToFloat64(identityParseErrors.WithLabelValues(sourceKea)) - before; delta != 1 {
		t.Errorf("kea parse errors delta = %v, want 1", delta)
	}
	if m, _ := s.Lookup("10.0.2.1"); m != s.tok.MACToken("aa:bb:cc:dd:ee:ff") {
		t.Errorf("kea assign not applied: mac = %q", m)
	}
	if m, _ := s.Lookup("10.0.2.2"); m != "" {
		t.Error("malformed kea row must not create a binding")
	}
	if m, _ := s.Lookup("10.0.2.3"); m == "" {
		t.Error("good kea row after the malformed one was not applied")
	}

	// Past the lease's own expire (1783003600) the binding stops resolving even
	// though maxLease is 24h.
	*clk = time.Unix(1783003601, 0).UTC()
	if m, _ := s.Lookup("10.0.2.1"); m != "" {
		t.Errorf("mac = %q, want empty past the kea lease expiry", m)
	}
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
	e := enrich(in, nil, nil, nil, s, nil)
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

	e := enrich(FlowMessage{SrcAddr: "10.10.20.30", DstAddr: "8.8.8.8"}, nil, nil, nil, s, nil)
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

// Tombstones: a release/Stop must not be resurrected by a later OUT-OF-ORDER
// older open event (the resurrection bug). Offsets are in-memory, so a restart
// re-reads files from 0 and a multi-file scan applies files in arbitrary order,
// making a replayed older assign/Start a real path.
func TestTombstoneNoResurrection(t *testing.T) {
	t.Run("dhcp: older assign replayed after release does not resurrect", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("11:11:11:11:11:11")
		// assign at +1h, release at +2h, then an OLDER assign at +1h replayed.
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(1 * time.Hour), EventID: 10, IP: "10.0.0.5", MACToken: mac})
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(2 * time.Hour), EventID: 12, IP: "10.0.0.5", MACToken: mac})
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(1 * time.Hour), EventID: 10, IP: "10.0.0.5", MACToken: mac})
		*clk = identBase.Add(3 * time.Hour)
		if m, u := s.Lookup("10.0.0.5"); m != "" || u != "" {
			t.Fatalf("(%q,%q), want empty — older replayed assign must not resurrect a released lease", m, u)
		}
	})

	t.Run("radius: older start replayed after stop does not resurrect", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		// Live lease so macState absence, not ipState, is what drops the user.
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.6", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(2 * time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac})
		// OLDER Start for the same session replayed after the Stop.
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
		*clk = identBase.Add(3 * time.Hour)
		if m, u := s.Lookup("10.0.0.6"); m != mac || u != "" {
			t.Fatalf("(%q,%q), want (%q, empty) — older replayed Start must not resurrect a stopped session", m, u, mac)
		}
	})

	t.Run("radius: older interim from a different session does not resurrect", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		other := s.tok.UserToken("mallory")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.7", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(2 * time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Interim-Update", SessionID: "S0", UserToken: other, MACToken: mac})
		*clk = identBase.Add(3 * time.Hour)
		if m, u := s.Lookup("10.0.0.7"); m != mac || u != "" {
			t.Fatalf("(%q,%q), want (%q, empty) — older cross-session Interim must not resurrect a stopped session", m, u, mac)
		}
	})
}

// Same-second open-vs-close tie on an established binding resolves to CLOSED
// regardless of the arrival order of the tied pair, matching the deterministic
// tie-break pinned in cmd/trace. (A close for an IP/MAC with no prior binding is
// a no-op — there is nothing to tombstone — so the pair is applied against a
// lease/session established a step earlier, which is the realistic case.)
func TestTombstoneSameSecondTie(t *testing.T) {
	t.Run("dhcp assign+release tie, both orders", func(t *testing.T) {
		for _, order := range []string{"assign-first", "release-first"} {
			t.Run(order, func(t *testing.T) {
				s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
				mac := s.tok.MACToken("11:11:11:11:11:11")
				// Established lease a step before the tied pair.
				s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.8", MACToken: mac})
				assign := DhcpEvent{EventTime: identBase.Add(time.Hour), EventID: 10, IP: "10.0.0.8", MACToken: mac}
				release := DhcpEvent{EventTime: identBase.Add(time.Hour), EventID: 12, IP: "10.0.0.8", MACToken: mac}
				if order == "assign-first" {
					s.applyDHCP(assign)
					s.applyDHCP(release)
				} else {
					s.applyDHCP(release)
					s.applyDHCP(assign)
				}
				*clk = identBase.Add(2 * time.Hour)
				if m, _ := s.Lookup("10.0.0.8"); m != "" {
					t.Fatalf("mac = %q, want empty — same-second assign/release tie must resolve to closed", m)
				}
			})
		}
	})

	t.Run("radius start+stop tie, both orders", func(t *testing.T) {
		for _, order := range []string{"start-first", "stop-first"} {
			t.Run(order, func(t *testing.T) {
				s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
				mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
				user := s.tok.UserToken("jdoe")
				s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.9", MACToken: mac})
				// Established session a step before the tied pair.
				s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
				start := RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac}
				stop := RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac}
				if order == "start-first" {
					s.applyRADIUS(start)
					s.applyRADIUS(stop)
				} else {
					s.applyRADIUS(stop)
					s.applyRADIUS(start)
				}
				*clk = identBase.Add(2 * time.Hour)
				if m, u := s.Lookup("10.0.0.9"); m != mac || u != "" {
					t.Fatalf("(%q,%q), want (%q, empty) — same-second Start/Stop tie must resolve to closed", m, u, mac)
				}
			})
		}
	})
}

// Cross-entity same-second handover: a close of the OLD entity and a same-second
// open of a NEW entity (re-auth / lease-reassign at second resolution) must end
// with the new entity attributed, in either arrival order. The strictly-newer
// reopen guard applies only to the SAME entity, so it must not swallow this.
func TestTombstoneCrossEntitySameSecondHandover(t *testing.T) {
	t.Run("dhcp release MAC1 + assign MAC2 same second, both orders", func(t *testing.T) {
		for _, order := range []string{"release-first", "assign-first"} {
			t.Run(order, func(t *testing.T) {
				s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
				mac1 := s.tok.MACToken("11:11:11:11:11:11")
				mac2 := s.tok.MACToken("22:22:22:22:22:22")
				// mac1 leased a step before the handover.
				s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.13", MACToken: mac1})
				release := DhcpEvent{EventTime: identBase.Add(time.Hour), EventID: 12, IP: "10.0.0.13", MACToken: mac1}
				assign := DhcpEvent{EventTime: identBase.Add(time.Hour), EventID: 10, IP: "10.0.0.13", MACToken: mac2}
				if order == "release-first" {
					s.applyDHCP(release)
					s.applyDHCP(assign)
				} else {
					s.applyDHCP(assign)
					s.applyDHCP(release)
				}
				*clk = identBase.Add(2 * time.Hour)
				if m, _ := s.Lookup("10.0.0.13"); m != mac2 {
					t.Fatalf("mac = %q, want %q — same-second cross-MAC handover must leave the new MAC leased", m, mac2)
				}
			})
		}
	})

	t.Run("radius stop S1 + start S2 same second, both orders", func(t *testing.T) {
		for _, order := range []string{"stop-first", "start-first"} {
			t.Run(order, func(t *testing.T) {
				s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
				mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
				userA := s.tok.UserToken("alice")
				userB := s.tok.UserToken("bob")
				s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.14", MACToken: mac})
				s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Start", SessionID: "S1", UserToken: userA, MACToken: mac})
				stop := RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: userA, MACToken: mac}
				start := RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Start", SessionID: "S2", UserToken: userB, MACToken: mac}
				if order == "stop-first" {
					s.applyRADIUS(stop)
					s.applyRADIUS(start)
				} else {
					s.applyRADIUS(start)
					s.applyRADIUS(stop)
				}
				*clk = identBase.Add(2 * time.Hour)
				if m, u := s.Lookup("10.0.0.14"); m != mac || u != userB {
					t.Fatalf("(%q,%q), want (%q,%q) — same-second cross-session handover must attribute the new user", m, u, mac, userB)
				}
			})
		}
	})
}

// A release/Stop for an IP/MAC with NO existing binding is a no-op: it must not
// invent a tombstone that would block a later legitimate open. This is the
// accepted residual gap of the tombstone design (the close guard requires an
// existing binding to act on) — pinned here so a future refactor can't change it
// silently.
func TestTombstoneCloseWithNoBindingIsNoop(t *testing.T) {
	t.Run("dhcp release then later assign binds normally", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("11:11:11:11:11:11")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 12, IP: "10.0.0.15", MACToken: mac}) // release, no prior lease
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(time.Hour), EventID: 10, IP: "10.0.0.15", MACToken: mac})
		*clk = identBase.Add(2 * time.Hour)
		if m, _ := s.Lookup("10.0.0.15"); m != mac {
			t.Fatalf("mac = %q, want %q — a release with no prior lease must not tombstone the IP", m, mac)
		}
	})

	t.Run("radius stop then later start binds normally", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.16", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase, AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac}) // stop, no prior session
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(time.Hour), AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
		*clk = identBase.Add(2 * time.Hour)
		if m, u := s.Lookup("10.0.0.16"); m != mac || u != user {
			t.Fatalf("(%q,%q), want (%q,%q) — a Stop with no prior session must not tombstone the MAC", m, u, mac, user)
		}
	})
}

// A genuinely strictly-newer open after a close re-binds — tombstones must not
// block a real reopen.
func TestTombstoneStrictlyNewerReopens(t *testing.T) {
	t.Run("dhcp release then newer assign re-binds", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("11:11:11:11:11:11")
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(1 * time.Hour), EventID: 10, IP: "10.0.0.10", MACToken: mac})
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(2 * time.Hour), EventID: 12, IP: "10.0.0.10", MACToken: mac})
		s.applyDHCP(DhcpEvent{EventTime: identBase.Add(3 * time.Hour), EventID: 10, IP: "10.0.0.10", MACToken: mac})
		*clk = identBase.Add(4 * time.Hour)
		if m, _ := s.Lookup("10.0.0.10"); m != mac {
			t.Fatalf("mac = %q, want %q — a strictly-newer assign after release must re-bind", m, mac)
		}
	})

	t.Run("radius stop then newer start re-binds", func(t *testing.T) {
		s, clk := newClockedStore(t, 100*time.Hour, 100*time.Hour)
		mac := s.tok.MACToken("aa:bb:cc:dd:ee:ff")
		user := s.tok.UserToken("jdoe")
		s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.11", MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(1 * time.Hour), AcctStatus: "Start", SessionID: "S1", UserToken: user, MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(2 * time.Hour), AcctStatus: "Stop", SessionID: "S1", UserToken: user, MACToken: mac})
		s.applyRADIUS(RadiusEvent{EventTime: identBase.Add(3 * time.Hour), AcctStatus: "Start", SessionID: "S2", UserToken: user, MACToken: mac})
		*clk = identBase.Add(4 * time.Hour)
		if m, u := s.Lookup("10.0.0.11"); m != mac || u != user {
			t.Fatalf("(%q,%q), want (%q,%q) — a strictly-newer Start after Stop must re-bind", m, u, mac, user)
		}
	})
}

// Once a tombstone is evicted past its deadline, a late older open replayed
// afterward must still read as absent — Lookup's deadline check catches it, so
// the invariant holds even after the tombstone is gone.
func TestTombstoneExpiryThenLateReplay(t *testing.T) {
	s, clk := newClockedStore(t, 1*time.Hour, 1*time.Hour)
	mac := s.tok.MACToken("11:11:11:11:11:11")
	// assign at base, release at +30m -> tombstone deadline +30m+1h = +90m.
	s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.12", MACToken: mac})
	s.applyDHCP(DhcpEvent{EventTime: identBase.Add(30 * time.Minute), EventID: 12, IP: "10.0.0.12", MACToken: mac})
	// Advance past the tombstone deadline and sweep it out.
	*clk = identBase.Add(2 * time.Hour)
	s.evictExpired()
	// A late OLDER assign (event time back at base) replayed after eviction: its
	// own lease deadline is base+1h, already in the past at the query clock.
	s.applyDHCP(DhcpEvent{EventTime: identBase, EventID: 10, IP: "10.0.0.12", MACToken: mac})
	if m, _ := s.Lookup("10.0.0.12"); m != "" {
		t.Fatalf("mac = %q, want empty — a late older assign after tombstone eviction is past its own deadline", m)
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
