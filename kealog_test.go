package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Golden test over the memfile fixture: the header, the blank line, and the
// declined (state=1) lease are skipped structurally; the short row is the only
// error; everything else becomes a lease event with the cltt-reconstructed
// EventTime and the real expiry in Deadline.
func TestParseKeaFixture(t *testing.T) {
	tok := newTestTokenizer(t, "golden-key")
	data, err := os.ReadFile("testdata/kea/kea-leases4.csv")
	if err != nil {
		t.Fatal(err)
	}

	var got []DhcpEvent
	var errs int
	for _, line := range strings.Split(string(data), "\n") {
		ev, ok, err := parseKeaLease(line, tok)
		if err != nil {
			errs++
			continue
		}
		if ok {
			got = append(got, ev)
		}
	}

	if errs != 1 {
		t.Errorf("errors = %d, want 1 (the short row)", errs)
	}

	want := []struct {
		id       uint16
		ip       string
		when     int64 // expire - valid_lifetime
		deadline int64 // expire
		mac      string
	}{
		{10, "10.10.20.30", 1783000000, 1783003600, "aa:bb:cc:dd:ee:ff"}, // assign
		{10, "10.10.20.30", 1783001800, 1783005400, "aa:bb:cc:dd:ee:ff"}, // renew of the same address
		{12, "10.10.20.31", 1783003700, 1783003700, "11:22:33:44:55:66"}, // valid_lifetime=0 delete
		// state=2 expired-reclaimed: the event time is `expire` itself, NOT the
		// cltt (1783003600) — a release dated at the lease's start would be older
		// than the assign it supersedes and applyDHCP would reject the tombstone.
		{12, "10.10.20.32", 1783007200, 1783007200, "77:88:99:aa:bb:cc"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d events, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.EventID != w.id || g.IP != w.ip {
			t.Errorf("event %d = (%d,%s), want (%d,%s)", i, g.EventID, g.IP, w.id, w.ip)
		}
		if !g.EventTime.Equal(time.Unix(w.when, 0)) {
			t.Errorf("event %d time = %s, want %s", i, g.EventTime, time.Unix(w.when, 0).UTC())
		}
		if !g.Deadline.Equal(time.Unix(w.deadline, 0)) {
			t.Errorf("event %d deadline = %s, want %s", i, g.Deadline, time.Unix(w.deadline, 0).UTC())
		}
		if g.MACToken != tok.MACToken(w.mac) {
			t.Errorf("event %d mac token mismatch", i)
		}
	}
}

func TestParseKeaLeaseEdgeCases(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	const assigned = "10.0.0.5,aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,host,0,,0"

	tests := []struct {
		name    string
		line    string
		wantOK  bool
		wantErr bool
		wantID  uint16
	}{
		{"header row is skipped", "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id", false, false, 0},
		{"blank line is skipped", "   ", false, false, 0},
		{"declined lease is skipped", "10.0.0.9,,,3600,1783003600,1,0,0,,1,,0", false, false, 0},
		{"unknown state is skipped", "10.0.0.9,aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,host,7,,0", false, false, 0},
		{"assigned lease parses as 10", assigned, true, false, 10},
		{"zero lifetime parses as 12", "10.0.0.5,aa:bb:cc:dd:ee:ff,,0,1783003600,1,0,0,host,0,,0", true, false, 12},
		{"expired-reclaimed parses as 12", "10.0.0.5,aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,host,2,,0", true, false, 12},
		{"short lease row is an error", "10.0.0.5,aa:bb:cc:dd:ee:ff,,3600", false, true, 0},
		{"bad lifetime is an error", "10.0.0.5,aa:bb:cc:dd:ee:ff,,BAD,1783003600,1,0,0,host,0,,0", false, true, 0},
		{"bad expire is an error", "10.0.0.5,aa:bb:cc:dd:ee:ff,,3600,BAD,1,0,0,host,0,,0", false, true, 0},
		{"bad state is an error", "10.0.0.5,aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,host,BAD,,0", false, true, 0},
		{"non-IP first field is not a lease row", "# a comment,x,y", false, false, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok, err := parseKeaLease(tc.line, tok)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error=%v", err, tc.wantErr)
			}
			if ok && ev.EventID != tc.wantID {
				t.Errorf("event id = %d, want %d", ev.EventID, tc.wantID)
			}
		})
	}
}

// The MAC is the join key between the lease stream and the RADIUS stream, so a
// Kea colon-separated hwaddr must tokenize identically to the NPS
// Calling-Station-Id spelling of the same hardware address (mirrors the
// cross-source check in pseudonym_test.go, extended to the Kea parser).
func TestKeaMACJoinsRADIUS(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	ke, ok, err := parseKeaLease("10.10.20.30,aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,laptop-01,0,,0", tok)
	if err != nil || !ok {
		t.Fatalf("parseKeaLease ok=%v err=%v", ok, err)
	}
	npsLine := `<Event><Timestamp data_type="4">07/08/2026 09:15:00.100</Timestamp>` +
		`<User-Name data_type="1">MUIC\jdoe</User-Name>` +
		`<Calling-Station-Id data_type="1">AA-BB-CC-DD-EE-FF</Calling-Station-Id>` +
		`<Acct-Status-Type data_type="0">1</Acct-Status-Type>` +
		`<Acct-Session-Id data_type="1">SESSION-A</Acct-Session-Id></Event>`
	re, ok, err := parseNPSLine(npsLine, tok, time.UTC)
	if err != nil || !ok {
		t.Fatalf("parseNPSLine ok=%v err=%v", ok, err)
	}

	if !isToken(ke.MACToken) {
		t.Errorf("kea MAC token is not a token: %q", ke.MACToken)
	}
	if ke.MACToken != re.MACToken {
		t.Errorf("same MAC tokenized differently across sources: kea=%q nps=%q", ke.MACToken, re.MACToken)
	}
	if strings.Contains(strings.ToLower(ke.MACToken+"|"+ke.HostToken), "aabbccddeeff") {
		t.Error("raw MAC leaked into the parsed Kea event")
	}
}

// A state=2 expired-reclaimed row must actually CLOSE the lease. The release is
// timestamped at `expire`, not at the cltt: a reclaim row can carry a longer
// valid_lifetime than the renew that preceded it, so a cltt-dated tombstone
// would be older than that renew and applyDHCP's newest-wins guard would drop
// it — leaving an ended lease still resolvable.
func TestKeaExpiredReclaimClosesLease(t *testing.T) {
	s, clk := newClockedStore(t, 24*time.Hour, 24*time.Hour)
	const ip = "10.0.9.1"
	for _, line := range []string{
		ip + ",aa:bb:cc:dd:ee:ff,,3600,1783003600,1,0,0,host,0,,0", // assign, cltt 1783000000
		ip + ",aa:bb:cc:dd:ee:ff,,3600,1783007200,1,0,0,host,0,,0", // renew,  cltt 1783003600
		ip + ",aa:bb:cc:dd:ee:ff,,7200,1783007200,1,0,0,host,2,,0", // reclaimed at 1783007200
	} {
		s.ingestKea(line)
	}

	// Inside what would have been the renewed lease, but after the reclaim.
	*clk = time.Unix(1783005000, 0).UTC()
	if mac, _ := s.Lookup(ip); mac != "" {
		t.Errorf("reclaimed lease still resolves to %q; the tombstone was rejected", mac)
	}
}
