package main

import (
	"strings"
	"testing"
	"time"
)

func TestResolveService(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []uint32
		wantErr bool
	}{
		{"facebook", "facebook", []uint32{32934}, false},
		{"case-insensitive + spaces", "  Facebook ", []uint32{32934}, false},
		{"meta alias", "meta", []uint32{32934}, false},
		{"google", "google", []uint32{15169}, false},
		{"cloudflare", "cloudflare", []uint32{13335}, false},
		{"unknown", "tiktok", nil, true},
		{"empty", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveService(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) || (len(got) > 0 && got[0] != tt.want[0]) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"datetime layout", "2026-06-16 14:30:00", false},
		{"date only", "2026-06-16", false},
		{"rfc3339", "2026-06-16T14:30:00Z", false},
		{"trimmed", "  2026-06-16 14:30:00 ", false},
		{"garbage", "not-a-time", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTime(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Zone-less input must be UTC, not the host's local zone — a 7h-offset window
// would silently miss flows (ClickHouse stores timestamps in UTC).
func TestParseTimeIsUTC(t *testing.T) {
	got, err := parseTime("2026-06-11 08:00:00")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 6, 11, 8, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v (UTC)", got, want)
	}
}

func TestBuildQuery(t *testing.T) {
	t0 := time.Date(2026, 6, 16, 14, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 16, 15, 0, 0, 0, time.UTC)

	t.Run("asn predicate", func(t *testing.T) {
		sql, args, err := buildQuery(filter{from: t0, to: t1, dstASNs: []uint32{32934}, limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(sql, "dst_asn IN (?)") {
			t.Fatalf("missing asn predicate:\n%s", sql)
		}
		// args: from, to, asns, limit
		if len(args) != 4 {
			t.Fatalf("got %d args, want 4: %v", len(args), args)
		}
	})

	t.Run("org predicate is bound, not interpolated (injection guard)", func(t *testing.T) {
		evil := "cloudflare'; DROP TABLE flows; --"
		sql, args, err := buildQuery(filter{from: t0, to: t1, dstOrg: evil, limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(sql, "DROP TABLE") || strings.Contains(sql, evil) {
			t.Fatalf("user value leaked into SQL string:\n%s", sql)
		}
		if !strings.Contains(sql, "positionCaseInsensitive(dst_org, ?)") {
			t.Fatalf("missing org predicate:\n%s", sql)
		}
		// The evil string must appear as a bound arg, verbatim.
		found := false
		for _, a := range args {
			if s, ok := a.(string); ok && s == evil {
				found = true
			}
		}
		if !found {
			t.Fatalf("evil value not passed as a bound arg: %v", args)
		}
	})

	t.Run("dst-ip with src-ip narrowing", func(t *testing.T) {
		sql, args, err := buildQuery(filter{from: t0, to: t1, dstIP: "203.0.113.5", srcIP: "10.1.2.3", limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(sql, "dst_ip = ?") || !strings.Contains(sql, "src_ip = ?") {
			t.Fatalf("missing dst_ip/src_ip predicate:\n%s", sql)
		}
		// args: from, to, dstIP, srcIP, limit
		if len(args) != 5 {
			t.Fatalf("got %d args, want 5: %v", len(args), args)
		}
		if args[len(args)-1] != 50 {
			t.Fatalf("limit not last arg: %v", args)
		}
	})

	t.Run("no destination predicate is an error", func(t *testing.T) {
		if _, _, err := buildQuery(filter{from: t0, to: t1, limit: 10}); err == nil {
			t.Fatal("expected error for missing destination predicate")
		}
	})
}

func TestBuildDNSQuery(t *testing.T) {
	t0 := time.Date(2026, 7, 13, 15, 35, 0, 0, time.UTC)
	t1 := time.Date(2026, 7, 13, 15, 55, 0, 0, time.UTC)

	t.Run("qname exact-or-suffix predicate, bound args", func(t *testing.T) {
		sql, args := buildDNSQuery(filter{who: true, from: t0, to: t1, qname: "facebook.com", limit: 500})
		if !strings.Contains(sql, "FROM dns_events FINAL") {
			t.Fatalf("must query dns_events FINAL:\n%s", sql)
		}
		if !strings.Contains(sql, "(qname = ? OR endsWith(qname, ?))") {
			t.Fatalf("missing qname predicate:\n%s", sql)
		}
		// args: from, to, qname, "."+qname, limit
		if len(args) != 5 {
			t.Fatalf("got %d args, want 5: %v", len(args), args)
		}
		if args[0] != t0 || args[1] != t1 {
			t.Fatalf("time bounds not first two args: %v", args)
		}
		if args[2] != "facebook.com" || args[3] != ".facebook.com" {
			t.Fatalf("qname args wrong: %v", args[2:4])
		}
		if args[4] != 500 {
			t.Fatalf("limit not last arg: %v", args)
		}
	})

	t.Run("dst-ip predicate matches answer_ip", func(t *testing.T) {
		sql, args := buildDNSQuery(filter{who: true, from: t0, to: t1, dstIP: "157.240.1.35", limit: 100})
		if !strings.Contains(sql, "answer_ip = ?") {
			t.Fatalf("missing answer_ip predicate:\n%s", sql)
		}
		if strings.Contains(sql, "endsWith") {
			t.Fatalf("dst-ip mode must not use qname predicate:\n%s", sql)
		}
		// args: from, to, dstIP, limit
		if len(args) != 4 || args[2] != "157.240.1.35" {
			t.Fatalf("args wrong: %v", args)
		}
	})

	t.Run("qname is bound, not interpolated (injection guard)", func(t *testing.T) {
		evil := "x'; DROP TABLE dns_events; --"
		sql, args := buildDNSQuery(filter{who: true, from: t0, to: t1, qname: evil, limit: 10})
		if strings.Contains(sql, "DROP TABLE") || strings.Contains(sql, evil) {
			t.Fatalf("user value leaked into SQL:\n%s", sql)
		}
		found := false
		for _, a := range args {
			if s, ok := a.(string); ok && s == evil {
				found = true
			}
		}
		if !found {
			t.Fatalf("evil value not passed as bound arg: %v", args)
		}
	})
}

func TestBuildIdentityQueries(t *testing.T) {
	from := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 13, 23, 0, 0, 0, time.UTC)

	t.Run("dhcp query binds ip set and window", func(t *testing.T) {
		sql, args := buildDHCPQuery([]string{"10.1.2.3", "10.1.2.4"}, from, to)
		if !strings.Contains(sql, "FROM identity_dhcp_events FINAL") || !strings.Contains(sql, "ip IN (?)") {
			t.Fatalf("bad dhcp sql:\n%s", sql)
		}
		// Must equal identity_dhcp_events' full ORDER BY in schema.sql
		// (host_token included), so FINAL cannot collapse two same-second events
		// that differ only by host_token. See migrations/002_identity_orderby.sql.
		if !strings.Contains(sql, "ORDER BY ip, event_time, event_id, mac_token, host_token") {
			t.Fatalf("dhcp ORDER BY must repeat the table's full ORDER BY:\n%s", sql)
		}
		if len(args) != 3 {
			t.Fatalf("got %d args, want 3: %v", len(args), args)
		}
		ips, ok := args[0].([]string)
		if !ok || len(ips) != 2 {
			t.Fatalf("first arg must be the ip slice: %v", args[0])
		}
	})

	t.Run("radius query binds mac set and window", func(t *testing.T) {
		sql, args := buildRADIUSQuery([]string{"macAAA"}, from, to)
		if !strings.Contains(sql, "FROM identity_radius_events FINAL") || !strings.Contains(sql, "mac_token IN (?)") {
			t.Fatalf("bad radius sql:\n%s", sql)
		}
		// Must equal identity_radius_events' full ORDER BY in schema.sql
		// (user_token and nas_ip included) — omitting them let FINAL collapse
		// genuinely distinct same-second accounting events, which is evidence
		// loss. See migrations/002_identity_orderby.sql.
		if !strings.Contains(sql, "ORDER BY mac_token, event_time, session_id, acct_status, user_token, nas_ip") {
			t.Fatalf("radius ORDER BY must repeat the table's full ORDER BY:\n%s", sql)
		}
		if len(args) != 3 {
			t.Fatalf("got %d args, want 3: %v", len(args), args)
		}
	})
}

func TestBuildFilter(t *testing.T) {
	t.Run("around sets symmetric window", func(t *testing.T) {
		f, err := buildFilter(false, "", "facebook", 0, "", "", "2026-06-16 14:30:00", 10*time.Minute, "", "", "", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.to.Sub(f.from); got != 10*time.Minute {
			t.Fatalf("window width = %v, want 10m", got)
		}
	})

	t.Run("rejects two destinations", func(t *testing.T) {
		_, err := buildFilter(false, "", "facebook", 15169, "", "", "2026-06-16", 10*time.Minute, "", "", "", 1000)
		if err == nil {
			t.Fatal("expected error for two destination flags")
		}
	})

	t.Run("rejects missing time window", func(t *testing.T) {
		_, err := buildFilter(false, "", "facebook", 0, "", "", "", 10*time.Minute, "", "", "", 1000)
		if err == nil {
			t.Fatal("expected error for missing time window")
		}
	})

	t.Run("rejects around mixed with from/to", func(t *testing.T) {
		_, err := buildFilter(false, "", "facebook", 0, "", "", "2026-06-16", 10*time.Minute, "2026-06-16", "", "", 1000)
		if err == nil {
			t.Fatal("expected error mixing -around with -from/-to")
		}
	})

	t.Run("rejects invalid dst-ip", func(t *testing.T) {
		_, err := buildFilter(false, "", "", 0, "", "999.999.0.1", "2026-06-16", 10*time.Minute, "", "", "", 1000)
		if err == nil {
			t.Fatal("expected error for invalid dst-ip")
		}
	})
}

// buildFilter positional args are (who, qname, service, dstASN, dstOrg, dstIP,
// around, window, from, to, srcIP, limit). whoFilter wraps the common who-mode
// shape so the test cases below stay readable.
func whoFilter(qname, dstIP, around, from, to, srcIP, service string, dstASN uint, dstOrg string) (filter, error) {
	return buildFilter(true, qname, service, dstASN, dstOrg, dstIP, around, 10*time.Minute, from, to, srcIP, 1000)
}

func TestBuildFilterWho(t *testing.T) {
	t.Run("qname is normalized (lowercase, no trailing dot)", func(t *testing.T) {
		f, err := whoFilter("Facebook.COM.", "", "2026-07-13 15:45:00", "", "", "", "", 0, "")
		if err != nil {
			t.Fatal(err)
		}
		if !f.who || f.qname != "facebook.com" {
			t.Fatalf("who=%v qname=%q, want who=true qname=facebook.com", f.who, f.qname)
		}
	})

	t.Run("dst-ip sets answer predicate", func(t *testing.T) {
		f, err := whoFilter("", "157.240.1.35", "2026-07-13 15:45:00", "", "", "", "", 0, "")
		if err != nil {
			t.Fatal(err)
		}
		if f.dstIP != "157.240.1.35" || f.qname != "" {
			t.Fatalf("dstIP=%q qname=%q", f.dstIP, f.qname)
		}
	})

	t.Run("rejects neither qname nor dst-ip", func(t *testing.T) {
		if _, err := whoFilter("", "", "2026-07-13", "", "", "", "", 0, ""); err == nil {
			t.Fatal("expected error for missing -qname/-dst-ip")
		}
	})

	t.Run("rejects both qname and dst-ip", func(t *testing.T) {
		if _, err := whoFilter("facebook.com", "157.240.1.35", "2026-07-13", "", "", "", "", 0, ""); err == nil {
			t.Fatal("expected error for both -qname and -dst-ip")
		}
	})

	t.Run("rejects service with who", func(t *testing.T) {
		if _, err := whoFilter("facebook.com", "", "2026-07-13", "", "", "", "facebook", 0, ""); err == nil {
			t.Fatal("expected error for -service with -who")
		}
	})

	t.Run("rejects dst-asn with who", func(t *testing.T) {
		if _, err := whoFilter("facebook.com", "", "2026-07-13", "", "", "", "", 15169, ""); err == nil {
			t.Fatal("expected error for -dst-asn with -who")
		}
	})

	t.Run("rejects dst-org with who", func(t *testing.T) {
		if _, err := whoFilter("facebook.com", "", "2026-07-13", "", "", "", "", 0, "cloudflare"); err == nil {
			t.Fatal("expected error for -dst-org with -who")
		}
	})

	t.Run("rejects src-ip with who", func(t *testing.T) {
		if _, err := whoFilter("facebook.com", "", "2026-07-13", "", "", "10.1.2.3", "", 0, ""); err == nil {
			t.Fatal("expected error for -src-ip with -who")
		}
	})

	t.Run("rejects missing time window", func(t *testing.T) {
		if _, err := whoFilter("facebook.com", "", "", "", "", "", "", 0, ""); err == nil {
			t.Fatal("expected error for missing time window")
		}
	})

	t.Run("rejects invalid dst-ip", func(t *testing.T) {
		if _, err := whoFilter("", "999.999.0.1", "2026-07-13", "", "", "", "", 0, ""); err == nil {
			t.Fatal("expected error for invalid -dst-ip")
		}
	})
}
