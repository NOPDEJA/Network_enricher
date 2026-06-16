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

func TestBuildFilter(t *testing.T) {
	t.Run("around sets symmetric window", func(t *testing.T) {
		f, err := buildFilter("facebook", 0, "", "", "2026-06-16 14:30:00", 10*time.Minute, "", "", "", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.to.Sub(f.from); got != 10*time.Minute {
			t.Fatalf("window width = %v, want 10m", got)
		}
	})

	t.Run("rejects two destinations", func(t *testing.T) {
		_, err := buildFilter("facebook", 15169, "", "", "2026-06-16", 10*time.Minute, "", "", "", 1000)
		if err == nil {
			t.Fatal("expected error for two destination flags")
		}
	})

	t.Run("rejects missing time window", func(t *testing.T) {
		_, err := buildFilter("facebook", 0, "", "", "", 10*time.Minute, "", "", "", 1000)
		if err == nil {
			t.Fatal("expected error for missing time window")
		}
	})

	t.Run("rejects around mixed with from/to", func(t *testing.T) {
		_, err := buildFilter("facebook", 0, "", "", "2026-06-16", 10*time.Minute, "2026-06-16", "", "", 1000)
		if err == nil {
			t.Fatal("expected error mixing -around with -from/-to")
		}
	})

	t.Run("rejects invalid dst-ip", func(t *testing.T) {
		_, err := buildFilter("", 0, "", "999.999.0.1", "2026-06-16", 10*time.Minute, "", "", "", 1000)
		if err == nil {
			t.Fatal("expected error for invalid dst-ip")
		}
	})
}
