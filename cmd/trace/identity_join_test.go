package main

import (
	"testing"
	"time"
)

// tm is a terse UTC clock: tm(h, m) -> 2026-07-13 h:m:00 UTC.
func tm(h, m int) time.Time {
	return time.Date(2026, 7, 13, h, m, 0, 0, time.UTC)
}

func TestDHCPBindingAt(t *testing.T) {
	const lease = time.Hour

	tests := []struct {
		name   string
		events []dhcpEvent
		ip     string
		at     time.Time
		want   string
	}{
		{
			name:   "empty input",
			events: nil,
			ip:     "10.0.0.1",
			at:     tm(12, 0),
			want:   "",
		},
		{
			name: "assign then evaluated inside lease",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macA",
		},
		{
			name: "expired after maxLease",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
			},
			ip:   "10.0.0.1",
			at:   tm(11, 30), // > 10:00 + 1h
			want: "",
		},
		{
			name: "renew extends the lease",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 50), EventID: 11, IP: "10.0.0.1", MACToken: "macA"},
			},
			ip:   "10.0.0.1",
			at:   tm(11, 30), // covered by the 10:50 renew (until 11:50)
			want: "macA",
		},
		{
			name: "evaluated before any event",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
			},
			ip:   "10.0.0.1",
			at:   tm(9, 0),
			want: "",
		},
		{
			name: "release closes the lease",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 12, IP: "10.0.0.1", MACToken: "macA"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "",
		},
		{
			// Same-second assign+release arrive in the query's deterministic
			// order (ORDER BY ..., event_id): release (12) after assign (10),
			// so the tie resolves to closed.
			name: "same-second assign and release resolves to released",
			events: []dhcpEvent{
				{Time: tm(10, 20), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 12, IP: "10.0.0.1", MACToken: "macA"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "",
		},
		{
			name: "release with mismatched MAC is ignored",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 12, IP: "10.0.0.1", MACToken: "macB"}, // stale release
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macA",
		},
		{
			name: "reassign to a different MAC supersedes",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 10, IP: "10.0.0.1", MACToken: "macB"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macB",
		},
		{
			name: "out-of-order events: newest wins (older assign ignored)",
			events: []dhcpEvent{
				{Time: tm(10, 20), EventID: 10, IP: "10.0.0.1", MACToken: "macB"},
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"}, // arrives later but older
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macB",
		},
		{
			name: "release older than binding does not close",
			events: []dhcpEvent{
				{Time: tm(10, 20), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 0), EventID: 12, IP: "10.0.0.1", MACToken: "macA"}, // stale release
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macA",
		},
		{
			name: "empty MAC token event is ignored",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: ""},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 10),
			want: "",
		},
		{
			name: "other IP does not leak",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.9", MACToken: "macZ"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 10),
			want: "",
		},
		{
			name: "future event relative to T is skipped",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 40), EventID: 10, IP: "10.0.0.1", MACToken: "macB"}, // after T
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dhcpBindingAt(tt.events, tt.ip, tt.at, lease); got != tt.want {
				t.Fatalf("dhcpBindingAt = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRADIUSBindingAt(t *testing.T) {
	const sess = time.Hour

	tests := []struct {
		name   string
		events []radiusEvent
		mac    string
		at     time.Time
		want   string
	}{
		{
			name:   "empty input",
			events: nil,
			mac:    "macA",
			at:     tm(12, 0),
			want:   "",
		},
		{
			name: "start then evaluated inside session",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userA",
		},
		{
			name: "expired after maxSession",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(11, 30),
			want: "",
		},
		{
			name: "interim-update extends the session",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 50), AcctStatus: "Interim-Update", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(11, 30), // covered by 10:50 interim (until 11:50)
			want: "userA",
		},
		{
			name: "stop closes only the matching session_id",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s2", UserToken: "userA", MACToken: "macA"}, // wrong session
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userA",
		},
		{
			name: "stop with matching session_id closes",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "",
		},
		{
			// Same-second Start+Stop arrive in the query's deterministic order
			// (ORDER BY ..., acct_status): "Start" < "Stop" lexicographically,
			// so the tie resolves to closed.
			name: "same-second start and stop resolves to closed",
			events: []radiusEvent{
				{Time: tm(10, 20), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "",
		},
		{
			name: "newer session takes over",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Start", SessionID: "s2", UserToken: "userB", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userB",
		},
		{
			name: "out-of-order: older different-session start ignored",
			events: []radiusEvent{
				{Time: tm(10, 20), AcctStatus: "Start", SessionID: "s2", UserToken: "userB", MACToken: "macA"},
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userB",
		},
		{
			name: "evaluated before any event",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(9, 0),
			want: "",
		},
		{
			name: "future event relative to T is skipped",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 40), AcctStatus: "Start", SessionID: "s2", UserToken: "userB", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userA",
		},
		{
			name: "other MAC does not leak",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userZ", MACToken: "macZ"},
			},
			mac:  "macA",
			at:   tm(10, 10),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := radiusBindingAt(tt.events, tt.mac, tt.at, sess); got != tt.want {
				t.Fatalf("radiusBindingAt = %q, want %q", got, tt.want)
			}
		})
	}
}
