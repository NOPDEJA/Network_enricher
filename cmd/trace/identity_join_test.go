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
		name    string
		events  []dhcpEvent
		ip      string
		at      time.Time
		want    string
		wantAmb bool
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
			// Same-second assign+release of the SAME MAC: the batch's close set
			// removes the MAC the batch's open set introduced, so the lease ends
			// closed regardless of row order (spec case 2).
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
			// Resurrection guard: a released lease must not be reopened by an
			// out-of-order OLDER assign arriving after the release. The tombstone
			// keeps the closed binding so the newest-wins guard rejects it.
			name: "older assign after release does not resurrect the lease",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 12, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"}, // older, replayed
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "",
		},
		{
			// A strictly-newer assign after a release is a genuine reopen.
			name: "newer assign after release re-binds",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 12, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 40), EventID: 10, IP: "10.0.0.1", MACToken: "macB"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 50),
			want: "macB",
		},
		{
			// Cross-MAC same-second handover: release macA + assign macB at the
			// same second must leave macB leased — the batch's open set is
			// {macB} and the close set {macA} removes nothing from it.
			name: "same-second cross-MAC handover leaves new MAC leased",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 12, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 10, IP: "10.0.0.1", MACToken: "macB"},
			},
			ip:   "10.0.0.1",
			at:   tm(10, 30),
			want: "macB",
		},
		{
			// Accepted residual gap: a release with no prior binding invents no
			// tombstone, so a later assign binds normally.
			name: "release with no prior binding is a no-op",
			events: []dhcpEvent{
				{Time: tm(10, 0), EventID: 12, IP: "10.0.0.1", MACToken: "macA"},
				{Time: tm(10, 20), EventID: 10, IP: "10.0.0.1", MACToken: "macA"},
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
			got, amb := dhcpBindingAt(tt.events, tt.ip, tt.at, lease)
			if got != tt.want || amb != tt.wantAmb {
				t.Fatalf("dhcpBindingAt = (%q, %v), want (%q, %v)", got, amb, tt.want, tt.wantAmb)
			}
		})
	}
}

func TestRADIUSBindingAt(t *testing.T) {
	const sess = time.Hour

	tests := []struct {
		name    string
		events  []radiusEvent
		mac     string
		at      time.Time
		want    string
		wantAmb bool
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
			// Same-second Start+Stop of the SAME session: the batch's close set
			// removes the session its open set introduced, so it ends closed
			// regardless of row order (spec case 2).
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
			// Resurrection guard: a stopped session must not be reopened by an
			// out-of-order OLDER Start arriving after the Stop.
			name: "older start after stop does not resurrect the session",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"}, // older, replayed
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "",
		},
		{
			// DELIBERATE DIVERGENCE from the live store (see identity_join.go's
			// header). The s0 interim is at 10:10 and merely ARRIVES after the
			// 10:20 Stop; the evidence says s0 opened at 10:10 and displaced s1
			// (the inherited bare-interim behavior, spec case 11), and the 10:20
			// Stop names s1, which is no longer a candidate — an unrelated close
			// (spec case 5). The batch fold reads timestamps, not arrival order,
			// so s0 survives. The old arrival-order fold answered "" here.
			name: "interim for another session before a stop survives that stop",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 10), AcctStatus: "Interim-Update", SessionID: "s0", UserToken: "userZ", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userZ",
		},
		{
			// A strictly-newer Start after a Stop is a genuine reopen.
			name: "newer start after stop re-binds",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 40), AcctStatus: "Start", SessionID: "s2", UserToken: "userB", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 50),
			want: "userB",
		},
		{
			// Cross-session same-second handover: Stop s1 + Start s2 at the same
			// second must attribute userB — the batch's open set is {(s2,userB)}
			// and the close set {s1} removes nothing from it.
			name: "same-second cross-session handover attributes new session",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Start", SessionID: "s2", UserToken: "userB", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userB",
		},
		{
			// Accepted residual gap: a Stop with no prior binding invents no
			// tombstone, so a later Start binds normally.
			name: "stop with no prior binding is a no-op",
			events: []radiusEvent{
				{Time: tm(10, 0), AcctStatus: "Stop", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
				{Time: tm(10, 20), AcctStatus: "Start", SessionID: "s1", UserToken: "userA", MACToken: "macA"},
			},
			mac:  "macA",
			at:   tm(10, 30),
			want: "userA",
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
			got, amb := radiusBindingAt(tt.events, tt.mac, tt.at, sess)
			if got != tt.want || amb != tt.wantAmb {
				t.Fatalf("radiusBindingAt = (%q, %v), want (%q, %v)", got, amb, tt.want, tt.wantAmb)
			}
		})
	}
}
