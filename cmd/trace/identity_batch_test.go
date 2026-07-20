package main

import (
	"fmt"
	"testing"
	"time"
)

// These are the 11 cases of the identity-v2 spec table: the same-timestamp batch
// fold in identity_join.go. Cases marked REGRESSION fail against the previous
// sequential/arrival-order fold and are the reason this change exists.
//
// Cases whose events share one timestamp are run over ALL permutations of that
// batch — the whole point of the fold is that the answer cannot depend on the
// order rows come back in, and asserting one order would not prove it.

// permutations returns every ordering of in. Only ever used on 2-3 element
// batches in tests, so the factorial blowup is not a concern.
func permutations[T any](in []T) [][]T {
	if len(in) <= 1 {
		return [][]T{append([]T(nil), in...)}
	}
	var out [][]T
	for i := range in {
		rest := make([]T, 0, len(in)-1)
		rest = append(rest, in[:i]...)
		rest = append(rest, in[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]T{in[i]}, p...))
		}
	}
	return out
}

// assign/renew/release build dhcpEvents for ip 10.0.0.1 tersely.
func assign(t time.Time, mac string) dhcpEvent {
	return dhcpEvent{Time: t, EventID: 10, IP: "10.0.0.1", MACToken: mac}
}

func release(t time.Time, mac string) dhcpEvent {
	return dhcpEvent{Time: t, EventID: 12, IP: "10.0.0.1", MACToken: mac}
}

func TestDHCPBindingAtSpecCases(t *testing.T) {
	const lease = time.Hour

	tests := []struct {
		name string
		// setup runs first, in the given order; batch is permuted when its
		// events share a timestamp.
		setup   []dhcpEvent
		batch   []dhcpEvent
		at      time.Time
		want    string
		wantAmb bool
	}{
		{
			// 1. handover: the close names the OLD MAC, the open the NEW one.
			name:  "case 1: same-second handover C(M1),O(M2) binds M2",
			setup: []dhcpEvent{assign(tm(10, 0), "M1")},
			batch: []dhcpEvent{release(tm(10, 20), "M1"), assign(tm(10, 20), "M2")},
			at:    tm(10, 30),
			want:  "M2",
		},
		{
			// 2. same-entity tie: the close cancels the open it shares a MAC with.
			name:  "case 2: same-second same-entity O(M1),C(M1) ends closed",
			batch: []dhcpEvent{assign(tm(10, 20), "M1"), release(tm(10, 20), "M1")},
			at:    tm(10, 30),
			want:  "",
		},
		{
			// 3. REGRESSION (F1 replay). A legitimate handover in the same second
			// as a REPLAYED open of the closed MAC. M1 is closed in this batch, so
			// it cannot survive whatever order the replay arrives in. The old fold
			// let the replayed O(M1) win in some orders — false attribution to a
			// device that had already released the lease.
			name:  "case 3: F1 replay C(M1),O(M2),O(M1) never binds M1",
			setup: []dhcpEvent{assign(tm(10, 0), "M1")},
			batch: []dhcpEvent{
				release(tm(10, 20), "M1"),
				assign(tm(10, 20), "M2"),
				assign(tm(10, 20), "M1"), // replayed
			},
			at:   tm(10, 30),
			want: "M2",
		},
		{
			// 4. REGRESSION. Two opens and a close of one of them: A is the only
			// survivor, in every order. The old fold gave A in only 3 of 6 orders.
			name: "case 4: O(A),O(B),C(B) binds A in every order",
			batch: []dhcpEvent{
				assign(tm(10, 20), "A"),
				assign(tm(10, 20), "B"),
				release(tm(10, 20), "B"),
			},
			at:   tm(10, 30),
			want: "A",
		},
		{
			// 5. A close naming a MAC that is not a candidate removes nothing —
			// and must NOT move the deadline either.
			name:  "case 5: unrelated close leaves the candidate active",
			setup: []dhcpEvent{assign(tm(10, 0), "M1")},
			batch: []dhcpEvent{release(tm(10, 20), "M2")},
			at:    tm(10, 30),
			want:  "M1",
		},
		{
			// 6a. Two same-second opens, nothing closed: the evidence names two
			// devices and does not choose. Report ambiguous, not a guess.
			name: "case 6a: two same-second opens read ambiguous",
			batch: []dhcpEvent{
				assign(tm(10, 0), "A"),
				assign(tm(10, 0), "B"),
			},
			at:      tm(10, 10),
			want:    "",
			wantAmb: true,
		},
		{
			// 6b. A later close of one candidate RESOLVES the ambiguity.
			name: "case 6b: later close resolves the ambiguity to the survivor",
			setup: []dhcpEvent{
				assign(tm(10, 0), "A"),
				assign(tm(10, 0), "B"),
				release(tm(10, 30), "A"),
			},
			at:   tm(10, 40),
			want: "B",
		},
		{
			// 7. A later open REPLACES the whole candidate set, which also
			// resolves the ambiguity.
			name: "case 7: later open replaces the candidate set",
			setup: []dhcpEvent{
				assign(tm(10, 0), "X"),
				assign(tm(10, 0), "Y"),
				assign(tm(10, 30), "X"),
			},
			at:   tm(10, 40),
			want: "X",
		},
		{
			// 8. REGRESSION (deadline carry). Y's last open was 00:00, so Y expires
			// at 01:00 — the 00:30 close of X must NOT extend Y's life to 01:30.
			// This is why the deadline is carried in state instead of recomputed
			// when the ambiguity collapses.
			name: "case 8: close-only batch does not extend the deadline",
			setup: []dhcpEvent{
				assign(tm(0, 0), "X"),
				assign(tm(0, 0), "Y"),
				release(tm(0, 30), "X"),
			},
			at:   tm(1, 15), // past 00:00 + 1h
			want: "",
		},
		{
			// 9. The deadline is inclusive, matching Lookup's After check.
			name:  "case 9: query exactly at the deadline is still active",
			setup: []dhcpEvent{assign(tm(10, 0), "A")},
			at:    tm(11, 0), // exactly 10:00 + 1h
			want:  "A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := [][]dhcpEvent{tt.batch}
			if sameTimestamp(tt.batch) && len(tt.batch) > 1 {
				perms = permutations(tt.batch)
			}
			for _, p := range perms {
				events := append(append([]dhcpEvent(nil), tt.setup...), p...)
				got, amb := dhcpBindingAt(events, "10.0.0.1", tt.at, lease)
				if got != tt.want || amb != tt.wantAmb {
					t.Fatalf("dhcpBindingAt = (%q, %v), want (%q, %v)\nbatch order: %s",
						got, amb, tt.want, tt.wantAmb, describeDHCP(p))
				}
			}
		})
	}
}

func TestRADIUSBindingAtSpecCases(t *testing.T) {
	const sess = time.Hour

	start := func(t time.Time, sid, user string) radiusEvent {
		return radiusEvent{Time: t, AcctStatus: "Start", SessionID: sid, UserToken: user, MACToken: "macA"}
	}
	interim := func(t time.Time, sid, user string) radiusEvent {
		return radiusEvent{Time: t, AcctStatus: "Interim-Update", SessionID: sid, UserToken: user, MACToken: "macA"}
	}
	stop := func(t time.Time, sid string) radiusEvent {
		return radiusEvent{Time: t, AcctStatus: "Stop", SessionID: sid, UserToken: "", MACToken: "macA"}
	}

	tests := []struct {
		name    string
		setup   []radiusEvent
		batch   []radiusEvent
		at      time.Time
		want    string
		wantAmb bool
	}{
		{
			// 3. REGRESSION (F1 replay), RADIUS form: Stop s1 + Start s2 +
			// replayed Start s1 in one second. s1 is closed in this batch, so
			// userA can never be attributed, in any of the 6 orders.
			name:  "case 3: F1 replay C(s1),O(s2),O(s1) never attributes s1",
			setup: []radiusEvent{start(tm(10, 0), "s1", "userA")},
			batch: []radiusEvent{
				stop(tm(10, 20), "s1"),
				start(tm(10, 20), "s2", "userB"),
				start(tm(10, 20), "s1", "userA"), // replayed
			},
			at:   tm(10, 30),
			want: "userB",
		},
		{
			// 5. A Stop naming a different session removes nothing.
			name:  "case 5: unrelated Stop leaves the session active",
			setup: []radiusEvent{start(tm(10, 0), "s1", "userA")},
			batch: []radiusEvent{stop(tm(10, 20), "s2")},
			at:    tm(10, 30),
			want:  "userA",
		},
		{
			// 10. One surviving SESSION but two conflicting USER tokens in the
			// same second. The candidate is the (session, user) pair precisely so
			// this is visible; report ambiguous rather than pick a user. Reachable
			// because the widened ORDER BY (Part 2) stops collapsing these rows.
			name:  "case 10: same session with conflicting users is ambiguous",
			setup: []radiusEvent{start(tm(10, 0), "s1", "user0")},
			batch: []radiusEvent{
				interim(tm(10, 20), "s1", "user1"),
				interim(tm(10, 20), "s1", "user2"),
			},
			at:      tm(10, 30),
			want:    "",
			wantAmb: true,
		},
		{
			// 11. INHERITED behavior, pinned not endorsed: a bare Interim-Update
			// for a session never Started silently displaces the active session
			// with no Stop. Documented as a known limitation; not changed here.
			name:  "case 11: bare interim for an unseen session displaces the active one",
			setup: []radiusEvent{start(tm(10, 0), "s1", "userA")},
			batch: []radiusEvent{interim(tm(10, 20), "s2", "userB")},
			at:    tm(10, 30),
			want:  "userB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := [][]radiusEvent{tt.batch}
			if sameTimestamp(tt.batch) && len(tt.batch) > 1 {
				perms = permutations(tt.batch)
			}
			for _, p := range perms {
				events := append(append([]radiusEvent(nil), tt.setup...), p...)
				got, amb := radiusBindingAt(events, "macA", tt.at, sess)
				if got != tt.want || amb != tt.wantAmb {
					t.Fatalf("radiusBindingAt = (%q, %v), want (%q, %v)\nbatch order: %s",
						got, amb, tt.want, tt.wantAmb, describeRADIUS(p))
				}
			}
		})
	}
}

// sameTimestamp reports whether every event in the batch shares one timestamp,
// which is what makes permuting it meaningful.
func sameTimestamp[T dhcpEvent | radiusEvent](batch []T) bool {
	if len(batch) == 0 {
		return false
	}
	var times []time.Time
	for _, e := range batch {
		switch v := any(e).(type) {
		case dhcpEvent:
			times = append(times, v.Time)
		case radiusEvent:
			times = append(times, v.Time)
		}
	}
	for _, t := range times[1:] {
		if !t.Equal(times[0]) {
			return false
		}
	}
	return len(times) > 0
}

func describeDHCP(batch []dhcpEvent) string {
	var s string
	for _, e := range batch {
		s += fmt.Sprintf("[%d %s] ", e.EventID, e.MACToken)
	}
	return s
}

func describeRADIUS(batch []radiusEvent) string {
	var s string
	for _, e := range batch {
		s += fmt.Sprintf("[%s %s/%s] ", e.AcctStatus, e.SessionID, e.UserToken)
	}
	return s
}
