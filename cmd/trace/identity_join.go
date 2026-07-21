package main

import (
	"sort"
	"time"
)

// This file resolves identity bindings for the FORENSIC (evidence) path. It
// used to be a behaviorally-identical manual re-expression of the live store in
// the repo-root package (identity.go: applyDHCP, applyRADIUS, Lookup). It is
// NOT that any more — it deliberately DIVERGES, and must not be re-synced.
//
// Why it diverges: identity.go folds events in ARRIVAL order into a
// current-state view ("who is behind this IP right now"). When several events
// share one timestamp — event_time is second-resolution — arrival order decides
// the outcome, and arrival order is information the stored evidence does not
// contain. That is fine for the live store, which is ADVISORY: it annotates
// flows best-effort and a wrong same-second tie costs an annotation. It is not
// fine for cmd/trace, which is the EVIDENCE path: the same question asked twice
// over the same rows must give the same answer, and where the evidence genuinely
// does not determine an answer the tool must say so rather than pick one.
//
// So here the fold is a deterministic BATCH fold. Events for the key with
// event_time <= T are grouped into batches of IDENTICAL timestamp, processed in
// ascending time order, and each batch is applied as a SET — order within a
// batch is irrelevant by construction. State is a candidate SET A plus one
// carried deadline. If A still holds more than one distinct answer at T, the
// binding is reported AMBIGUOUS rather than resolved.
//
// The deadline is carried explicitly and is NOT recomputed when ambiguity later
// collapses: `O(X),O(Y)@00:00` then `C(X)@00:30` with a 1h horizon must read
// absent at 01:15, because Y's last open was at 00:00. Carrying one common
// deadline is sufficient because every nonempty open-set REPLACES A (so all
// survivors were opened in the same batch), and close-only batches only remove
// members.
//
// Consequence, stated plainly: cmd/trace and the live store CAN disagree under
// same-second replay. cmd/trace is the answer of record.

// dhcpEvent is the subset of identity_dhcp_events the join needs.
type dhcpEvent struct {
	Time     time.Time
	EventID  uint16 // 10 assign, 11 renew, 12 release
	IP       string
	MACToken string
}

// radiusEvent is the subset of identity_radius_events the join needs.
type radiusEvent struct {
	Time       time.Time
	AcctStatus string // Start, Interim-Update, Stop
	SessionID  string
	UserToken  string
	MACToken   string
}

// radiusCand is one RADIUS candidate. The candidate is the PAIR: a session can
// be reported with conflicting user tokens in the same second, which is a real
// ambiguity, not something to silently resolve. Its ENTITY (what a Stop closes)
// is sessionID alone, so a Stop removes the candidate whatever its user token.
type radiusCand struct {
	sessionID string
	userToken string
}

// dhcpBindingAt returns the mac_token leased to ip at instant t, and whether the
// evidence is ambiguous at t (several MACs opened in the same second with none
// closed). It returns ("", false) when no trusted lease covers t and ("", true)
// when the lease is ambiguous — callers must distinguish the two.
func dhcpBindingAt(events []dhcpEvent, ip string, t time.Time, maxLease time.Duration) (string, bool) {
	f := make([]dhcpEvent, 0, len(events))
	for _, e := range events {
		if e.IP == ip && e.MACToken != "" && !e.Time.After(t) {
			f = append(f, e)
		}
	}
	sort.SliceStable(f, func(i, j int) bool { return f[i].Time.Before(f[j].Time) })

	cands := make(map[string]struct{})
	var deadline time.Time

	for i := 0; i < len(f); {
		j := i
		for j < len(f) && f[j].Time.Equal(f[i].Time) {
			j++
		}
		batchTime := f[i].Time

		open := make(map[string]struct{})
		closes := make(map[string]struct{})
		for _, e := range f[i:j] {
			switch e.EventID {
			case 10, 11: // assign / renew
				open[e.MACToken] = struct{}{}
			case 12: // release
				closes[e.MACToken] = struct{}{}
			}
		}

		// A nonempty open set REPLACES the candidates and resets the deadline;
		// a close-only batch only removes members and leaves the deadline as-is.
		if len(open) > 0 {
			cands = open
			deadline = batchTime.Add(maxLease)
		}
		for c := range cands {
			if _, gone := closes[c]; gone {
				delete(cands, c)
			}
		}
		i = j
	}

	switch {
	case len(cands) == 0:
		return "", false // nothing open: unknown
	case t.After(deadline):
		return "", false // expired (equality still counts as covered, as in Lookup)
	case len(cands) > 1:
		return "", true // several MACs opened in the same second: ambiguous
	}
	for c := range cands {
		return c, false
	}
	return "", false
}

// radiusBindingAt returns the user_token whose session owns mac at instant t,
// and whether the evidence is ambiguous at t (several surviving sessions, or one
// session reported with conflicting user tokens in the same second). It returns
// ("", false) when no trusted session covers t and ("", true) when ambiguous.
func radiusBindingAt(events []radiusEvent, mac string, t time.Time, maxSession time.Duration) (string, bool) {
	f := make([]radiusEvent, 0, len(events))
	for _, e := range events {
		if e.MACToken == mac && e.MACToken != "" && !e.Time.After(t) {
			f = append(f, e)
		}
	}
	sort.SliceStable(f, func(i, j int) bool { return f[i].Time.Before(f[j].Time) })

	cands := make(map[radiusCand]struct{})
	var deadline time.Time

	for i := 0; i < len(f); {
		j := i
		for j < len(f) && f[j].Time.Equal(f[i].Time) {
			j++
		}
		batchTime := f[i].Time

		open := make(map[radiusCand]struct{})
		closes := make(map[string]struct{})
		for _, e := range f[i:j] {
			switch e.AcctStatus {
			case "Start", "Interim-Update":
				open[radiusCand{sessionID: e.SessionID, userToken: e.UserToken}] = struct{}{}
			case "Stop":
				closes[e.SessionID] = struct{}{}
			}
		}

		if len(open) > 0 {
			cands = open
			deadline = batchTime.Add(maxSession)
		}
		for c := range cands {
			if _, gone := closes[c.sessionID]; gone {
				delete(cands, c)
			}
		}
		i = j
	}

	if len(cands) == 0 || t.After(deadline) {
		return "", false
	}

	sessions := make(map[string]struct{}, len(cands))
	users := make(map[string]struct{}, len(cands))
	var user string
	for c := range cands {
		sessions[c.sessionID] = struct{}{}
		users[c.userToken] = struct{}{}
		user = c.userToken
	}
	if len(sessions) > 1 || len(users) > 1 {
		return "", true
	}
	return user, false
}
