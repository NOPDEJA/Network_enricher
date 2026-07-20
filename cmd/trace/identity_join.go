package main

import "time"

// This file is a behaviorally-identical MANUAL RE-EXPRESSION of the identity
// binding semantics in the repo-root package (identity.go: applyDHCP,
// applyRADIUS, and the Lookup deadline check). Go cannot import a `package
// main`, and the repo's cmd/ tools are deliberately standalone mains that
// re-declare the little they need (see the same note in cmd/dnsscan/main.go).
//
// The live store folds events into a CURRENT-STATE view ("who is behind this IP
// right now"). Forensics instead asks "who was behind this IP at instant T", so
// here the same fold is evaluated as-of an arbitrary T: replay every event with
// event_time <= T using the exact newest-event-wins guards from identity.go
// (including tombstones: a release/Stop marks a binding closed instead of
// deleting it, so a later OLDER open can't resurrect it), then apply the same
// deadline/closed check (a binding whose deadline is before T, or that is a
// closed tombstone, reads as absent). Events after T are the future relative to
// T and are skipped.
//
// When identity.go's applyDHCP / applyRADIUS / Lookup change, diff them against
// this file by hand and re-sync. The canonical semantics tests live with the
// canonical copy; the tests here lock in this re-expression.

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

// ipBinding mirrors identity.go's ipBinding.
type ipBinding struct {
	macToken  string
	eventTime time.Time
	deadline  time.Time
	closed    bool // tombstone: a release closed this lease
}

// macBinding mirrors identity.go's macBinding.
type macBinding struct {
	userToken string
	sessionID string
	eventTime time.Time
	deadline  time.Time
	closed    bool // tombstone: a Stop closed this session
}

// dhcpBindingAt returns the mac_token leased to ip at instant t, or "" if no
// trusted lease covers t. It mirrors applyDHCP (newest-event-wins; a different
// MAC reassigns; release tombstones only its own MAC so a later OLDER assign
// can't resurrect it; reopening a tombstone needs a strictly-newer event) plus
// Lookup's deadline/closed check, evaluated over the events at or before t.
func dhcpBindingAt(events []dhcpEvent, ip string, t time.Time, maxLease time.Duration) string {
	var b ipBinding
	have := false
	for _, e := range events {
		if e.IP != ip || e.MACToken == "" || e.Time.After(t) {
			continue
		}
		switch e.EventID {
		case 10, 11: // assign / renew
			if have {
				if b.closed {
					if !e.Time.After(b.eventTime) {
						continue // not strictly newer than the tombstone: stays closed
					}
				} else if e.Time.Before(b.eventTime) {
					continue // older than current binding: don't overwrite newer state
				}
			}
			b = ipBinding{macToken: e.MACToken, eventTime: e.Time, deadline: e.Time.Add(maxLease)}
			have = true
		case 12: // release — tombstone its own MAC, and not from the past
			if have && b.macToken == e.MACToken && !e.Time.Before(b.eventTime) {
				b = ipBinding{macToken: e.MACToken, eventTime: e.Time, deadline: e.Time.Add(maxLease), closed: true}
			}
		}
	}
	if !have || b.closed || t.After(b.deadline) {
		return ""
	}
	return b.macToken
}

// radiusBindingAt returns the user_token whose session owns mac at instant t, or
// "" if no trusted session covers t. It mirrors applyRADIUS (Start/Interim open
// or extend; a newer session takes over; Stop tombstones only the exact
// session_id so a later OLDER Start/Interim can't resurrect it; reopening a
// tombstone needs a strictly-newer event) plus Lookup's deadline/closed check,
// evaluated over the events at or before t.
func radiusBindingAt(events []radiusEvent, mac string, t time.Time, maxSession time.Duration) string {
	var b macBinding
	have := false
	for _, e := range events {
		if e.MACToken != mac || e.MACToken == "" || e.Time.After(t) {
			continue
		}
		switch e.AcctStatus {
		case "Start", "Interim-Update":
			if have {
				if b.closed {
					if !e.Time.After(b.eventTime) {
						continue // not strictly newer than the tombstone: stays closed
					}
				} else if b.sessionID == e.SessionID {
					if e.Time.Before(b.eventTime) {
						continue // older same-session event: don't move the deadline backward
					}
				} else if e.Time.Before(b.eventTime) {
					continue // older event from a different session: ignore
				}
			}
			b = macBinding{userToken: e.UserToken, sessionID: e.SessionID, eventTime: e.Time, deadline: e.Time.Add(maxSession)}
			have = true
		case "Stop": // exact session-ID match only, and not from the past
			if have && b.sessionID == e.SessionID && !e.Time.Before(b.eventTime) {
				b = macBinding{userToken: e.UserToken, sessionID: e.SessionID, eventTime: e.Time, deadline: e.Time.Add(maxSession), closed: true}
			}
		}
	}
	if !have || b.closed || t.After(b.deadline) {
		return ""
	}
	return b.userToken
}
