package main

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ISC Kea memfile lease CSV (kea-leases4.csv) column positions:
//
//	0 address  1 hwaddr  2 client_id  3 valid_lifetime  4 expire  5 subnet_id
//	6 fqdn_fwd  7 fqdn_rev  8 hostname  9 state  10 user_context  11 pool_id
//
// The file is append-only: every lease change appends a new row, so tailing it
// with the shared incremental scanner yields a lease event stream directly.
const (
	keaColAddress  = 0
	keaColHWAddr   = 1
	keaColLifetime = 3
	keaColExpire   = 4
	keaColHostname = 8
	keaColState    = 9
	keaMinCols     = 10 // through `state`; the trailing columns are optional to us
)

// Kea lease states (the `state` column).
const (
	keaStateDefault          = 0 // assigned
	keaStateDeclined         = 1 // client declined the address
	keaStateExpiredReclaimed = 2 // lease expired and was reclaimed
)

var (
	errShortKeaRow     = errors.New("kea lease row has too few fields")
	errInvalidKeaField = errors.New("kea lease row has an unparseable numeric field")
)

// parseKeaLease parses one ISC Kea memfile lease row into the existing
// DhcpEvent. Kea replaces the Windows DHCP audit log on the campus resolver, but
// it answers the same question (which MAC held which IP, when), so it folds into
// the same event contract rather than a new type or table.
//
// Three outcomes, matching parseDHCPLine / parseNPSLine:
//
//	err != nil             -> the row IS a lease row but is malformed
//	ok == false, err == nil -> skipped silently: blank line, the CSV header, or a
//	                          declined (state=1) lease
//	ok == true              -> a lease assign/renew/release to feed into the store
//
// The header is skipped structurally, not by string match: its `address` field
// ("address") does not parse as an IP, so it falls through as a silent skip.
// That also survives rotation, where a scan may start mid-file with no header.
//
// TIME: unlike the Windows NPS/DHCP parsers there is NO timezone knob here.
// Kea's `expire` is an absolute UNIX epoch, so it is unambiguous — LOG_TZ /
// DHCP_LOG_TZ exist only because the Windows logs write naive local time.
// For an assign/renew, EventTime = expire - valid_lifetime is Kea's own cltt
// (client-last-transmit-time) reconstruction: that is when the client actually
// got or renewed the lease. For a release, EventTime is `expire` itself — the
// instant the binding ended. See the note at the return site for why a release
// must NOT use cltt.
//
// Event mapping onto the existing 10/12 contract:
//
//	valid_lifetime > 0, state=0 (assigned)  -> 10 (assign/renew; Kea does not
//	                                           distinguish the two)
//	valid_lifetime == 0                     -> 12 (released/deleted)
//	state=2 (expired-reclaimed)             -> 12 (the binding is gone)
//	state=1 (declined)                      -> skipped (hwaddr is typically empty,
//	                                           so there is no device to bind)
func parseKeaLease(line string, tok identityTokenizer) (DhcpEvent, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return DhcpEvent{}, false, nil
	}

	fields := strings.Split(line, ",")
	addr := strings.TrimSpace(fields[keaColAddress])
	if _, err := netip.ParseAddr(addr); err != nil {
		return DhcpEvent{}, false, nil // header row / not a lease row
	}

	// From here the row is a lease row we intend to parse, so a structural
	// problem is a real error rather than a silent skip.
	if len(fields) < keaMinCols {
		return DhcpEvent{}, false, errShortKeaRow
	}

	lifetime, err := strconv.ParseInt(strings.TrimSpace(fields[keaColLifetime]), 10, 64)
	if err != nil {
		return DhcpEvent{}, false, errInvalidKeaField
	}
	expire, err := strconv.ParseInt(strings.TrimSpace(fields[keaColExpire]), 10, 64)
	if err != nil {
		return DhcpEvent{}, false, errInvalidTimestamp
	}
	state, err := strconv.Atoi(strings.TrimSpace(fields[keaColState]))
	if err != nil {
		return DhcpEvent{}, false, errInvalidKeaField
	}

	if state == keaStateDeclined {
		return DhcpEvent{}, false, nil
	}

	var eventID uint16
	switch {
	case lifetime == 0, state == keaStateExpiredReclaimed:
		eventID = 12
	case state == keaStateDefault:
		eventID = 10
	default:
		// A state Kea added that we don't model. Skip rather than guess: an
		// unknown state must not silently open or close a binding.
		return DhcpEvent{}, false, nil
	}

	// An assign/renew happened at cltt (expire - valid_lifetime); a release
	// happened AT expire. Using cltt for a release would date the tombstone
	// before the assign it supersedes, and applyDHCP's newest-wins guard would
	// then reject it — leaving an expired lease resolvable, which is exactly the
	// false-attribution window this parser exists to close. (For the
	// valid_lifetime=0 delete row the two formulas coincide; it is the
	// state=2 expired-reclaimed row, which keeps its lifetime, that diverges.)
	expireAt := time.Unix(expire, 0).UTC()
	eventTime := expireAt
	if eventID == 10 {
		eventTime = expireAt.Add(-time.Duration(lifetime) * time.Second)
	}

	return DhcpEvent{
		EventTime: eventTime,
		EventID:   eventID,
		IP:        addr,
		MACToken:  tok.MACToken(fields[keaColHWAddr]),
		HostToken: tok.HostToken(fields[keaColHostname]),
		// The real lease expiry, which the Windows audit log does not carry. It
		// clamps the binding's trust window in applyDHCP; see leaseDeadline.
		Deadline: expireAt,
	}, true, nil
}
