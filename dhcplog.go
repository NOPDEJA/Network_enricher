package main

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// DhcpEvent is one parsed Windows DHCP audit-log row. The MAC and hostname are
// already tokenized; the IP stays in the clear because it is the join key
// against the flow's src/dst address (and is already present in every flow).
type DhcpEvent struct {
	EventTime time.Time
	EventID   uint16
	IP        string
	MACToken  string
	HostToken string

	// Deadline is the lease's real expiry when the source log carries one (ISC
	// Kea's `expire` column; see kealog.go). Zero from the Windows audit log,
	// which has no reliable lease-duration field. IN-MEMORY ONLY: it clamps the
	// binding's trust window in applyDHCP and is deliberately NOT persisted —
	// chEventWriter.sendDHCP names its columns explicitly, so this field touches
	// no DDL. Consequence: cmd/trace, which folds candidate sets from the stored
	// rows, still uses maxLease semantics — a known, accepted divergence from
	// identity.go (cmd/trace already diverges by design).
	Deadline time.Time
}

var errShortDHCPRow = errors.New("dhcp row has too few fields")

// dhcpTimeLayout matches the Windows DHCP audit format: MM/DD/YY then HH:MM:SS
// in two separate CSV columns. Interpreted in the parser's *time.Location — see
// the LOG_TZ timezone note in identity.go.
const dhcpTimeLayout = "01/02/06 15:04:05"

// DHCP audit CSV column positions (IPv4 DhcpSrvLog-*.log):
//
//	0 ID  1 Date  2 Time  3 Description  4 IP Address  5 Host Name  6 MAC Address ...
const (
	dhcpColID   = 0
	dhcpColDate = 1
	dhcpColTime = 2
	dhcpColIP   = 4
	dhcpColHost = 5
	dhcpColMAC  = 6
	dhcpMinCols = 7
)

// parseDHCPLine parses one Windows DHCP audit-log row. Like parseNPSLine it has
// three outcomes:
//
//	err != nil            -> a lease event (10/11/12) that is malformed
//	ok == false, err==nil -> a line we skip silently: the text preamble, the CSV
//	                         header, blank lines, or an event ID other than
//	                         10/11/12 (log-start, DNS updates, etc.)
//	ok == true             -> a lease assign/renew/release to feed into the store
//
// The preamble and header are skipped structurally: their first comma-separated
// field ("Microsoft DHCP...", "ID", "00        The log was started.") does not
// parse as an integer, so they fall through as silent skips without needing to
// detect where the CSV section begins — which also survives log rotation, where
// a scan may start mid-file with no preamble at all.
func parseDHCPLine(line string, tok identityTokenizer, loc *time.Location) (DhcpEvent, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return DhcpEvent{}, false, nil
	}

	fields := strings.Split(line, ",")
	id, err := strconv.Atoi(strings.TrimSpace(fields[dhcpColID]))
	if err != nil {
		return DhcpEvent{}, false, nil // preamble / header / not a data row
	}
	if id != 10 && id != 11 && id != 12 {
		return DhcpEvent{}, false, nil // valid event, but not a lease change
	}

	// From here the row is a lease event we intend to parse, so a structural
	// problem is a real error rather than a silent skip.
	if len(fields) < dhcpMinCols {
		return DhcpEvent{}, false, errShortDHCPRow
	}

	ts, err := time.ParseInLocation(dhcpTimeLayout,
		strings.TrimSpace(fields[dhcpColDate])+" "+strings.TrimSpace(fields[dhcpColTime]), loc)
	if err != nil {
		return DhcpEvent{}, false, errInvalidTimestamp
	}

	return DhcpEvent{
		EventTime: ts,
		EventID:   uint16(id),
		IP:        strings.TrimSpace(fields[dhcpColIP]),
		MACToken:  tok.MACToken(fields[dhcpColMAC]),
		HostToken: tok.HostToken(fields[dhcpColHost]),
	}, true, nil
}
