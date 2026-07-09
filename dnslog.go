package main

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DnsEvent is one parsed BIND9 resolver-log record: the client that asked, the
// hostname it resolved, and (when the log carries the answer) one answered
// address with its TTL. Unlike the identity side, the hostname is NOT personal
// data in this design and stays in the CLEAR — there is no tokenizer here.
//
// One log line can yield several events: a response carrying two A records emits
// one event per (ClientIP, QName, AnswerIP). A query-only line — the standard
// querylog, which never carries answers — emits a single event with AnswerIP
// empty; it can't tag a live flow but is still forensically useful in the event
// table.
type DnsEvent struct {
	EventTime  time.Time
	ClientIP   string
	ClientPort uint16 // client source port — the per-line discriminator for the event table
	QName      string // normalized: lowercase, trailing dot stripped
	QType      string // "A" or "AAAA" (the record types we tag on)
	AnswerIP   string // "" for a query-only line
	TTL        uint32 // 0 for a query-only line
}

var errMalformedDNS = errors.New("malformed BIND log line")

// dnsTimeLayout is BIND's default logging channel timestamp when the channel is
// configured `print-time yes` (the norm for a file channel): day-mon-year with a
// millisecond fraction. Interpreted in the parser's *time.Location — see LOG_TZ.
const dnsTimeLayout = "02-Jan-2006 15:04:05.000"

// Two documented BIND9 line shapes. Both are matched leniently and table-tested
// so a real MUIC sample can tighten them later:
//
//  1. Standard querylog (category `queries`, `querylog yes`). Carries no answer:
//     08-Jul-2026 09:15:00.123 client @0x7f 10.0.0.5#54321 (host): query: host IN A +E(0)K (10.0.0.1)
//     The trailing (10.0.0.1) is the resolver/destination address, NOT an answer.
//
//  2. A response-log variant that carries the answered records with TTLs — what
//     we get if MUIC enables response logging (dnstap client-response messages).
//     RESPONSE-LOG FORMAT CHOICE: there is no single canonical one-line BIND
//     "response" text format (the short dnstap-read/querylog forms omit answer
//     rdata). We therefore model the answer section on the universally
//     documented DNS presentation form (RFC 1035 master-file / `dig` answer
//     section: `owner TTL IN A rdata`), carried on a `client ... : response:`
//     line that mirrors the querylog prefix. This is deliberately a MODELED
//     format pending re-validation against a real dnstap-read sample; the answer
//     scan below is format-agnostic enough to survive minor prefix differences:
//     08-Jul-2026 09:15:00.456 client 10.0.0.5#54321 (host): response: host IN A NOERROR host. 300 IN A 93.184.216.34
//
// Both prefixes capture the client source port (#\d+): it is the per-line
// discriminator that keeps replayed identical lines deduping to one row while
// distinct same-millisecond UDP transactions stay separate in the event table.
var (
	dnsQueryRe = regexp.MustCompile(
		`client\s+(?:@\S+\s+)?(\S+?)#(\d+)\s+\([^)]*\):\s*query:\s+(\S+)\s+\S+\s+(\S+)`)
	// The response prefix carries the queried type ("host IN A NOERROR ..."), so
	// capture it too — a no-answer response must still record its QType, else an
	// A-NXDOMAIN and AAAA-NXDOMAIN in the same millisecond would collapse.
	dnsResponseRe = regexp.MustCompile(
		`client\s+(?:@\S+\s+)?(\S+?)#(\d+)\s+\([^)]*\):\s*response:\s+(\S+)\s+\S+\s+(\S+)`)
	// One resource record in presentation form, restricted to the address types
	// we tag on. Applied across the whole line: the querylog/response prefix has
	// no "<name> <ttl> IN A/AAAA <ip>" shape, so only real answer RRs match.
	dnsAnswerRe = regexp.MustCompile(`(\S+)\s+(\d+)\s+IN\s+(A|AAAA)\s+(\S+)`)
)

// parseDNSLine parses one BIND9 resolver-log line. Return contract mirrors the
// NPS/DHCP parsers, adapted to the one-line-many-answers shape:
//
//	err != nil        -> a query/response line we could not parse (count an error)
//	len == 0, err==nil -> a line we skip silently (not a query/response line, blank)
//	len  > 0          -> one event per answered address (or a single query-only event)
func parseDNSLine(line string, loc *time.Location) ([]DnsEvent, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	// Only query and response lines are ours; every other category (lame-server,
	// resolver, security, …) is a silent skip.
	isResponse := strings.Contains(line, ": response: ")
	isQuery := !isResponse && strings.Contains(line, ": query: ")
	if !isQuery && !isResponse {
		return nil, nil
	}

	ts, err := parseDNSTime(line, loc)
	if err != nil {
		return nil, err
	}

	if isQuery {
		m := dnsQueryRe.FindStringSubmatch(line)
		if m == nil {
			return nil, errMalformedDNS
		}
		qname := normalizeHost(m[3])
		if qname == "" {
			return nil, errMalformedDNS
		}
		return []DnsEvent{{
			EventTime:  ts,
			ClientIP:   m[1],
			ClientPort: parsePort(m[2]),
			QName:      qname,
			QType:      m[4],
		}}, nil
	}

	// Response line: pull the client, port, queried name and type from the prefix,
	// then scan the answer section for A/AAAA records.
	m := dnsResponseRe.FindStringSubmatch(line)
	if m == nil {
		return nil, errMalformedDNS
	}
	clientIP := m[1]
	clientPort := parsePort(m[2])
	qname := normalizeHost(m[3])
	if qname == "" {
		return nil, errMalformedDNS
	}
	qtype := m[4]

	var events []DnsEvent
	for _, a := range dnsAnswerRe.FindAllStringSubmatch(line, -1) {
		ttl64, cerr := strconv.ParseUint(a[2], 10, 32)
		if cerr != nil {
			continue
		}
		// Validate the rdata: an A record must carry a v4 address and an AAAA a v6
		// one. Non-IP rdata (or a type/family mismatch) is skipped, not tagged.
		ip := net.ParseIP(a[4])
		if ip == nil {
			continue
		}
		if a[3] == "A" && ip.To4() == nil {
			continue // A with a non-v4 literal
		}
		if a[3] == "AAAA" && ip.To4() != nil {
			continue // AAAA with a v4 literal
		}
		events = append(events, DnsEvent{
			EventTime:  ts,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			QName:      qname,
			QType:      a[3],
			AnswerIP:   a[4],
			TTL:        uint32(ttl64),
		})
	}
	if len(events) == 0 {
		// A response with no valid A/AAAA answer (NXDOMAIN, CNAME-only, MX/TXT, or
		// only malformed rdata): still record that the client resolved this name,
		// keeping the queried type so distinct same-millisecond types don't collapse.
		events = append(events, DnsEvent{EventTime: ts, ClientIP: clientIP, ClientPort: clientPort, QName: qname, QType: qtype})
	}
	return events, nil
}

// parsePort reads a client source port; an out-of-range value yields 0 (the
// discriminator degrades but never panics).
func parsePort(s string) uint16 {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

// parseDNSTime reads BIND's leading "DD-Mon-YYYY HH:MM:SS.mmm" stamp (the first
// two whitespace-separated tokens) and anchors it in loc.
func parseDNSTime(line string, loc *time.Location) (time.Time, error) {
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return time.Time{}, errMalformedDNS
	}
	j := strings.IndexByte(line[i+1:], ' ')
	if j < 0 {
		return time.Time{}, errMalformedDNS
	}
	stamp := line[:i+1+j]
	t, err := time.ParseInLocation(dnsTimeLayout, stamp, loc)
	if err != nil {
		return time.Time{}, errInvalidTimestamp
	}
	return t, nil
}
