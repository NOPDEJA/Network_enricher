package main

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// tcpdumpDNSParser parses `tcpdump -v` verbose text into the same DnsEvent stream
// the BIND parser produces (dnslog.go), so both feed the identical DNSStore live
// map + dns_events table. It is STATEFUL because one DNS packet spans two lines:
//
//	15:39:41.068677 IP (tos 0x0, ttl 128, id 35219, ..., proto UDP (17), length 63)
//	    10.0.0.66.51578 > 10.0.0.3.53: 31291+ A? example.com. (35)
//
// The unindented header carries the packet time-of-day (no date); the indented
// line carries the addresses and DNS payload. feed() is called once per line in
// file order and holds the header's timestamp as pending state until the payload
// line consumes it.
//
// SINGLE-CALLER INVARIANT: like DNSStore's applyDNS, feed runs only on the single
// poller goroutine (DNSStore.scan → ingestDNS → parse), so the pending/rollover
// state needs no lock.
type tcpdumpDNSParser struct {
	loc        *time.Location
	resolverIP string // if set, packets whose CLIENT is the resolver are the upstream leg — skipped

	// baseDate is midnight (in loc) of the day the next packet belongs to. tcpdump
	// prints only a time-of-day, so we anchor it to a date and advance across a
	// midnight rollover (see feed).
	baseDate time.Time

	havePrev bool          // seen at least one header (prevTOD valid)
	prevTOD  time.Duration // previous packet's time since midnight, for rollover detection

	pending     bool      // a header was parsed and its payload line is expected next
	pendingTime time.Time // full timestamp carried by the pending header
}

var errMalformedTcpdumpDNS = errors.New("malformed tcpdump DNS line")

// todRe matches a tcpdump header's leading time-of-day token (HH:MM:SS.frac).
var todRe = regexp.MustCompile(`^(\d{2}):(\d{2}):(\d{2})\.(\d+)`)

// respCountsRe matches the answer/authority/additional counts (an/ns/ar) that
// separate a response's status prefix from its resource-record list. The first
// match in the payload is always the counts: the txid+flags and any status word
// before it never contain a "d+/d+/d+" run.
var respCountsRe = regexp.MustCompile(`(\d+)/\d+/\d+`)

// newTcpdumpDNSParser builds a parser anchored to baseDate (its date component,
// taken in loc, seeds the rollover clock). resolverIP may be "" to disable the
// upstream-leg filter.
func newTcpdumpDNSParser(loc *time.Location, baseDate time.Time, resolverIP string) *tcpdumpDNSParser {
	if loc == nil {
		loc = time.UTC
	}
	y, m, d := baseDate.In(loc).Date()
	return &tcpdumpDNSParser{
		loc:        loc,
		resolverIP: resolverIP,
		baseDate:   time.Date(y, m, d, 0, 0, 0, 0, loc),
	}
}

// feed parses one line. Return contract mirrors parseDNSLine:
//
//	err != nil          -> a packet line we could not parse (count a parse error)
//	len == 0, err==nil  -> a line we skip silently (header, non-DNS, upstream leg, …)
//	len  > 0            -> one event per answered address (or a single query-only event)
func (p *tcpdumpDNSParser) feed(line string) ([]DnsEvent, error) {
	if line == "" {
		return nil, nil
	}

	// Indented line -> the payload half of a packet. Without a pending header
	// (poller started mid-file, or the header was a non-UDP/truncated packet) it is
	// a silent skip. Consume the pending timestamp exactly once.
	if line[0] == ' ' || line[0] == '\t' {
		if !p.pending {
			return nil, nil
		}
		ts := p.pendingTime
		p.pending = false
		return p.parsePayload(strings.TrimLeft(line, " \t"), ts)
	}

	// Unindented line -> a header if it starts with a time-of-day, else silent skip.
	tok := line
	if sp := strings.IndexByte(line, ' '); sp >= 0 {
		tok = line[:sp]
	}
	tod, ok := parseTOD(tok)
	if !ok {
		return nil, nil // not a header
	}

	// Midnight rollover: a packet more than 1h EARLIER than the previous one has
	// wrapped past midnight, so advance the anchor date. A small backward jitter
	// (out-of-order by seconds) stays on the same day.
	if p.havePrev && p.prevTOD-tod > time.Hour {
		p.baseDate = p.baseDate.AddDate(0, 0, 1)
	}
	p.prevTOD = tod
	p.havePrev = true

	// Only UDP packets carry the DNS payloads we parse; a non-UDP (or EOF-truncated)
	// header clears pending so its payload line, if any, is silently skipped.
	if strings.Contains(line, "proto UDP") {
		p.pending = true
		p.pendingTime = p.baseDate.Add(tod)
	} else {
		p.pending = false
	}
	return nil, nil
}

// parsePayload parses the indented address+DNS line, ts being the timestamp from
// its header.
func (p *tcpdumpDNSParser) parsePayload(s string, ts time.Time) ([]DnsEvent, error) {
	// Split "SRC > DST: PAYLOAD".
	gt := strings.Index(s, " > ")
	if gt < 0 {
		return nil, nil
	}
	src := s[:gt]
	rest := s[gt+3:]
	colon := strings.Index(rest, ": ")
	if colon < 0 {
		return nil, nil
	}
	dst := rest[:colon]
	payload := rest[colon+2:]

	srcIP, srcPort, ok1 := splitIPPort(src)
	dstIP, dstPort, ok2 := splitIPPort(dst)
	if !ok1 || !ok2 {
		return nil, nil
	}

	// Direction by which endpoint is port 53. Neither -> not a DNS transaction.
	var clientIP string
	var clientPort uint16
	isQuery := false
	switch {
	case dstPort == 53:
		isQuery = true
		clientIP, clientPort = srcIP, srcPort
	case srcPort == 53:
		clientIP, clientPort = dstIP, dstPort
	default:
		return nil, nil
	}

	// Upstream leg to the public forwarder: the client-facing copy of the same
	// answer arrives separately, so drop this one to avoid double-counting.
	if p.resolverIP != "" && clientIP == p.resolverIP {
		return nil, nil
	}

	if isQuery {
		return parseTcpdumpQuery(payload, ts, clientIP, clientPort)
	}
	return parseTcpdumpResponse(payload, ts, clientIP, clientPort)
}

// parseTcpdumpQuery reads "TXID[flags] [1au] QTYPE? qname. (len)" and emits one
// query-only event (empty AnswerIP). Malformed input after the QTYPE? marker is a
// counted error.
func parseTcpdumpQuery(payload string, ts time.Time, clientIP string, clientPort uint16) ([]DnsEvent, error) {
	fields := strings.Fields(payload)
	// Find the "QTYPE?" field: skip the txid (field 0) and any bracketed tokens.
	qi := -1
	for i := 1; i < len(fields); i++ {
		if strings.HasSuffix(fields[i], "?") {
			qi = i
			break
		}
	}
	if qi < 0 || qi+1 >= len(fields) {
		return nil, errMalformedTcpdumpDNS
	}
	qtype := strings.TrimSuffix(fields[qi], "?")
	qname := normalizeHost(fields[qi+1])
	if qtype == "" || qname == "" {
		return nil, errMalformedTcpdumpDNS
	}
	return []DnsEvent{{
		EventTime:  ts,
		ClientIP:   clientIP,
		ClientPort: clientPort,
		QName:      qname,
		QType:      qtype,
	}}, nil
}

// parseTcpdumpResponse reads "TXID[flags] [STATUS] an/ns/ar RR, RR, … (len)" and
// emits one event per A/AAAA answer. QName is the FIRST RR's owner (the queried
// name; a CNAME chain's final A owner differs). A response with zero answers (no
// RR list — NXDomain/ServFail) is a silent skip: the query line already recorded
// the ask, unlike the BIND parser which emits a no-answer event for its combined
// query+response line. A response whose RRs yield no A/AAAA (PTR/CNAME-only) still
// emits one no-answer fallback event so the forensic table shows the resolution.
func parseTcpdumpResponse(payload string, ts time.Time, clientIP string, clientPort uint16) ([]DnsEvent, error) {
	// Strip the trailing " (len)".
	if idx := strings.LastIndex(payload, " ("); idx >= 0 {
		payload = payload[:idx]
	}
	loc := respCountsRe.FindStringSubmatchIndex(payload)
	if loc == nil {
		return nil, nil // no an/ns/ar counts: not a shape we tag
	}
	ancount, _ := strconv.Atoi(payload[loc[2]:loc[3]])
	answerSection := strings.TrimSpace(payload[loc[1]:])
	if ancount == 0 || answerSection == "" {
		return nil, nil // zero-answer response (query line already recorded the ask)
	}

	rrs := strings.Split(answerSection, ", ")
	firstFields := strings.Fields(rrs[0])
	if len(firstFields) < 2 {
		return nil, nil // RR list present but unparseable owner/type
	}
	qname := normalizeHost(firstFields[0])
	firstType := firstFields[1]
	if qname == "" {
		return nil, nil
	}

	var events []DnsEvent
	for _, rr := range rrs {
		f := strings.Fields(rr)
		if len(f) < 3 {
			continue
		}
		typ := f[1]
		if typ != "A" && typ != "AAAA" {
			continue
		}
		ip := net.ParseIP(f[2])
		if ip == nil {
			continue
		}
		if typ == "A" && ip.To4() == nil {
			continue // A with a non-v4 literal
		}
		if typ == "AAAA" && ip.To4() != nil {
			continue // AAAA with a v4 literal
		}
		events = append(events, DnsEvent{
			EventTime:  ts,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			QName:      qname,
			QType:      typ,
			AnswerIP:   f[2],
		})
	}
	if len(events) == 0 {
		// PTR/CNAME/SRV-only answer: no address to tag, but record that the client
		// resolved this name (mirrors dnslog.go's no-answer fallback).
		events = append(events, DnsEvent{
			EventTime:  ts,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			QName:      qname,
			QType:      firstType,
		})
	}
	return events, nil
}

// splitIPPort splits tcpdump's "A.B.C.D.port" endpoint on the last dot. A bad
// port yields ok=false so the line is skipped, never panics.
func splitIPPort(s string) (ip string, port uint16, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", 0, false
	}
	p, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return "", 0, false
	}
	return s[:i], uint16(p), true
}

// parseTOD reads a "HH:MM:SS.frac" time-of-day into a duration since midnight,
// keeping full sub-second precision (tcpdump prints microseconds).
func parseTOD(tok string) (time.Duration, bool) {
	m := todRe.FindStringSubmatch(tok)
	if m == nil {
		return 0, false
	}
	h, _ := strconv.Atoi(m[1])
	mi, _ := strconv.Atoi(m[2])
	s, _ := strconv.Atoi(m[3])
	if h > 23 || mi > 59 || s > 59 {
		return 0, false
	}
	frac := m[4]
	if len(frac) > 9 {
		frac = frac[:9]
	}
	ns, _ := strconv.Atoi(frac)
	for i := len(frac); i < 9; i++ {
		ns *= 10
	}
	return time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute +
		time.Duration(s)*time.Second + time.Duration(ns)*time.Nanosecond, true
}
