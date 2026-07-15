package main

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// dnstapDNSParser parses `dnstap-read -y` YAML text into the same DnsEvent stream
// the BIND and tcpdump parsers produce, so all three feed the identical DNSStore
// live map + dns_events table. dnstap is BIND's binary response log; the
// dnstap-export sidecar converts it to this YAML text (see docker_compose.yml).
// It is the ONLY DNS source carrying real answer TTLs, so answer events keep a
// genuine TTL and never set TTLUnknown.
//
// It is STATEFUL because one DNS message is a multi-line YAML document:
//
//	type: MESSAGE
//	identity: Nop-laptop
//	version: BIND 9.20.24
//	message:
//	  type: CLIENT_RESPONSE
//	  response_time: !!timestamp 2026-07-15T08:42:54Z
//	  query_address: "127.0.0.1"
//	  query_port: 42201
//	  response_message_data:
//	    QUESTION_SECTION:
//	      - 'google.com. IN A'
//	    ANSWER_SECTION:
//	      - 'google.com. 49 IN A 142.250.66.110'
//	  response_message: |
//	    ;; ... dig-format DUPLICATE of the sections above — must be ignored ...
//	---
//
// Documents are separated by a column-0 `---`; the fields accumulate as pending
// state until the block's terminator arrives, then flush emits its events.
//
// This is a line-oriented state machine, NOT a YAML parse: the `!!timestamp`
// tags and multi-doc stream are hostile to strict YAML, and the project style is
// dependency-free line scanning (matches dnslog.go / tcpdumplog.go).
//
// SINGLE-CALLER INVARIANT: like the tcpdump parser, feed runs only on the single
// DNS poller goroutine (DNSStore.scan -> ingestDNS -> parse), one line at a time
// in file order, so the pending block state needs no lock. The parser is retained
// per file path across scans (DNSStore.parsers), so a block split across two scans
// keeps its state and emits when its `---` finally arrives.
//
// TIMEZONE NOTE: unlike the BIND and tcpdump parsers, the dnstap YAML timestamp
// carries an explicit zone (RFC3339 `Z`), so NO *time.Location interpretation
// applies here — DNS_LOG_TZ is irrelevant for this format.
type dnstapDNSParser struct {
	inBlock   bool // a `type:` block start has been seen and its terminator not yet reached
	inLiteral bool // inside a `... |` YAML literal block (the dig-format duplicate); ignore until col-0

	kind    string        // the message-level kind: CLIENT_QUERY / CLIENT_RESPONSE / FORWARDER_* / …
	section dnstapSection // which list header the current 6-space items belong to

	eventTime  time.Time // from query_time / response_time
	clientIP   string    // from query_address (the client side in both CLIENT_QUERY and CLIENT_RESPONSE)
	clientPort uint16    // from query_port — keeps its replay-dedup discriminator role
	qname      string    // normalized name from QUESTION_SECTION
	qtype      string    // last token of the QUESTION item (A / AAAA / PTR / …)

	answers []dnstapAnswer // valid A/AAAA answers accrued from ANSWER_SECTION
}

// dnstapAnswer is one validated A/AAAA answer record pending emission.
type dnstapAnswer struct {
	qtype    string // "A" or "AAAA" (the record type, mirroring dnslog.go)
	answerIP string
	ttl      uint32
}

// dnstapSection marks which list the current 6-space `- '...'` items feed. Only
// the QUESTION and ANSWER lists contribute; AUTHORITY/ADDITIONAL/OPT items are
// dropped (sectNone) — the NXDOMAIN block's SOA in AUTHORITY_SECTION must never
// become an event.
type dnstapSection int

const (
	sectNone dnstapSection = iota
	sectQuestion
	sectAnswer
)

var errMalformedDnstapDNS = errors.New("malformed dnstap DNS block")

// newDnstapDNSParser builds a parser. No location parameter is meaningful (the
// timestamps carry their own zone); dnsstore passes none. See the type doc.
func newDnstapDNSParser() *dnstapDNSParser {
	return &dnstapDNSParser{}
}

// feed parses one line. Return contract mirrors parseDNSLine / tcpdumpParser.feed:
//
//	err != nil          -> a block we could not parse (count ONE parse error)
//	len == 0, err==nil  -> a line we skip silently (boilerplate, skipped kind, …)
//	len  > 0            -> one query-only event, or one event per answered address
//
// Events are emitted when a block's terminator line arrives (a col-0 `---`, or a
// col-0 `type:` starting the next block), so the terminator line is the call that
// returns the block's events.
func (p *dnstapDNSParser) feed(line string) ([]DnsEvent, error) {
	if line == "" {
		return nil, nil // blank lines carry no state (the poller drops them anyway)
	}

	// A column-0 line (no leading whitespace) is structural: it terminates the
	// current block or is stream boilerplate. It ALSO ends any literal-block skip,
	// because a `... |` dig body is always deeper-indented and can never hold a
	// col-0 line — so the next col-0 line is a reliable resync point.
	if line[0] != ' ' && line[0] != '\t' {
		p.inLiteral = false

		// `---` closes the current multi-doc block: emit its pending events.
		if line == "---" {
			return p.flush()
		}
		// A col-0 `type:` opens the next block. Reached either normally (right after
		// a `---`, nothing pending) or on a truncation resync (a rotation re-fed us
		// from offset 0 mid-block): either way flush whatever is pending, then start
		// a clean block so a half-read predecessor can't leak into it.
		if strings.HasPrefix(line, "type:") {
			evs, err := p.flush()
			p.begin()
			return evs, err
		}
		// identity: / version: / message: and any other boilerplate: nothing to do.
		return nil, nil
	}

	// Indented line: only meaningful inside an active block and outside a literal.
	if !p.inBlock || p.inLiteral {
		return nil, nil
	}

	content := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(content, "- ") {
		// A list item belongs to the section header that preceded it. Only the
		// QUESTION and ANSWER lists feed events; AUTHORITY/ADDITIONAL/OPT items reach
		// here with section==sectNone and are ignored. Strip the single quotes BEFORE
		// field-splitting: an unstripped trailing quote would break net.ParseIP.
		item := strings.Trim(strings.TrimPrefix(content, "- "), "'")
		switch p.section {
		case sectQuestion:
			p.parseQuestion(item)
		case sectAnswer:
			p.parseAnswer(item)
		}
		return nil, nil
	}

	// A non-list-item line ends any open list, then may set a field or (re)open a
	// section. Everything is keyed off the token before the first colon.
	p.section = sectNone
	key, val := splitDnstapField(content)
	switch key {
	case "type":
		p.kind = val
	case "query_time", "response_time":
		p.parseTimestamp(val)
	case "query_address":
		p.clientIP = strings.Trim(val, `"`)
	case "query_port":
		p.clientPort = parsePort(val)
	case "query_message", "response_message":
		// The `|` literal block DUPLICATES the sections in dig format (unquoted
		// answer lines that would double-count). Ignore every following line until
		// the next col-0 line. This is the #1 trap in the format.
		if val == "|" {
			p.inLiteral = true
		}
	case "QUESTION_SECTION":
		p.section = sectQuestion
	case "ANSWER_SECTION":
		p.section = sectAnswer
	}
	return nil, nil
}

// parseTimestamp reads a `!!timestamp 2026-07-15T08:42:54Z` value. RFC3339 with an
// explicit zone (and fractional seconds if present). A malformed stamp leaves
// eventTime zero, so flush reports the block as an error.
func (p *dnstapDNSParser) parseTimestamp(val string) {
	s := strings.TrimSpace(strings.TrimPrefix(val, "!!timestamp"))
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		p.eventTime = t
	}
}

// parseQuestion reads a QUESTION item "qname. IN QTYPE": QName is the first token
// (normalized), QType the last. There is one question per block.
func (p *dnstapDNSParser) parseQuestion(item string) {
	f := strings.Fields(item)
	if len(f) < 2 {
		return
	}
	p.qname = normalizeHost(f[0])
	p.qtype = f[len(f)-1]
}

// parseAnswer reads an ANSWER item "owner TTL IN TYPE rdata" (RFC 1035
// presentation). Only A/AAAA with a valid matching-family literal are kept;
// CNAME/PTR/SOA and bad rdata/TTL are skipped, not fatal — the same rules as the
// BIND parser's answer scan (dnslog.go). The QName comes from the QUESTION section
// at emission, NOT the answer owner (they differ on a CNAME chain).
func (p *dnstapDNSParser) parseAnswer(item string) {
	f := strings.Fields(item)
	if len(f) < 5 {
		return
	}
	typ := f[3]
	if typ != "A" && typ != "AAAA" {
		return
	}
	ttl64, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return
	}
	ip := net.ParseIP(f[4])
	if ip == nil {
		return
	}
	if typ == "A" && ip.To4() == nil {
		return // A with a non-v4 literal
	}
	if typ == "AAAA" && ip.To4() != nil {
		return // AAAA with a v4 literal
	}
	p.answers = append(p.answers, dnstapAnswer{qtype: typ, answerIP: f[4], ttl: uint32(ttl64)})
}

// flush emits the pending block's events and resets state. It is the sole place a
// block turns into events, so the 3-outcome contract is decided here.
func (p *dnstapDNSParser) flush() ([]DnsEvent, error) {
	if !p.inBlock {
		return nil, nil
	}
	defer p.reset()

	// Only the two client-facing kinds are ours; every other kind (FORWARDER_*,
	// UPDATE_*, …) is the upstream leg or unrelated and is a silent whole-block
	// skip. The forwarder blocks carry query_address "0.0.0.0", so this kind gate
	// IS the upstream-leg filter — no resolver-IP knob is needed here.
	if p.kind != "CLIENT_QUERY" && p.kind != "CLIENT_RESPONSE" {
		return nil, nil
	}
	// A block that reached its terminator without a timestamp, client address, or
	// question name is malformed (a truncated/rotated fragment): count it ONCE for
	// the block, not per line.
	if p.eventTime.IsZero() || p.clientIP == "" || p.qname == "" {
		return nil, errMalformedDnstapDNS
	}

	if p.kind == "CLIENT_QUERY" {
		return []DnsEvent{{
			EventTime:  p.eventTime,
			ClientIP:   p.clientIP,
			ClientPort: p.clientPort,
			QName:      p.qname,
			QType:      p.qtype,
		}}, nil
	}

	// CLIENT_RESPONSE: one event per valid A/AAAA answer, carrying the REAL TTL —
	// dnstap is the only source with answer TTLs, so TTLUnknown stays false.
	var events []DnsEvent
	for _, a := range p.answers {
		events = append(events, DnsEvent{
			EventTime:  p.eventTime,
			ClientIP:   p.clientIP,
			ClientPort: p.clientPort,
			QName:      p.qname, // the QUESTION name, not the answer owner (they differ on a CNAME chain)
			QType:      a.qtype,
			AnswerIP:   a.answerIP,
			TTL:        a.ttl,
		})
	}
	if len(events) == 0 {
		// NXDOMAIN, CNAME/PTR-only, or empty answer: emit one no-answer fallback.
		// Unlike the tcpdump parser, a dnstap response ALWAYS carries the question
		// name, so tcpdump's zero-answer forensic gap does NOT exist here — the
		// resolution is always recorded, keeping the queried type.
		events = append(events, DnsEvent{
			EventTime:  p.eventTime,
			ClientIP:   p.clientIP,
			ClientPort: p.clientPort,
			QName:      p.qname,
			QType:      p.qtype,
		})
	}
	return events, nil
}

// begin starts a fresh block, clearing all per-block state. Reuses the answers
// backing array to avoid a per-block allocation on the poller path.
func (p *dnstapDNSParser) begin() {
	p.inBlock = true
	p.inLiteral = false
	p.kind = ""
	p.section = sectNone
	p.eventTime = time.Time{}
	p.clientIP = ""
	p.clientPort = 0
	p.qname = ""
	p.qtype = ""
	p.answers = p.answers[:0]
}

// reset clears state to "no active block" (post-emit, or after a `---`).
func (p *dnstapDNSParser) reset() {
	p.begin()
	p.inBlock = false
}

// splitDnstapField splits "key: value" on the first colon, trimming the value. A
// line with no colon yields the whole line as key and an empty value.
func splitDnstapField(s string) (key, val string) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i+1:])
}
