// Command dnsscan is a read-only, std-lib-only reconnaissance tool for a
// `tcpdump -v` verbose DNS capture (the first real MUIC sample format). It
// streams a capture file line by line through the same stateful parser the
// enricher uses and prints a plain-text stats report — packet/query/response
// mix, answer families, status words, cardinalities, top qnames, capture span,
// and a dedup preview — WITHOUT ever printing a raw client IP (only a count),
// so it is safe to run against sensitive campus captures.
//
//	go run ./cmd/dnsscan -file capture.txt -tz Asia/Bangkok -date 2026-07-13 -resolver 192.168.64.3
//
// NOTE: the parser below (tcpdumpDNSParser + helpers, and the DnsEvent struct
// and normalizeHost) is a behaviorally-identical MANUAL COPY of the canonical
// parser in the repo-root package (tcpdumplog.go / dnslog.go / pseudonym.go) —
// comments are trimmed and some locals renamed, so it is NOT byte-for-byte. Go
// cannot import a `package main`, and the repo's cmd/ tools are deliberately
// standalone mains that re-declare the little they need (see cmd/trace,
// cmd/loadgen). When the canonical parser changes, diff it against this copy by
// hand and re-sync; the parser tests live with the canonical copy.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	file := flag.String("file", "", "path to a tcpdump -v verbose DNS capture (required)")
	tz := flag.String("tz", "Asia/Bangkok", "IANA timezone the capture's wall-clock times are in")
	date := flag.String("date", "", "capture date YYYY-MM-DD in -tz (default: today in -tz)")
	resolver := flag.String("resolver", "", "resolver IP whose upstream leg to the public forwarder is dropped")
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "dnsscan: -file is required")
		flag.Usage()
		os.Exit(2)
	}
	loc, err := time.LoadLocation(*tz)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnsscan: invalid -tz %q: %v\n", *tz, err)
		os.Exit(2)
	}
	baseDate := time.Now().In(loc)
	if *date != "" {
		d, derr := time.ParseInLocation("2006-01-02", *date, loc)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "dnsscan: invalid -date %q (want YYYY-MM-DD): %v\n", *date, derr)
			os.Exit(2)
		}
		baseDate = d
	}

	f, err := os.Open(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnsscan: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	rep := scan(f, loc, baseDate, *resolver)
	rep.print(os.Stdout, *file, loc, baseDate, *resolver)
}

// lineKind is a payload line's DNS direction, decided once and shared by the raw
// tally and the event classification (so they never disagree).
type lineKind int

const (
	kindOther lineKind = iota
	kindQuery
	kindResponse
)

// report accumulates the streaming stats. Client IPs are only ever counted, never
// stored for display (uniqueClients is a set used solely for its size).
type report struct {
	resolverIP string

	totalLines int
	packets    int // header lines with a valid time-of-day

	queriesByType map[string]int // raw, includes the upstream resolver leg
	clientQueries int            // queries after dropping the upstream leg (for avg qps)
	responses     int

	answerA    int
	answerAAAA int
	queryOnly  int
	fallback   int
	silentSkip int
	parseErr   int

	nxDomain int
	servFail int

	uniqueClients map[string]struct{}
	uniqueQNames  map[string]struct{}
	qnameQueries  map[string]int // query count per qname, for the top-15

	totalEvents int
	dedupKeys   map[string]struct{} // distinct (client, qname, answer) triples

	haveSpan  bool
	firstSeen time.Time
	lastSeen  time.Time
}

// statusWordRe pulls a response status word (NXDomain/ServFail/…) for the raw
// tally; the parser doesn't surface it.
var statusWordRe = regexp.MustCompile(`\b(NXDomain|ServFail|NoError|Refused|FormErr|NotImp)\b`)

func scan(f *os.File, loc *time.Location, baseDate time.Time, resolverIP string) *report {
	r := &report{
		resolverIP:    resolverIP,
		queriesByType: map[string]int{},
		uniqueClients: map[string]struct{}{},
		uniqueQNames:  map[string]struct{}{},
		qnameQueries:  map[string]int{},
		dedupKeys:     map[string]struct{}{},
	}
	p := newTcpdumpDNSParser(loc, baseDate, resolverIP)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20) // real capture is 66MB; long RR lists per line

	// udpPending mirrors the parser's own UDP gate for the RAW tallies: a payload is
	// only classified when its header was a UDP packet, so a TCP (or other) payload
	// isn't miscounted as a query just because a port happens to be 53.
	udpPending := false

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		r.totalLines++
		if line == "" {
			continue
		}

		// Cheap raw classification for the line-level tallies the event stream can't
		// recover (packet count, per-qtype queries incl. upstream, status words). The
		// direction (kind) decided here is reused to bucket the parser's events, so
		// the raw tally and the event tally never disagree.
		indented := line[0] == ' ' || line[0] == '\t'
		kind := kindOther
		if !indented {
			if _, ok := parseTOD(firstToken(line)); ok {
				r.packets++
				udpPending = strings.Contains(line, "proto UDP") || strings.Contains(line, "next-header UDP")
			} else {
				udpPending = false
			}
		} else if udpPending {
			kind = classifyPayload(strings.TrimLeft(line, " \t"), r)
			udpPending = false
		}

		evs, err := p.feed(line)
		if err != nil {
			r.parseErr++
			continue
		}
		if len(evs) == 0 {
			if indented {
				r.silentSkip++ // an indented line that yielded nothing (upstream/zero-answer/non-DNS)
			}
			continue
		}
		for _, e := range evs {
			r.totalEvents++
			r.uniqueClients[e.ClientIP] = struct{}{}
			r.uniqueQNames[e.QName] = struct{}{}
			r.dedupKeys[e.ClientIP+"\x00"+e.QName+"\x00"+e.AnswerIP] = struct{}{}
			if e.EventTime.IsZero() {
				continue
			}
			if !r.haveSpan || e.EventTime.Before(r.firstSeen) {
				r.firstSeen = e.EventTime
			}
			if !r.haveSpan || e.EventTime.After(r.lastSeen) {
				r.lastSeen = e.EventTime
			}
			r.haveSpan = true
		}
		classifyEvents(kind, evs, r)
	}
	if serr := sc.Err(); serr != nil {
		fmt.Fprintf(os.Stderr, "dnsscan: read error: %v\n", serr)
	}
	return r
}

// classifyPayload decides a payload line's direction (mirroring the parser's own
// port/shape logic) and does the raw line-level tallies: query qtypes (including
// the upstream-leg queries the parser drops), a post-filter client-query count,
// response count, and status words. It returns the direction so the caller can
// bucket that same line's parser events consistently.
func classifyPayload(payload string, r *report) lineKind {
	gt := strings.Index(payload, " > ")
	if gt < 0 {
		return kindOther
	}
	rest := payload[gt+3:]
	colon := strings.Index(rest, ": ")
	if colon < 0 {
		return kindOther
	}
	srcIP, srcPort, ok1 := splitIPPort(payload[:gt])
	dstIP, dstPort, ok2 := splitIPPort(rest[:colon])
	if !ok1 || !ok2 {
		return kindOther
	}
	body := rest[colon+2:]

	isQuery := false
	clientIP := ""
	switch {
	case dstPort == 53 && srcPort == 53:
		isQuery = payloadHasQueryMarker(body)
		if isQuery {
			clientIP = srcIP
		} else {
			clientIP = dstIP
		}
	case dstPort == 53:
		isQuery = true
		clientIP = srcIP
	case srcPort == 53:
		clientIP = dstIP
	default:
		return kindOther
	}

	if isQuery {
		for _, fld := range strings.Fields(body) {
			if strings.HasSuffix(fld, "?") {
				r.queriesByType[strings.TrimSuffix(fld, "?")]++
				break
			}
		}
		if r.resolverIP == "" || clientIP != r.resolverIP {
			r.clientQueries++ // exclude the upstream resolver leg from the qps rate
		}
		return kindQuery
	}

	r.responses++
	if m := statusWordRe.FindString(body); m != "" {
		switch m {
		case "NXDomain":
			r.nxDomain++
		case "ServFail":
			r.servFail++
		}
	}
	return kindResponse
}

// classifyEvents buckets a single payload line's parser events using the line's
// already-decided direction — no guessing from QType, so PTR/NS/SVCB/CNAME/TXT
// queries land in query-only (and the top-15) rather than being mislabeled
// fallbacks.
func classifyEvents(kind lineKind, evs []DnsEvent, r *report) {
	switch kind {
	case kindQuery:
		// A non-upstream query yields exactly one query-only event (empty answer);
		// an upstream-filtered query yields none.
		for _, e := range evs {
			r.queryOnly++
			r.qnameQueries[e.QName]++
		}
	case kindResponse:
		if len(evs) == 1 && evs[0].AnswerIP == "" {
			r.fallback++ // PTR/CNAME-only: no address to tag
			return
		}
		for _, e := range evs {
			switch e.QType {
			case "A":
				r.answerA++
			case "AAAA":
				r.answerAAAA++
			}
		}
	}
}

func (r *report) print(w *os.File, path string, loc *time.Location, baseDate time.Time, resolverIP string) {
	out := bufio.NewWriter(w)
	defer out.Flush()

	res := resolverIP
	if res == "" {
		res = "(none)"
	}
	fmt.Fprintf(out, "dnsscan report for %s\n", path)
	fmt.Fprintf(out, "  timezone=%s  base-date=%s  resolver=%s\n\n", loc, baseDate.Format("2006-01-02"), res)

	fmt.Fprintf(out, "lines read . . . . . . . %d\n", r.totalLines)
	fmt.Fprintf(out, "packets  . . . . . . . . %d\n", r.packets)
	fmt.Fprintf(out, "responses  . . . . . . . %d\n", r.responses)
	fmt.Fprintf(out, "parse errors . . . . . . %d\n", r.parseErr)
	fmt.Fprintf(out, "silent skips . . . . . . %d\n\n", r.silentSkip)

	fmt.Fprintln(out, "queries by qtype (raw, incl. upstream leg):")
	for _, kv := range sortedByCountDesc(r.queriesByType) {
		fmt.Fprintf(out, "  %-6s %d\n", kv.key, kv.n)
	}
	fmt.Fprintf(out, "client queries (excl. upstream) . %d\n\n", r.clientQueries)

	fmt.Fprintln(out, "events:")
	fmt.Fprintf(out, "  answer A . . . . . . . %d\n", r.answerA)
	fmt.Fprintf(out, "  answer AAAA  . . . . . %d\n", r.answerAAAA)
	fmt.Fprintf(out, "  query-only . . . . . . %d\n", r.queryOnly)
	fmt.Fprintf(out, "  fallback (no address). %d\n", r.fallback)
	fmt.Fprintf(out, "  total events . . . . . %d\n\n", r.totalEvents)

	fmt.Fprintln(out, "status words:")
	fmt.Fprintf(out, "  NXDomain . . . . . . . %d\n", r.nxDomain)
	fmt.Fprintf(out, "  ServFail . . . . . . . %d\n\n", r.servFail)

	fmt.Fprintf(out, "unique clients . . . . . %d (count only; IPs not printed)\n", len(r.uniqueClients))
	fmt.Fprintf(out, "unique qnames  . . . . . %d\n\n", len(r.uniqueQNames))

	fmt.Fprintln(out, "top 15 qnames by query count:")
	top := sortedByCountDesc(r.qnameQueries)
	for i := 0; i < len(top) && i < 15; i++ {
		fmt.Fprintf(out, "  %5d  %s\n", top[i].n, top[i].key)
	}
	fmt.Fprintln(out)

	if r.haveSpan {
		span := r.lastSeen.Sub(r.firstSeen)
		fmt.Fprintf(out, "event-time span  . . . . %s .. %s (%s)\n",
			r.firstSeen.Format("15:04:05"), r.lastSeen.Format("15:04:05"), span)
		if secs := span.Seconds(); secs > 0 {
			// Rate over CLIENT queries (upstream leg excluded) — what the reader wants.
			fmt.Fprintf(out, "avg client queries/sec . %.2f\n", float64(r.clientQueries)/secs)
		}
	}
	fmt.Fprintf(out, "\ndedup preview: %d events -> %d distinct (client,qname,answer) triples\n",
		r.totalEvents, len(r.dedupKeys))
}

type kv struct {
	key string
	n   int
}

func sortedByCountDesc(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, n := range m {
		out = append(out, kv{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	return out
}

func firstToken(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------------------------------------------------------------------------
// VENDORED PARSER — verbatim copy of tcpdumplog.go (+ DnsEvent from dnslog.go,
// normalizeHost from pseudonym.go). See the package doc comment. Do not edit
// here; sync from the canonical files.
// ---------------------------------------------------------------------------

type DnsEvent struct {
	EventTime  time.Time
	ClientIP   string
	ClientPort uint16
	QName      string
	QType      string
	AnswerIP   string
	TTL        uint32
	TTLUnknown bool
}

func normalizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

type tcpdumpDNSParser struct {
	loc        *time.Location
	resolverIP string

	baseDate time.Time

	havePrev bool
	prevTOD  time.Duration

	pending     bool
	pendingTime time.Time
}

var errMalformedTcpdumpDNS = errors.New("malformed tcpdump DNS line")

var todRe = regexp.MustCompile(`^(\d{2}):(\d{2}):(\d{2})\.(\d+)`)

var respCountsRe = regexp.MustCompile(`(\d+)/\d+/\d+`)

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

func (p *tcpdumpDNSParser) feed(line string) ([]DnsEvent, error) {
	if line == "" {
		return nil, nil
	}

	if line[0] == ' ' || line[0] == '\t' {
		if !p.pending {
			return nil, nil
		}
		ts := p.pendingTime
		p.pending = false
		return p.parsePayload(strings.TrimLeft(line, " \t"), ts)
	}

	tok := line
	if sp := strings.IndexByte(line, ' '); sp >= 0 {
		tok = line[:sp]
	}
	tod, ok := parseTOD(tok)
	if !ok {
		p.pending = false // stale pending must not pair with a later payload
		return nil, nil
	}

	if p.havePrev && p.prevTOD-tod > 12*time.Hour {
		p.baseDate = p.baseDate.AddDate(0, 0, 1)
	}
	p.prevTOD = tod
	p.havePrev = true

	if strings.Contains(line, "proto UDP") || strings.Contains(line, "next-header UDP") {
		p.pending = true
		p.pendingTime = p.baseDate.Add(tod)
	} else {
		p.pending = false
	}
	return nil, nil
}

func (p *tcpdumpDNSParser) parsePayload(s string, ts time.Time) ([]DnsEvent, error) {
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

	var clientIP string
	var clientPort uint16
	var isQuery bool
	switch {
	case dstPort == 53 && srcPort == 53:
		isQuery = payloadHasQueryMarker(payload)
		if isQuery {
			clientIP, clientPort = srcIP, srcPort
		} else {
			clientIP, clientPort = dstIP, dstPort
		}
	case dstPort == 53:
		isQuery = true
		clientIP, clientPort = srcIP, srcPort
	case srcPort == 53:
		clientIP, clientPort = dstIP, dstPort
	default:
		return nil, nil
	}

	if p.resolverIP != "" && clientIP == p.resolverIP {
		return nil, nil
	}

	if isQuery {
		return parseTcpdumpQuery(payload, ts, clientIP, clientPort)
	}
	return parseTcpdumpResponse(payload, ts, clientIP, clientPort)
}

func payloadHasQueryMarker(payload string) bool {
	for _, f := range strings.Fields(payload) {
		if strings.HasSuffix(f, "?") {
			return true
		}
	}
	return false
}

func parseTcpdumpQuery(payload string, ts time.Time, clientIP string, clientPort uint16) ([]DnsEvent, error) {
	fields := strings.Fields(payload)
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

func parseTcpdumpResponse(payload string, ts time.Time, clientIP string, clientPort uint16) ([]DnsEvent, error) {
	if idx := strings.LastIndex(payload, " ("); idx >= 0 {
		payload = payload[:idx]
	}
	loc := respCountsRe.FindStringSubmatchIndex(payload)
	if loc == nil {
		return nil, nil
	}
	ancount, _ := strconv.Atoi(payload[loc[2]:loc[3]])
	answerSection := strings.TrimSpace(payload[loc[1]:])
	if ancount == 0 || answerSection == "" {
		return nil, nil
	}

	rrs := strings.Split(answerSection, ", ")
	firstFields := strings.Fields(rrs[0])
	if len(firstFields) < 2 {
		return nil, nil
	}
	qname := normalizeHost(firstFields[0])
	firstType := firstFields[1]
	if qname == "" {
		return nil, nil
	}

	var events []DnsEvent
	for _, rr := range rrs {
		fset := strings.Fields(rr)
		if len(fset) < 3 {
			continue
		}
		typ := fset[1]
		if typ != "A" && typ != "AAAA" {
			continue
		}
		ip := net.ParseIP(fset[2])
		if ip == nil {
			continue
		}
		if typ == "A" && ip.To4() == nil {
			continue
		}
		if typ == "AAAA" && ip.To4() != nil {
			continue
		}
		events = append(events, DnsEvent{
			EventTime:  ts,
			ClientIP:   clientIP,
			ClientPort: clientPort,
			QName:      qname,
			QType:      typ,
			AnswerIP:   fset[2],
			TTLUnknown: true,
		})
	}
	if len(events) == 0 {
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

func splitIPPort(s string) (ip string, port uint16, ok bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", 0, false
	}
	pp, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return "", 0, false
	}
	return s[:i], uint16(pp), true
}

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
