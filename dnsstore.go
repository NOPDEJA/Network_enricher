package main

import (
	"container/heap"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// DNSStore answers "what hostname did this client resolve for that address"
// for campus-WiFi forensics — the "what" side to the identity "who" side. It
// keeps a live map built from BIND9 resolver logs:
//
//	(clientIP, answeredIP) -> hostname
//
// so a flow whose client resolved dst_ip a moment earlier gets dst_ip's
// hostname stamped on it. Unlike the identity maps this one can explode
// (client × destination cardinality), so it has a HARD size cap with eviction,
// not just a TTL sweep. Hostnames are NOT personal data here and stay in the
// CLEAR — there is no tokenizer.
//
// Timezone note: log timestamps carry no zone; the parser interprets them in
// dnsLoc, resolved at startup from LOG_TZ / DNS_LOG_TZ (see logtz.go).
type DNSStore struct {
	mu      sync.RWMutex
	entries map[dnsKey]dnsBinding

	maxSize int // hard cap on live entries; over it, evict expired-first then oldest

	dnsDir string
	dnsLoc *time.Location

	// offsets tracks per-file read position across scans. Only the single poller
	// goroutine touches it, so it needs no lock.
	offsets map[string]int64

	ch *chDNSWriter // ClickHouse persistence; nil when ClickHouse is down

	// newParser builds a fresh line parser for ONE log file. Per-file because the
	// tcpdump parser is stateful across its two-line packets: a pending header from
	// one file must never pair with a payload from another (cross-file =
	// wrong-client attribution, an evidence-integrity bug). The BIND factory returns
	// a stateless closure, so one-per-file is harmless. Set at construction.
	newParser func() func(line string) ([]DnsEvent, error)

	// parsers holds the live parser per file path, created on first sight of a path.
	// It shares offsets' lifecycle and key set: an entry is created when a file
	// first yields a line, retained for process life, and bounded by the dir's file
	// count (offsets is never pruned either, so the two stay in sync and bounded).
	// Only the single poller goroutine touches it, so it needs no lock.
	parsers map[string]func(line string) ([]DnsEvent, error)

	// now is the clock, swappable in tests. Defaults to time.Now.
	now func() time.Time
}

type dnsKey struct {
	clientIP string
	answerIP string
}

type dnsBinding struct {
	hostname  string
	eventTime time.Time // time of the resolving event (newest-wins guard)
	deadline  time.Time // entry is trusted until this instant
}

const (
	// A resolved answer is trusted for its record TTL, floored and capped: a
	// TTL of 0 or a few seconds must still cover the flow that immediately
	// follows the query, and a multi-day TTL must not pin a stale mapping.
	dnsMinTTL = 60 * time.Second
	dnsMaxTTL = time.Hour

	// dnsDefaultUnknownTTL is the validity granted to an answer whose source omits
	// the record TTL (the tcpdump text format prints no TTLs). Chosen inside the
	// [dnsMinTTL, dnsMaxTTL] band so the floor/cap below leave it unchanged: long
	// enough to tag the flows following the resolution, short enough not to pin a
	// stale mapping. BIND answer events carry a real TTL and never hit this.
	dnsDefaultUnknownTTL = 10 * time.Minute

	// dnsMaxEntries is the hard cap. client×dst cardinality can blow up, so this
	// is the OOM backstop, not just the TTL sweep. ~1M entries.
	dnsMaxEntries = 1 << 20
)

// NewDNSStore builds the store. conn may be nil (ClickHouse unavailable), in
// which case events still tag flows live but are not persisted.
func NewDNSStore(dnsDir string, dnsLoc *time.Location, conn driver.Conn) *DNSStore {
	if dnsLoc == nil {
		dnsLoc = time.UTC
	}
	s := &DNSStore{
		entries: make(map[dnsKey]dnsBinding),
		maxSize: dnsMaxEntries,
		dnsDir:  dnsDir,
		dnsLoc:  dnsLoc,
		offsets: make(map[string]int64),
		parsers: make(map[string]func(line string) ([]DnsEvent, error)),
		now:     time.Now,
	}
	s.newParser = func() func(line string) ([]DnsEvent, error) {
		return func(line string) ([]DnsEvent, error) { return parseDNSLine(line, s.dnsLoc) }
	}
	if conn != nil {
		w := &chDNSWriter{conn: conn, maxBuffer: 100_000}
		w.sendFn = w.sendDNS
		s.ch = w
	}
	return s
}

// NewDNSStoreTcpdump builds a store that ingests `tcpdump -v` verbose text instead
// of BIND resolver logs. It reuses NewDNSStore's map/eviction/persistence and only
// swaps the parse function for the stateful two-line tcpdump parser. baseDate seeds
// the parser's date anchor (tcpdump prints no date); resolverIP may be "".
func NewDNSStoreTcpdump(dnsDir string, dnsLoc *time.Location, baseDate time.Time, resolverIP string, conn driver.Conn) *DNSStore {
	s := NewDNSStore(dnsDir, dnsLoc, conn)
	s.newParser = func() func(line string) ([]DnsEvent, error) {
		return newTcpdumpDNSParser(s.dnsLoc, baseDate, resolverIP).feed
	}
	return s
}

// NewDNSStoreDnstap builds a store that ingests `dnstap-read -y` YAML text (BIND's
// binary response log, converted by the dnstap-export sidecar) instead of BIND
// resolver logs. It reuses NewDNSStore's map/eviction/persistence and only swaps
// the parse function for the stateful multi-line dnstap parser. dnsLoc is accepted
// for signature parity with the other constructors but IGNORED by the parser: the
// dnstap YAML timestamps carry an explicit zone (RFC3339 Z), so there is nothing
// to interpret.
func NewDNSStoreDnstap(dnsDir string, dnsLoc *time.Location, conn driver.Conn) *DNSStore {
	s := NewDNSStore(dnsDir, dnsLoc, conn)
	s.newParser = func() func(line string) ([]DnsEvent, error) {
		return newDnstapDNSParser().feed
	}
	return s
}

// Lookup resolves (clientIP, answeredIP) to the hostname the client last saw
// for that address. Flow hot-path: one RLock, one map read, no I/O and no
// allocation. An expired entry reads as absent, so a stale mapping never tags a
// flow. A miss returns "" — the flow proceeds untagged (fail open).
func (s *DNSStore) Lookup(clientIP, answeredIP string) string {
	if clientIP == "" || answeredIP == "" {
		return ""
	}
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.entries[dnsKey{clientIP, answeredIP}]
	if !ok || now.After(b.deadline) {
		return ""
	}
	return b.hostname
}

// applyDNS folds one resolved answer into the live map. A query-only event
// (empty AnswerIP) can't key a live tag, so it is a no-op here (it is still
// persisted to the event table by ingestDNS).
//
// SINGLE-MUTATOR INVARIANT: applyDNS runs only on the poller goroutine, so no
// other goroutine ever writes s.entries. That lets the expensive eviction
// SELECTION run under RLock (concurrent enrich-path Lookups keep flowing) with
// only the bounded deletion pass under the write lock — the O(n) scan never
// stalls Lookups.
//
// Newest-event-wins keeps a replayed/out-of-order older resolution from
// clobbering a newer one; ties (equal EventTime, different hostname) break
// deterministically on the greater hostname so scan order can't decide the
// final state (replay-order-independent).
func (s *DNSStore) applyDNS(e DnsEvent) {
	if e.AnswerIP == "" || e.QName == "" {
		return
	}
	// Only an answer flagged TTLUnknown (the tcpdump text format prints no TTL) gets
	// the documented unknown-TTL horizon. A genuine TTL — including a real BIND
	// TTL==0 record — passes through as-is and is clamped to the 60s floor, so the
	// tcpdump default never leaks into the BIND path. Both are clamped to
	// [dnsMinTTL, dnsMaxTTL].
	var ttl time.Duration
	if e.TTLUnknown {
		ttl = dnsDefaultUnknownTTL
	} else {
		ttl = time.Duration(e.TTL) * time.Second
	}
	if ttl > dnsMaxTTL {
		ttl = dnsMaxTTL
	}
	if ttl < dnsMinTTL {
		ttl = dnsMinTTL
	}
	k := dnsKey{e.ClientIP, e.AnswerIP}

	// Only a brand-new key grows the map, so only then must we make room. Select
	// victims without the write lock, then delete them under it (bounded hold).
	s.mu.RLock()
	_, exists := s.entries[k]
	atCap := !exists && len(s.entries) >= s.maxSize
	s.mu.RUnlock()
	if atCap {
		if victims := s.selectEvictions(); len(victims) > 0 {
			s.mu.Lock()
			for _, vk := range victims {
				// Sole mutator: no re-check needed, each victim is still present.
				delete(s.entries, vk)
				dnsEvictions.Inc()
			}
			s.mu.Unlock()
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.entries[k]; ok {
		if e.EventTime.Before(b.eventTime) {
			return // older than current binding: don't overwrite newer state
		}
		if e.EventTime.Equal(b.eventTime) && e.QName <= b.hostname {
			return // tie: keep unless the new hostname sorts strictly greater
		}
	}
	s.entries[k] = dnsBinding{
		hostname:  e.QName,
		eventTime: e.EventTime,
		deadline:  e.EventTime.Add(ttl),
	}
}

// selectEvictions picks the keys to shed when a new insert would exceed the cap:
// all expired entries first, then, if that frees fewer than `shed` slots, the
// oldest (earliest-deadline) non-expired entries to make up the difference. The
// oldest are chosen with a bounded max-heap of size `shed` — a partial selection
// over one O(n) pass, never a full sort. Runs under RLock only (see the
// single-mutator invariant on applyDNS), so Lookups aren't blocked.
func (s *DNSStore) selectEvictions() []dnsKey {
	now := s.now()
	shed := s.maxSize / 16
	if shed < 1 {
		shed = 1
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var expired []dnsKey
	oldest := &victimHeap{} // max-heap: root is the latest deadline among the kept oldest
	for k, b := range s.entries {
		if now.After(b.deadline) {
			expired = append(expired, k)
			continue
		}
		if oldest.Len() < shed {
			heap.Push(oldest, victim{key: k, deadline: b.deadline})
		} else if b.deadline.Before((*oldest)[0].deadline) {
			(*oldest)[0] = victim{key: k, deadline: b.deadline}
			heap.Fix(oldest, 0)
		}
	}

	// Expired alone may already free enough; otherwise top up with the oldest.
	victims := expired
	need := shed - len(expired)
	for i := 0; i < oldest.Len() && need > 0; i++ {
		victims = append(victims, (*oldest)[i].key)
		need--
	}
	return victims
}

// victim/victimHeap back the bounded oldest-selection in selectEvictions.
type victim struct {
	key      dnsKey
	deadline time.Time
}

type victimHeap []victim

func (h victimHeap) Len() int           { return len(h) }
func (h victimHeap) Less(i, j int) bool { return h[i].deadline.After(h[j].deadline) } // max at root
func (h victimHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *victimHeap) Push(x any)        { *h = append(*h, x.(victim)) }
func (h *victimHeap) Pop() any {
	old := *h
	n := len(old)
	v := old[n-1]
	*h = old[:n-1]
	return v
}

// evictExpired drops entries past their deadline. Normal housekeeping run at the
// end of each scan (not counted as a cap eviction); keeps the map bounded to
// currently-valid mappings between cardinality spikes.
func (s *DNSStore) evictExpired() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, b := range s.entries {
		if now.After(b.deadline) {
			delete(s.entries, k)
		}
	}
}

// StartPoller owns the single goroutine that tails the DNS log directory every
// 30s. It scans once immediately so tagging is warm shortly after start, then on
// the ticker until ctx is cancelled. Mirrors IdentityStore.StartPoller.
func (s *DNSStore) StartPoller(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		s.scan()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.scan()
			}
		}
	}()
}

const sourceDNS = "dns"

// scan reads newly-appended lines, applies parsed events, flushes to ClickHouse,
// then evicts expired entries. Only ever called from the poller goroutine. It
// recovers from any panic (untrusted log input, no supervisor) so a bad line
// can't silently kill DNS ingestion for the process lifetime.
func (s *DNSStore) scan() {
	defer func() {
		if r := recover(); r != nil {
			dnsScanPanics.Inc()
			slog.Error("dns: scan panicked, recovered", "panic", r)
		}
	}()
	scanAppendedDir(s.dnsDir, sourceDNS, s.offsets, s.ingestDNS)
	if s.ch != nil {
		s.ch.flush()
	}
	s.evictExpired()
}

// ingestDNS parses one line from the file at path through THAT file's parser,
// creating it on first sight. The per-file parser keeps the stateful tcpdump
// parser's pending-header state from leaking across files (see the parsers field).
func (s *DNSStore) ingestDNS(path, line string) {
	p := s.parsers[path]
	if p == nil {
		p = s.newParser()
		s.parsers[path] = p
	}
	evs, err := p(line)
	if err != nil {
		dnsParseErrors.Inc()
		return
	}
	for _, ev := range evs {
		dnsEventsParsed.Inc()
		s.applyDNS(ev)
		if s.ch != nil {
			s.ch.add(ev)
		}
	}
}

// chDNSWriter persists DNS events to ClickHouse. Same deliberately-simple
// buffer-and-flush design as the identity chEventWriter: tiny volume, retry the
// batch on failure (bounded), separate from the flow-path BatchWriter.
type chDNSWriter struct {
	conn      driver.Conn
	mu        sync.Mutex
	dns       []DnsEvent
	maxBuffer int

	// sendFn performs the actual write (defaulted to sendDNS) so tests can stub it.
	sendFn func([]DnsEvent) error
}

func (w *chDNSWriter) add(e DnsEvent) {
	w.mu.Lock()
	w.dns = append(w.dns, e)
	w.mu.Unlock()
}

func (w *chDNSWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.dns) == 0 {
		return
	}
	if err := w.sendFn(w.dns); err != nil {
		slog.Error("dns: clickhouse write failed, will retry", "rows", len(w.dns), "err", err)
		dnsEventWriteErrors.Inc()
		w.dns = capTail(w.dns, w.maxBuffer)
	} else {
		w.dns = w.dns[:0]
	}
}

func (w *chDNSWriter) sendDNS(rows []DnsEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), eventWriteTimeout)
	defer cancel()
	batch, err := w.conn.PrepareBatch(ctx,
		`INSERT INTO dns_events (event_time, client_ip, client_port, qname, qtype, answer_ip, ttl)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := batch.Append(r.EventTime, r.ClientIP, r.ClientPort, r.QName, r.QType, r.AnswerIP, r.TTL); err != nil {
			return err
		}
	}
	return batch.Send()
}

// FinalFlush drains any buffered DNS events to ClickHouse on shutdown, retrying
// up to attempts times. Returns the count still unsent (lost) if every attempt
// fails. Mirrors IdentityStore.FinalFlush.
func (s *DNSStore) FinalFlush(attempts int) int {
	if s.ch == nil {
		return 0
	}
	for i := 0; ; i++ {
		s.ch.flush()
		s.ch.mu.Lock()
		remaining := len(s.ch.dns)
		s.ch.mu.Unlock()
		if remaining == 0 || i >= attempts-1 {
			return remaining
		}
		time.Sleep(time.Second)
	}
}
