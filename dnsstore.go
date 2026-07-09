package main

import (
	"context"
	"log/slog"
	"sort"
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
		now:     time.Now,
	}
	if conn != nil {
		w := &chDNSWriter{conn: conn, maxBuffer: 100_000}
		w.sendFn = w.sendDNS
		s.ch = w
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
// persisted to the event table by ingestDNS). Newest-event-wins keeps a
// replayed/out-of-order older resolution from clobbering a newer one.
func (s *DNSStore) applyDNS(e DnsEvent) {
	if e.AnswerIP == "" || e.QName == "" {
		return
	}
	ttl := time.Duration(e.TTL) * time.Second
	if ttl > dnsMaxTTL {
		ttl = dnsMaxTTL
	}
	if ttl < dnsMinTTL {
		ttl = dnsMinTTL
	}
	k := dnsKey{e.ClientIP, e.AnswerIP}

	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.entries[k]; ok && e.EventTime.Before(b.eventTime) {
		return // older than current binding: don't overwrite newer state
	}
	if _, exists := s.entries[k]; !exists {
		s.evictToCapLocked()
	}
	s.entries[k] = dnsBinding{
		hostname:  e.QName,
		eventTime: e.EventTime,
		deadline:  e.EventTime.Add(ttl),
	}
}

// evictToCapLocked enforces the hard size cap before an insert that would grow
// the map. It drops expired entries first; if still at the cap it drops the
// oldest chunk (by deadline) in one pass so this O(n) sweep amortizes over many
// inserts rather than running per insert. Caller holds the write lock.
func (s *DNSStore) evictToCapLocked() {
	if len(s.entries) < s.maxSize {
		return
	}
	now := s.now()
	for k, b := range s.entries {
		if now.After(b.deadline) {
			delete(s.entries, k)
			dnsEvictions.Inc()
		}
	}
	if len(s.entries) < s.maxSize {
		return
	}
	// Still full: shed the oldest ~1/16 of capacity in one sorted pass, leaving
	// headroom so the next inserts don't each re-trigger this. At least one is
	// dropped so a tiny cap still makes room.
	shed := s.maxSize / 16
	if shed < 1 {
		shed = 1
	}
	target := s.maxSize - shed
	aged := make([]struct {
		k dnsKey
		d time.Time
	}, 0, len(s.entries))
	for k, b := range s.entries {
		aged = append(aged, struct {
			k dnsKey
			d time.Time
		}{k, b.deadline})
	}
	sort.Slice(aged, func(i, j int) bool { return aged[i].d.Before(aged[j].d) })
	for i := 0; i < len(aged) && len(s.entries) > target; i++ {
		delete(s.entries, aged[i].k)
		dnsEvictions.Inc()
	}
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

func (s *DNSStore) ingestDNS(line string) {
	evs, err := parseDNSLine(line, s.dnsLoc)
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
		`INSERT INTO dns_events (event_time, client_ip, qname, qtype, answer_ip, ttl)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := batch.Append(r.EventTime, r.ClientIP, r.QName, r.QType, r.AnswerIP, r.TTL); err != nil {
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
