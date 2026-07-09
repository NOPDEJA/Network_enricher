package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// IdentityStore answers "who was behind this IP at this moment" for campus-WiFi
// forensics. It keeps a small CURRENT-STATE view built from two log streams:
//
//	DHCP audit log:   ip  -> macToken   (which device holds the lease)
//	NPS/RADIUS log:   mac -> userToken  (which user authenticated that device)
//
// so a flow's source IP resolves to a device and a user via a two-hop join on
// the MAC — the RADIUS accounting stream never carries the client IP, only the
// MAC, which is why the DHCP lease is the necessary middle hop.
//
// Both the username and MAC are stored only as pseudonymous tokens (see
// pseudonym.go); raw identifiers are turned into tokens in the parsers and
// never enter this store.
//
// Timezone note: log timestamps carry no zone, so each parser interprets them
// in a configured *time.Location (npsLoc / dhcpLoc), resolved at startup from
// the LOG_TZ knob (global, with per-source NPS_LOG_TZ / DHCP_LOG_TZ overrides;
// see logtz.go). Real Windows NPS/DHCP servers write local time — set LOG_TZ to
// the server's zone (e.g. Asia/Bangkok) so timestamps join correctly against
// the flows; the default is UTC. An invalid zone fails loud at startup.
type IdentityStore struct {
	mu       sync.RWMutex
	ipState  map[string]ipBinding  // ip -> device holding the lease
	macState map[string]macBinding // macToken -> authenticated user session

	maxLease   time.Duration // hard cap on how long a lease is trusted without renewal
	maxSession time.Duration // idle bound on a RADIUS session with no Stop

	tok     *Tokenizer
	npsDir  string
	dhcpDir string
	npsLoc  *time.Location // zone the NPS log's naive timestamps are in
	dhcpLoc *time.Location // zone the DHCP log's naive timestamps are in

	// offsets tracks per-file read position across scans. Only the single poller
	// goroutine touches it, so it needs no lock.
	offsets map[string]int64

	ch *chEventWriter // ClickHouse persistence; nil when ClickHouse is down

	// now is the clock, swappable in tests. Defaults to time.Now.
	now func() time.Time
}

type ipBinding struct {
	macToken  string
	eventTime time.Time // time of the event that set this binding (newest-wins guard)
	deadline  time.Time // lease is trusted until this instant
}

type macBinding struct {
	userToken string
	sessionID string
	eventTime time.Time // time of the event that set this binding (newest-wins guard)
	deadline  time.Time // session is trusted until this instant
}

// NewIdentityStore builds the store. conn may be nil (ClickHouse unavailable),
// in which case events are still applied to the in-memory view for live tagging
// but not persisted.
func NewIdentityStore(tok *Tokenizer, npsDir, dhcpDir string, npsLoc, dhcpLoc *time.Location, maxLease, maxSession time.Duration, conn driver.Conn) *IdentityStore {
	if npsLoc == nil {
		npsLoc = time.UTC
	}
	if dhcpLoc == nil {
		dhcpLoc = time.UTC
	}
	s := &IdentityStore{
		ipState:    make(map[string]ipBinding),
		macState:   make(map[string]macBinding),
		maxLease:   maxLease,
		maxSession: maxSession,
		tok:        tok,
		npsDir:     npsDir,
		dhcpDir:    dhcpDir,
		npsLoc:     npsLoc,
		dhcpLoc:    dhcpLoc,
		offsets:    make(map[string]int64),
		now:        time.Now,
	}
	if conn != nil {
		w := &chEventWriter{conn: conn, maxBuffer: 100_000}
		w.sendDHCPFn = w.sendDHCP
		w.sendRadiusFn = w.sendRadius
		s.ch = w
	}
	return s
}

// Lookup resolves an IP to (macToken, userToken). It is the flow hot-path entry
// point: one RLock, up to two map reads, no I/O and no allocation beyond
// returning strings already interned in the store. An expired lease or session
// reads as absent (deadline check), so stale bindings never tag a flow even
// before the periodic sweep removes them. Either token may be "" independently:
// a known device whose user session has ended returns (macToken, "").
func (s *IdentityStore) Lookup(ip string) (macToken, userToken string) {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	ib, ok := s.ipState[ip]
	if !ok || now.After(ib.deadline) {
		return "", ""
	}
	mb, ok := s.macState[ib.macToken]
	if !ok || now.After(mb.deadline) {
		return ib.macToken, ""
	}
	return ib.macToken, mb.userToken
}

// applyDHCP folds one lease event into the in-memory view.
//
//	10 assign / 11 renew  -> (re)open the lease; a different MAC on the same IP
//	                         replaces the old binding (reassignment wins)
//	12 release            -> close the lease, but only if it still belongs to the
//	                         releasing MAC (ignore a stale release for an IP that
//	                         has already been reassigned)
//
// Newest-event-wins: an event older than the binding it would change is ignored,
// so a restart replay (offsets are in-memory, so a restart re-reads from 0) or a
// multi-file scan applying files out of order can't roll state backward.
//
// The lease deadline is event time + maxLease: the audit log has no reliable
// lease-duration column, so maxLease is the trust horizon.
func (s *IdentityStore) applyDHCP(e DhcpEvent) {
	if e.MACToken == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	switch e.EventID {
	case 10, 11:
		if b, ok := s.ipState[e.IP]; ok && e.EventTime.Before(b.eventTime) {
			return // older than current binding: don't overwrite newer state
		}
		s.ipState[e.IP] = ipBinding{macToken: e.MACToken, eventTime: e.EventTime, deadline: e.EventTime.Add(s.maxLease)}
	case 12:
		if b, ok := s.ipState[e.IP]; ok && b.macToken == e.MACToken && !e.EventTime.Before(b.eventTime) {
			delete(s.ipState, e.IP)
		}
	}
}

// applyRADIUS folds one accounting event into the in-memory view.
//
//	Start           -> open the session for this MAC
//	Interim-Update  -> extend it (idle bound resets)
//	Stop            -> close it
//
// Newest-event-wins keeps out-of-order/replayed records from misattributing a
// device:
//   - Start/Interim applies when there's no binding, when it's for the same
//     session, or when it's newer than the current binding (a newer session
//     takes over; an Interim whose Start we never saw — e.g. after a restart —
//     bootstraps state). An older event from a *different* session is ignored,
//     and an older event for the *same* session must not shrink the deadline.
//   - Stop closes the session only on an exact session-ID match (so a Stop with
//     an empty Acct-Session-Id can only close a binding whose stored ID is also
//     empty, never a live named session) and only if it isn't older than the
//     binding.
//
// The session survives a device roaming to a new IP: the new DHCP lease points
// the new IP at the same MAC, whose session is still open — so the user stays
// resolvable at the new address without a re-auth.
func (s *IdentityStore) applyRADIUS(e RadiusEvent) {
	if e.MACToken == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	switch e.AcctStatus {
	case "Start", "Interim-Update":
		if b, ok := s.macState[e.MACToken]; ok {
			if b.sessionID == e.SessionID {
				if e.EventTime.Before(b.eventTime) {
					return // older same-session event: don't move the deadline backward
				}
			} else if e.EventTime.Before(b.eventTime) {
				return // older event from a different session: ignore
			}
		}
		s.macState[e.MACToken] = macBinding{
			userToken: e.UserToken,
			sessionID: e.SessionID,
			eventTime: e.EventTime,
			deadline:  e.EventTime.Add(s.maxSession),
		}
	case "Stop":
		if b, ok := s.macState[e.MACToken]; ok && b.sessionID == e.SessionID && !e.EventTime.Before(b.eventTime) {
			delete(s.macState, e.MACToken)
		}
	}
}

// evictExpired drops bindings past their deadline so the maps stay bounded to
// currently-active leases and sessions. Event volume is tiny, so a full sweep
// on each poll is cheap; it runs under the write lock.
func (s *IdentityStore) evictExpired() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, b := range s.ipState {
		if now.After(b.deadline) {
			delete(s.ipState, ip)
		}
	}
	for mac, b := range s.macState {
		if now.After(b.deadline) {
			delete(s.macState, mac)
		}
	}
}

// StartPoller owns the single goroutine that tails the log directories every
// 30s, feeding new lines to the in-memory store and to ClickHouse. It scans
// once immediately so tagging is warm shortly after start, then on the ticker
// until ctx is cancelled.
func (s *IdentityStore) StartPoller(ctx context.Context) {
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

// scan reads newly-appended lines from every file in both log directories,
// applies the parsed events, flushes them to ClickHouse, then evicts expired
// bindings. It is only ever called from the poller goroutine.
//
// It recovers from any panic: the poller parses untrusted log input and has no
// supervisor, so an unhandled panic would silently kill identity ingestion for
// the rest of the process lifetime. A recovered scan just resumes next tick.
func (s *IdentityStore) scan() {
	defer func() {
		if r := recover(); r != nil {
			identityScanPanics.Inc()
			slog.Error("identity: scan panicked, recovered", "panic", r)
		}
	}()
	s.scanDir(s.npsDir, sourceNPS)
	s.scanDir(s.dhcpDir, sourceDHCP)
	if s.ch != nil {
		s.ch.flush()
	}
	s.evictExpired()
}

const (
	sourceNPS  = "nps"
	sourceDHCP = "dhcp"
)

// scanDir tails one identity log directory using the shared incremental-scan
// core (see filepoller.go), routing each line to the matching parser.
func (s *IdentityStore) scanDir(dir, source string) {
	scanAppendedDir(dir, source, s.offsets, func(line string) {
		if source == sourceNPS {
			s.ingestNPS(line)
		} else {
			s.ingestDHCP(line)
		}
	})
}

func (s *IdentityStore) ingestNPS(line string) {
	ev, ok, err := parseNPSLine(line, s.tok, s.npsLoc)
	if err != nil {
		identityParseErrors.WithLabelValues(sourceNPS).Inc()
		return
	}
	if !ok {
		return
	}
	identityEventsParsed.WithLabelValues(sourceNPS).Inc()
	s.applyRADIUS(ev)
	if s.ch != nil {
		s.ch.addRadius(ev)
	}
}

func (s *IdentityStore) ingestDHCP(line string) {
	ev, ok, err := parseDHCPLine(line, s.tok, s.dhcpLoc)
	if err != nil {
		identityParseErrors.WithLabelValues(sourceDHCP).Inc()
		return
	}
	if !ok {
		return
	}
	identityEventsParsed.WithLabelValues(sourceDHCP).Inc()
	s.applyDHCP(ev)
	if s.ch != nil {
		s.ch.addDHCP(ev)
	}
}

// chEventWriter persists identity events to ClickHouse. The event tables are the
// append-only forensic source of truth, but volume is tiny (thousands/day), so
// this stays deliberately simple: buffer within a scan, flush at scan end, and
// on a ClickHouse error keep the batch to retry next scan (bounded so a long
// outage can't grow it without limit). It stays entirely separate from the
// flow-path BatchWriter.
//
// The poller goroutine drives add/flush during normal operation; the shutdown
// drain (IdentityStore.FinalFlush) also calls flush from main's goroutine, which
// can overlap an in-flight poller scan, so a mutex guards the buffers.
type chEventWriter struct {
	conn      driver.Conn
	mu        sync.Mutex
	dhcp      []DhcpEvent
	radius    []RadiusEvent
	maxBuffer int

	// sendDHCPFn / sendRadiusFn perform the actual ClickHouse write. They're
	// fields (defaulted to the real methods in NewIdentityStore) so tests can stub
	// the round-trip, matching the flow BatchWriter's `send` field pattern.
	sendDHCPFn   func([]DhcpEvent) error
	sendRadiusFn func([]RadiusEvent) error
}

func (w *chEventWriter) addDHCP(e DhcpEvent) {
	w.mu.Lock()
	w.dhcp = append(w.dhcp, e)
	w.mu.Unlock()
}

func (w *chEventWriter) addRadius(e RadiusEvent) {
	w.mu.Lock()
	w.radius = append(w.radius, e)
	w.mu.Unlock()
}

func (w *chEventWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.dhcp) > 0 {
		if err := w.sendDHCPFn(w.dhcp); err != nil {
			slog.Error("identity: clickhouse dhcp write failed, will retry", "rows", len(w.dhcp), "err", err)
			identityEventWriteErrors.Inc()
			w.dhcp = capTail(w.dhcp, w.maxBuffer)
		} else {
			w.dhcp = w.dhcp[:0]
		}
	}
	if len(w.radius) > 0 {
		if err := w.sendRadiusFn(w.radius); err != nil {
			slog.Error("identity: clickhouse radius write failed, will retry", "rows", len(w.radius), "err", err)
			identityEventWriteErrors.Inc()
			w.radius = capTail(w.radius, w.maxBuffer)
		} else {
			w.radius = w.radius[:0]
		}
	}
}

// eventWriteTimeout bounds a single ClickHouse insert so a hung connection can't
// stall the poller goroutine indefinitely.
const eventWriteTimeout = 10 * time.Second

func (w *chEventWriter) sendDHCP(rows []DhcpEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), eventWriteTimeout)
	defer cancel()
	batch, err := w.conn.PrepareBatch(ctx,
		`INSERT INTO identity_dhcp_events (event_time, event_id, ip, mac_token, host_token)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := batch.Append(r.EventTime, r.EventID, r.IP, r.MACToken, r.HostToken); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (w *chEventWriter) sendRadius(rows []RadiusEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), eventWriteTimeout)
	defer cancel()
	batch, err := w.conn.PrepareBatch(ctx,
		`INSERT INTO identity_radius_events (event_time, acct_status, session_id, user_token, mac_token, nas_ip)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := batch.Append(r.EventTime, r.AcctStatus, r.SessionID, r.UserToken, r.MACToken, r.NASIP); err != nil {
			return err
		}
	}
	return batch.Send()
}

// FinalFlush drains any buffered identity events to ClickHouse on shutdown,
// retrying up to attempts times (mirroring the flow BatchWriter's FinalDrain).
// It returns the number of events still unsent — unavoidably lost — if every
// attempt fails.
func (s *IdentityStore) FinalFlush(attempts int) int {
	if s.ch == nil {
		return 0
	}
	for i := 0; ; i++ {
		s.ch.flush()
		s.ch.mu.Lock()
		remaining := len(s.ch.dhcp) + len(s.ch.radius)
		s.ch.mu.Unlock()
		if remaining == 0 || i >= attempts-1 {
			return remaining
		}
		time.Sleep(time.Second)
	}
}

// capTail keeps at most n most-recent elements, dropping the oldest — the
// bounded-buffer backstop for a sustained ClickHouse outage.
func capTail[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
