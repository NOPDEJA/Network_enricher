package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
// Timezone note: log timestamps are parsed as UTC (see npslog.go / dhcplog.go).
// Real Windows NPS/DHCP servers write local time; a production deployment whose
// servers aren't on UTC should have the parse location set to the server's
// zone. For this scaffold, treating them as UTC keeps parsing deterministic.
type IdentityStore struct {
	mu       sync.RWMutex
	ipState  map[string]ipBinding  // ip -> device holding the lease
	macState map[string]macBinding // macToken -> authenticated user session

	maxLease   time.Duration // hard cap on how long a lease is trusted without renewal
	maxSession time.Duration // idle bound on a RADIUS session with no Stop

	tok     *Tokenizer
	npsDir  string
	dhcpDir string

	// offsets tracks per-file read position across scans. Only the single poller
	// goroutine touches it, so it needs no lock.
	offsets map[string]int64

	ch *chEventWriter // ClickHouse persistence; nil when ClickHouse is down

	// now is the clock, swappable in tests. Defaults to time.Now.
	now func() time.Time
}

type ipBinding struct {
	macToken string
	deadline time.Time // lease is trusted until this instant
}

type macBinding struct {
	userToken string
	sessionID string
	deadline  time.Time // session is trusted until this instant
}

// NewIdentityStore builds the store. conn may be nil (ClickHouse unavailable),
// in which case events are still applied to the in-memory view for live tagging
// but not persisted.
func NewIdentityStore(tok *Tokenizer, npsDir, dhcpDir string, maxLease, maxSession time.Duration, conn driver.Conn) *IdentityStore {
	s := &IdentityStore{
		ipState:    make(map[string]ipBinding),
		macState:   make(map[string]macBinding),
		maxLease:   maxLease,
		maxSession: maxSession,
		tok:        tok,
		npsDir:     npsDir,
		dhcpDir:    dhcpDir,
		offsets:    make(map[string]int64),
		now:        time.Now,
	}
	if conn != nil {
		s.ch = &chEventWriter{conn: conn, maxBuffer: 100_000}
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
		s.ipState[e.IP] = ipBinding{macToken: e.MACToken, deadline: e.EventTime.Add(s.maxLease)}
	case 12:
		if b, ok := s.ipState[e.IP]; ok && b.macToken == e.MACToken {
			delete(s.ipState, e.IP)
		}
	}
}

// applyRADIUS folds one accounting event into the in-memory view.
//
//	Start           -> open the session for this MAC
//	Interim-Update  -> extend it (idle bound resets)
//	Stop            -> close it, but only if the session ID matches the open one,
//	                   so a late Stop for a prior session can't tear down a
//	                   re-auth that already opened a new session on the same MAC
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
		s.macState[e.MACToken] = macBinding{
			userToken: e.UserToken,
			sessionID: e.SessionID,
			deadline:  e.EventTime.Add(s.maxSession),
		}
	case "Stop":
		if b, ok := s.macState[e.MACToken]; ok && (b.sessionID == e.SessionID || e.SessionID == "") {
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
func (s *IdentityStore) scan() {
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

func (s *IdentityStore) scanDir(dir, source string) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Error("identity: cannot read log dir", "source", source, "dir", dir, "err", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		s.readAppended(filepath.Join(dir, entry.Name()), source)
	}
}

// readAppended reads the bytes added to one file since the last scan and parses
// only complete lines (a trailing partial line is left for the next scan). A
// file smaller than its stored offset was rotated/truncated, so it is re-read
// from 0.
func (s *IdentityStore) readAppended(path, source string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	size := fi.Size()
	off := s.offsets[path]
	if size < off {
		off = 0 // rotation or truncation: start over
	}
	if size == off {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		slog.Error("identity: cannot open log file", "source", source, "path", path, "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return
	}

	// Only advance past the last newline; hold back any partial final line.
	nl := bytes.LastIndexByte(data, '\n')
	if nl < 0 {
		return
	}
	s.offsets[path] = off + int64(nl+1)

	for _, raw := range bytes.Split(data[:nl+1], []byte{'\n'}) {
		line := strings.TrimRight(string(raw), "\r")
		if line == "" {
			continue
		}
		if source == sourceNPS {
			s.ingestNPS(line)
		} else {
			s.ingestDHCP(line)
		}
	}
}

func (s *IdentityStore) ingestNPS(line string) {
	ev, ok, err := parseNPSLine(line, s.tok)
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
	ev, ok, err := parseDHCPLine(line, s.tok)
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
// outage can't grow it without limit). It is touched only by the poller
// goroutine, so it needs no lock — and it stays entirely separate from the
// flow-path BatchWriter.
type chEventWriter struct {
	conn      driver.Conn
	dhcp      []DhcpEvent
	radius    []RadiusEvent
	maxBuffer int
}

func (w *chEventWriter) addDHCP(e DhcpEvent)     { w.dhcp = append(w.dhcp, e) }
func (w *chEventWriter) addRadius(e RadiusEvent) { w.radius = append(w.radius, e) }

func (w *chEventWriter) flush() {
	if len(w.dhcp) > 0 {
		if err := w.sendDHCP(w.dhcp); err != nil {
			slog.Error("identity: clickhouse dhcp write failed, will retry", "rows", len(w.dhcp), "err", err)
			identityEventWriteErrors.Inc()
			w.dhcp = capTail(w.dhcp, w.maxBuffer)
		} else {
			w.dhcp = w.dhcp[:0]
		}
	}
	if len(w.radius) > 0 {
		if err := w.sendRadius(w.radius); err != nil {
			slog.Error("identity: clickhouse radius write failed, will retry", "rows", len(w.radius), "err", err)
			identityEventWriteErrors.Inc()
			w.radius = capTail(w.radius, w.maxBuffer)
		} else {
			w.radius = w.radius[:0]
		}
	}
}

func (w *chEventWriter) sendDHCP(rows []DhcpEvent) error {
	ctx := context.Background()
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
	ctx := context.Background()
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

// capTail keeps at most n most-recent elements, dropping the oldest — the
// bounded-buffer backstop for a sustained ClickHouse outage.
func capTail[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
