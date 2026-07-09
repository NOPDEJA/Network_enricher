package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// FlowRow is a flat struct that maps directly to the ClickHouse flows table.
// It exists separately from EnrichedFlow because ClickHouse insertion needs
// plain scalar types — no nested structs.
type FlowRow struct {
	Timestamp       time.Time
	TenantID        uint32
	TenantName      string
	DstTenantID     uint32
	DstTenantName   string
	SrcMACToken     string
	SrcUserToken    string
	DstMACToken     string
	DstUserToken    string
	SrcHostname     string
	DstHostname     string
	SrcIP           string
	DstIP           string
	SrcPort         uint32
	DstPort         uint32
	Protocol        string
	Bytes           uint64
	Packets         uint64
	SrcCountry      string
	SrcCity         string
	SrcLat          float64
	SrcLon          float64
	SrcASN          uint32
	SrcOrg          string
	DstCountry      string
	DstCity         string
	DstLat          float64
	DstLon          float64
	DstASN          uint32
	DstOrg          string
	IsThreatSrc     uint8
	IsThreatDst     uint8
	ThreatLabel     string
	IsSampled       uint8
	SamplingRate    uint64
	ExpandedBytes   uint64
	ExpandedPackets uint64
	ExporterIP      string
	FlowType        string
}

func toFlowRow(e EnrichedFlow) FlowRow {
	ts := time.Unix(0, int64(e.TimeFlowStartNs))
	if e.TimeFlowStartNs == 0 {
		ts = time.Unix(0, int64(e.TimeReceivedNs))
	}

	var isThreatSrc, isThreatDst uint8
	if e.IsThreatSrc {
		isThreatSrc = 1
	}
	if e.IsThreatDst {
		isThreatDst = 1
	}
	var isSampled uint8
	if e.IsSampled {
		isSampled = 1
	}

	return FlowRow{
		Timestamp:       ts,
		TenantID:        e.TenantID,
		TenantName:      e.TenantName,
		DstTenantID:     e.DstTenantID,
		DstTenantName:   e.DstTenantName,
		SrcMACToken:     e.SrcMACToken,
		SrcUserToken:    e.SrcUserToken,
		DstMACToken:     e.DstMACToken,
		DstUserToken:    e.DstUserToken,
		SrcHostname:     e.SrcHostname,
		DstHostname:     e.DstHostname,
		SrcIP:           e.SrcAddr,
		DstIP:           e.DstAddr,
		SrcPort:         e.SrcPort,
		DstPort:         e.DstPort,
		Protocol:        e.Proto,
		Bytes:           e.Bytes,
		Packets:         e.Packets,
		SrcCountry:      e.SrcGeo.CountryCode,
		SrcCity:         e.SrcGeo.City,
		SrcLat:          e.SrcGeo.Lat,
		SrcLon:          e.SrcGeo.Lon,
		SrcASN:          e.SrcGeo.ASN,
		SrcOrg:          e.SrcGeo.OrgName,
		DstCountry:      e.DstGeo.CountryCode,
		DstCity:         e.DstGeo.City,
		DstLat:          e.DstGeo.Lat,
		DstLon:          e.DstGeo.Lon,
		DstASN:          e.DstGeo.ASN,
		DstOrg:          e.DstGeo.OrgName,
		IsThreatSrc:     isThreatSrc,
		IsThreatDst:     isThreatDst,
		ThreatLabel:     e.ThreatLabel,
		IsSampled:       isSampled,
		SamplingRate:    e.SamplingRate,
		ExpandedBytes:   e.ExpandedBytes,
		ExpandedPackets: e.ExpandedPackets,
		ExporterIP:      e.SamplerAddress,
		FlowType:        e.Type,
	}
}

type BatchWriter struct {
	conn       driver.Conn
	mu         sync.Mutex
	buffer     []FlowRow
	maxSize    int
	maxBuffer  int // hard cap: beyond this the oldest rows are dropped to bound memory
	maxAge     time.Duration
	retryAfter time.Time // skip send attempts until this time after a failure (back-off)

	// send performs the actual write. It returns the rows that should be
	// re-queued on a retryable failure (malformed rows are dropped and excluded);
	// on success it returns nil. It's a field so tests can stub the ClickHouse
	// round-trip; production wires it to sendToClickHouse.
	send func(rows []FlowRow) ([]FlowRow, error)
}

func NewBatchWriter(addr, database, username, password string) (*BatchWriter, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: database,
			Username: username,
			Password: password,
		},
		DialTimeout:  5 * time.Second,
		MaxOpenConns: 4,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(context.Background()); err != nil {
		return nil, err
	}
	if err := applySchema(conn); err != nil {
		return nil, err
	}
	w := &BatchWriter{
		conn:    conn,
		buffer:  make([]FlowRow, 0, 50_000),
		maxSize: 50_000,
		// Cap the re-queue buffer at 10× a normal batch. Under a sustained
		// ClickHouse outage rows accumulate here instead of being dropped; the cap
		// is the OOM backstop, the only place a flow is intentionally lost.
		maxBuffer: 500_000,
		maxAge:    1 * time.Second,
	}
	w.send = w.sendToClickHouse
	return w, nil
}

// applySchema runs the DDL statements to create tables if they don't exist.
func applySchema(conn driver.Conn) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS flows (
			timestamp        DateTime,
			tenant_id        UInt32,
			tenant_name      LowCardinality(String),
			dst_tenant_id    UInt32,
			dst_tenant_name  LowCardinality(String),
			src_mac_token    String,
			src_user_token   String,
			dst_mac_token    String,
			dst_user_token   String,
			src_hostname     String,
			dst_hostname     String,
			src_ip           String,
			dst_ip           String,
			src_port         UInt32,
			dst_port         UInt32,
			protocol         LowCardinality(String),
			bytes            UInt64,
			packets          UInt64,
			src_country      LowCardinality(String),
			src_city         String,
			src_lat          Float64,
			src_lon          Float64,
			src_asn          UInt32,
			src_org          LowCardinality(String),
			dst_country      LowCardinality(String),
			dst_city         String,
			dst_lat          Float64,
			dst_lon          Float64,
			dst_asn          UInt32,
			dst_org          LowCardinality(String),
			is_threat_src    UInt8,
			is_threat_dst    UInt8,
			threat_label     LowCardinality(String),
			is_sampled       UInt8,
			sampling_rate    UInt64,
			expanded_bytes   UInt64,
			expanded_packets UInt64,
			exporter_ip      String,
			flow_type        LowCardinality(String)
		) ENGINE = MergeTree()
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (tenant_id, timestamp, src_ip, dst_ip)
		TTL timestamp + INTERVAL 90 DAY DELETE`,

		// Migration for tables created before dst-side tenant attribution:
		// CREATE IF NOT EXISTS above is a no-op on them, so add the columns here.
		`ALTER TABLE flows
			ADD COLUMN IF NOT EXISTS dst_tenant_id UInt32 AFTER tenant_name,
			ADD COLUMN IF NOT EXISTS dst_tenant_name LowCardinality(String) AFTER dst_tenant_id`,

		// Migration for tables created before identity (who-side) tagging. Columns
		// are empty for untagged flows, so they're additive and safe on old tables.
		`ALTER TABLE flows
			ADD COLUMN IF NOT EXISTS src_mac_token String AFTER dst_tenant_name,
			ADD COLUMN IF NOT EXISTS src_user_token String AFTER src_mac_token,
			ADD COLUMN IF NOT EXISTS dst_mac_token String AFTER src_user_token,
			ADD COLUMN IF NOT EXISTS dst_user_token String AFTER dst_mac_token`,

		// Migration for tables created before DNS (what-side) tagging. Additive and
		// safe on old tables: empty for untagged flows.
		`ALTER TABLE flows
			ADD COLUMN IF NOT EXISTS src_hostname String AFTER dst_user_token,
			ADD COLUMN IF NOT EXISTS dst_hostname String AFTER src_hostname`,

		// Identity event tables: append-only forensic source of truth for the
		// DHCP+RADIUS join. Volume is tiny (thousands/day). MAC and username are
		// stored only as pseudonymous tokens.
		// ReplacingMergeTree + a fully-identifying ORDER BY makes replay idempotent:
		// offsets are in-memory only, so a restart re-reads the logs from byte 0 and
		// re-inserts every event — identical rows collapse on merge. Dedup is
		// eventual (merge-time), so exact forensic queries should use FINAL or
		// GROUP BY.
		`CREATE TABLE IF NOT EXISTS identity_dhcp_events (
			event_time DateTime,
			event_id   UInt16,
			ip         String,
			mac_token  String,
			host_token String
		) ENGINE = ReplacingMergeTree()
		PARTITION BY toYYYYMMDD(event_time)
		ORDER BY (ip, event_time, event_id, mac_token)
		TTL event_time + INTERVAL 90 DAY DELETE`,

		`CREATE TABLE IF NOT EXISTS identity_radius_events (
			event_time  DateTime,
			acct_status LowCardinality(String),
			session_id  String,
			user_token  String,
			mac_token   String,
			nas_ip      String
		) ENGINE = ReplacingMergeTree()
		PARTITION BY toYYYYMMDD(event_time)
		ORDER BY (mac_token, event_time, session_id, acct_status)
		TTL event_time + INTERVAL 90 DAY DELETE`,

		// DNS event table: append-only forensic record of hostnames clients
		// resolved. Hostnames stay in the CLEAR (not personal data here). Same
		// ReplacingMergeTree + fully-identifying ORDER BY as the identity tables so
		// restart-replay dedups on merge.
		`CREATE TABLE IF NOT EXISTS dns_events (
			event_time  DateTime,
			client_ip   String,
			client_port UInt16,
			qname       String,
			qtype       LowCardinality(String),
			answer_ip   String,
			ttl         UInt32
		) ENGINE = ReplacingMergeTree()
		PARTITION BY toYYYYMMDD(event_time)
		ORDER BY (client_ip, qname, answer_ip, event_time, qtype, client_port, ttl)
		TTL event_time + INTERVAL 90 DAY DELETE`,

		`CREATE TABLE IF NOT EXISTS flows_1m (
			timestamp    DateTime,
			tenant_id    UInt32,
			src_country  LowCardinality(String),
			dst_country  LowCardinality(String),
			protocol     LowCardinality(String),
			bytes        UInt64,
			packets      UInt64,
			flow_count   UInt64
		) ENGINE = SummingMergeTree()
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (tenant_id, timestamp, src_country, dst_country, protocol)`,

		`CREATE MATERIALIZED VIEW IF NOT EXISTS flows_1m_mv TO flows_1m AS
		SELECT
			toStartOfMinute(timestamp) AS timestamp,
			tenant_id,
			src_country,
			dst_country,
			protocol,
			sum(bytes)   AS bytes,
			sum(packets) AS packets,
			count()      AS flow_count
		FROM flows
		GROUP BY timestamp, tenant_id, src_country, dst_country, protocol`,

		`CREATE TABLE IF NOT EXISTS flows_1h (
			timestamp    DateTime,
			tenant_id    UInt32,
			src_country  LowCardinality(String),
			dst_country  LowCardinality(String),
			protocol     LowCardinality(String),
			bytes        UInt64,
			packets      UInt64,
			flow_count   UInt64
		) ENGINE = SummingMergeTree()
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (tenant_id, timestamp, src_country, dst_country, protocol)`,

		`CREATE MATERIALIZED VIEW IF NOT EXISTS flows_1h_mv TO flows_1h AS
		SELECT
			toStartOfHour(timestamp) AS timestamp,
			tenant_id,
			src_country,
			dst_country,
			protocol,
			sum(bytes)   AS bytes,
			sum(packets) AS packets,
			count()      AS flow_count
		FROM flows
		GROUP BY timestamp, tenant_id, src_country, dst_country, protocol`,
	}

	ctx := context.Background()
	for _, stmt := range stmts {
		if err := conn.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	slog.Info("clickhouse schema ready")
	return nil
}

func (w *BatchWriter) Add(row FlowRow) {
	w.mu.Lock()
	w.buffer = append(w.buffer, row)
	shouldFlush := len(w.buffer) >= w.maxSize
	w.mu.Unlock()
	if shouldFlush {
		w.flush()
	}
}

func (w *BatchWriter) flush() {
	w.drain(false)
}

// drain sends buffered rows to ClickHouse in maxSize batches. When force is false
// a recent failure's back-off window makes it a no-op, so a size-triggered flush
// doesn't hammer a dead ClickHouse on every flow; the 1s timer retries once the
// window passes. When force is true the back-off is ignored — the shutdown drain
// uses this so a failure in the last back-off window can't strand buffered rows.
func (w *BatchWriter) drain(force bool) {
	w.mu.Lock()
	chBufferRows.Set(float64(len(w.buffer)))
	if len(w.buffer) == 0 || (!force && time.Now().Before(w.retryAfter)) {
		w.mu.Unlock()
		return
	}
	rows := w.buffer
	w.buffer = make([]FlowRow, 0, w.maxSize)
	w.mu.Unlock()

	// Send in maxSize chunks: after a sustained outage the buffer can hold up to
	// maxBuffer rows, and shipping that as one giant insert risks a memory spike or
	// a rejected batch right as ClickHouse recovers.
	for i := 0; i < len(rows); i += w.maxSize {
		end := min(i+w.maxSize, len(rows))
		retryable, err := w.send(rows[i:end])
		if err != nil {
			// Re-queue what we couldn't write: the retryable rows of the failed chunk
			// (malformed rows are already dropped and excluded) plus every later chunk
			// we never attempted. They go ahead of newer arrivals; back off so the next
			// size-triggered flush is a no-op until the timer fires.
			unsent := append(retryable, rows[end:]...)
			slog.Error("clickhouse flush failed, re-queueing rows", "rows", len(unsent), "err", err)
			chWriteErrors.Inc()
			w.mu.Lock()
			w.buffer = append(unsent, w.buffer...)
			w.retryAfter = time.Now().Add(w.maxAge)
			if over := len(w.buffer) - w.maxBuffer; over > 0 {
				// Bounded buffer: a sustained outage must not OOM the process. Dropping
				// the oldest rows is the last resort and the only intentional flow loss.
				w.buffer = w.buffer[over:]
				chRowsDropped.Add(float64(over))
			}
			chBufferRows.Set(float64(len(w.buffer)))
			w.mu.Unlock()
			return
		}
		chFlushes.Inc()
		chRowsWritten.Add(float64(end - i))
	}
}

// FinalDrain flushes any buffered rows on shutdown, ignoring the back-off window
// and retrying up to attempts times (waiting maxAge between tries) so a transient
// failure in the last back-off window doesn't strand buffered rows. It returns the
// number of rows still buffered — unavoidably lost — if every attempt fails.
func (w *BatchWriter) FinalDrain(attempts int) int {
	for i := 0; ; i++ {
		w.drain(true)
		w.mu.Lock()
		remaining := len(w.buffer)
		w.mu.Unlock()
		if remaining == 0 || i >= attempts-1 {
			return remaining
		}
		time.Sleep(w.maxAge)
	}
}

// sendToClickHouse writes one batch. It returns an error only on a failure that
// warrants a retry (prepare or send), along with the rows that should be
// re-queued. A row that can't be appended is malformed — re-queueing it would
// loop forever and re-count it as dropped on every retry — so it's counted as
// dropped once and excluded from the returned set.
func (w *BatchWriter) sendToClickHouse(rows []FlowRow) ([]FlowRow, error) {
	ctx := context.Background()
	// Explicit column list: positional Append stays correct regardless of the
	// physical column order in a table that was migrated with ALTER ADD COLUMN.
	batch, err := w.conn.PrepareBatch(ctx, `INSERT INTO flows (
		timestamp, tenant_id, tenant_name, dst_tenant_id, dst_tenant_name,
		src_mac_token, src_user_token, dst_mac_token, dst_user_token,
		src_hostname, dst_hostname,
		src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets,
		src_country, src_city, src_lat, src_lon, src_asn, src_org,
		dst_country, dst_city, dst_lat, dst_lon, dst_asn, dst_org,
		is_threat_src, is_threat_dst, threat_label,
		is_sampled, sampling_rate, expanded_bytes, expanded_packets,
		exporter_ip, flow_type)`)
	if err != nil {
		return rows, err
	}
	// Zero-cap view so the first append allocates a fresh backing array rather than
	// clobbering the caller's rows slice (drain still references it for re-queueing).
	appended := rows[:0:0]
	for _, r := range rows {
		if err := batch.Append(
			r.Timestamp, r.TenantID, r.TenantName, r.DstTenantID, r.DstTenantName,
			r.SrcMACToken, r.SrcUserToken, r.DstMACToken, r.DstUserToken,
			r.SrcHostname, r.DstHostname,
			r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Protocol,
			r.Bytes, r.Packets,
			r.SrcCountry, r.SrcCity, r.SrcLat, r.SrcLon, r.SrcASN, r.SrcOrg,
			r.DstCountry, r.DstCity, r.DstLat, r.DstLon, r.DstASN, r.DstOrg,
			r.IsThreatSrc, r.IsThreatDst, r.ThreatLabel,
			r.IsSampled, r.SamplingRate, r.ExpandedBytes, r.ExpandedPackets,
			r.ExporterIP, r.FlowType,
		); err != nil {
			slog.Warn("dropping malformed row", "err", err)
			chRowsDropped.Inc()
			continue
		}
		appended = append(appended, r)
	}
	if err := batch.Send(); err != nil {
		return appended, err
	}
	return nil, nil
}

// StartFlushTimer flushes on a time trigger (whichever fires first: count or timer).
// The final drain on shutdown is main's job (after the workers exit) — flushing
// here on ctx.Done would race with workers still calling Add.
func (w *BatchWriter) StartFlushTimer(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(w.maxAge)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.flush()
			}
		}
	}()
}
