package main

import (
	"context"
	"log"
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
	conn    driver.Conn
	mu      sync.Mutex
	buffer  []FlowRow
	maxSize int
	maxAge  time.Duration
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
	return &BatchWriter{
		conn:    conn,
		buffer:  make([]FlowRow, 0, 50_000),
		maxSize: 50_000,
		maxAge:  1 * time.Second,
	}, nil
}

// applySchema runs the DDL statements to create tables if they don't exist.
func applySchema(conn driver.Conn) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS flows (
			timestamp        DateTime,
			tenant_id        UInt32,
			tenant_name      LowCardinality(String),
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
	log.Println("clickhouse schema ready")
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
	w.mu.Lock()
	if len(w.buffer) == 0 {
		w.mu.Unlock()
		return
	}
	rows := w.buffer
	w.buffer = make([]FlowRow, 0, w.maxSize)
	w.mu.Unlock()

	ctx := context.Background()
	batch, err := w.conn.PrepareBatch(ctx, "INSERT INTO flows")
	if err != nil {
		log.Printf("clickhouse prepare batch: %v", err)
		return
	}
	for _, r := range rows {
		if err := batch.Append(
			r.Timestamp, r.TenantID, r.TenantName,
			r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Protocol,
			r.Bytes, r.Packets,
			r.SrcCountry, r.SrcCity, r.SrcLat, r.SrcLon, r.SrcASN, r.SrcOrg,
			r.DstCountry, r.DstCity, r.DstLat, r.DstLon, r.DstASN, r.DstOrg,
			r.IsThreatSrc, r.IsThreatDst, r.ThreatLabel,
			r.IsSampled, r.SamplingRate, r.ExpandedBytes, r.ExpandedPackets,
			r.ExporterIP, r.FlowType,
		); err != nil {
			log.Printf("clickhouse append: %v", err)
		}
	}
	if err := batch.Send(); err != nil {
		log.Printf("clickhouse batch send: %v", err)
		return
	}
	log.Printf("clickhouse: flushed %d rows", len(rows))
}

// StartFlushTimer flushes on a time trigger (whichever fires first: count or timer).
// On shutdown (ctx.Done), performs one final flush to drain the buffer.
func (w *BatchWriter) StartFlushTimer(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(w.maxAge)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				w.flush()
				return
			case <-ticker.C:
				w.flush()
			}
		}
	}()
}
