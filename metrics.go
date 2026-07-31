package main

import (
	"context"
	"log/slog"
	"net/http"
	pprofhttp "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	flowsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_flows_received_total",
		Help: "Total flows read from Kafka.",
	})
	flowsDeduplicated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_flows_deduplicated_total",
		Help: "Flows dropped as 7-tuple duplicates within the TTL window.",
	})
	flowsWritten = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_flows_written_total",
		Help: "Flows forwarded to ClickHouse or stdout.",
	})
	threatHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "enricher_threat_hits_total",
		Help: "Flows matching threat intel, labeled by direction (src or dst).",
	}, []string{"direction"})
	chFlushes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_clickhouse_flushes_total",
		Help: "Number of ClickHouse batch flush operations.",
	})
	chRowsWritten = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_clickhouse_rows_written_total",
		Help: "Total rows written to ClickHouse across all flushes.",
	})
	chWriteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_clickhouse_write_errors_total",
		Help: "ClickHouse flush attempts that failed; their rows are re-queued, not dropped.",
	})
	chRowsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_clickhouse_rows_dropped_total",
		Help: "Rows dropped because the write buffer hit its hard cap during a sustained ClickHouse outage.",
	})
	chBufferRows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "enricher_clickhouse_buffer_rows",
		Help: "Rows currently buffered awaiting a ClickHouse flush (rises during an outage).",
	})
	threatIPsLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "enricher_threat_ips_loaded",
		Help: "Current number of IPs in the threat intel store.",
	})
	identityEventsParsed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "enricher_identity_events_parsed_total",
		Help: "Identity log events parsed and applied, labeled by source (nps, dhcp, or kea).",
	}, []string{"source"})
	identityParseErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "enricher_identity_parse_errors_total",
		Help: "Malformed identity log lines skipped, labeled by source (nps, dhcp, or kea).",
	}, []string{"source"})
	identityTagHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_identity_tag_hits_total",
		Help: "Flows where identity lookup resolved at least one MAC/user token.",
	})
	identityTagMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_identity_tag_misses_total",
		Help: "Flows where identity lookup resolved no token for either address.",
	})
	identityEventWriteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_identity_event_write_errors_total",
		Help: "ClickHouse write attempts for identity events that failed; the batch is retried next scan.",
	})
	identityScanPanics = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_identity_scan_panics_total",
		Help: "Identity poller scans that panicked and were recovered.",
	})
	dnsEventsParsed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_events_parsed_total",
		Help: "DNS log events parsed and applied.",
	})
	dnsParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_parse_errors_total",
		Help: "Malformed DNS log lines skipped.",
	})
	dnsTagHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_tag_hits_total",
		Help: "Flows where DNS lookup resolved at least one hostname.",
	})
	dnsTagMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_tag_misses_total",
		Help: "Flows where DNS lookup resolved no hostname for either address.",
	})
	dnsEvictions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_evictions_total",
		Help: "DNS store entries evicted under the hard size cap (expired-first, then oldest).",
	})
	dnsEventWriteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_event_write_errors_total",
		Help: "ClickHouse write attempts for DNS events that failed; the batch is retried next scan.",
	})
	dnsScanPanics = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "enricher_dns_scan_panics_total",
		Help: "DNS poller scans that panicked and were recovered.",
	})
)

func registerMetrics() {
	prometheus.MustRegister(
		flowsReceived,
		flowsDeduplicated,
		flowsWritten,
		threatHits,
		chFlushes,
		chRowsWritten,
		chWriteErrors,
		chRowsDropped,
		chBufferRows,
		threatIPsLoaded,
		identityEventsParsed,
		identityParseErrors,
		identityTagHits,
		identityTagMisses,
		identityEventWriteErrors,
		identityScanPanics,
		dnsEventsParsed,
		dnsParseErrors,
		dnsTagHits,
		dnsTagMisses,
		dnsEvictions,
		dnsEventWriteErrors,
		dnsScanPanics,
	)
}

// StartMetricsServer serves /metrics on addr and shuts down when ctx is cancelled.
func StartMetricsServer(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprofhttp.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprofhttp.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprofhttp.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprofhttp.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprofhttp.Trace)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			slog.Error("metrics server shutdown", "err", err)
		}
	}()

	go func() {
		slog.Info("metrics server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "err", err)
		}
	}()
}
