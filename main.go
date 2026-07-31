package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	// tzdata embeds the IANA zone database in the binary so LOG_TZ names like
	// "Asia/Bangkok" resolve via time.LoadLocation on hosts without a system
	// zoneinfo (Windows dev boxes), not just the Ubuntu deploy host.
	_ "time/tzdata"

	// goccy/go-json is a drop-in replacement for encoding/json that decodes the
	// goflow2 record with far fewer allocations — the JSON decode and its GC
	// pressure were the top per-flow CPU cost in the worker pool (see Unmarshal
	// benchmark). API-compatible, so call sites stay json.Unmarshal.
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	json "github.com/goccy/go-json"
	"github.com/segmentio/kafka-go"
)

type FlowMessage struct {
	// Present in all flow types (v5, v9, IPFIX)
	Type            string `json:"type"`
	TimeFlowStartNs uint64 `json:"time_flow_start_ns"`
	TimeFlowEndNs   uint64 `json:"time_flow_end_ns"`
	TimeReceivedNs  uint64 `json:"time_received_ns"`
	SrcAddr         string `json:"src_addr"`
	DstAddr         string `json:"dst_addr"`
	SrcPort         uint32 `json:"src_port"`
	DstPort         uint32 `json:"dst_port"`
	Proto           string `json:"proto"` // "TCP", "UDP", "ICMP", etc.
	Bytes           uint64 `json:"bytes"`
	Packets         uint64 `json:"packets"`
	SamplingRate    uint64 `json:"sampling_rate"`
	SamplerAddress  string `json:"sampler_address"` // exporter IP
	NextHop         string `json:"next_hop"`
	SrcAS           uint32 `json:"src_as"`
	DstAS           uint32 `json:"dst_as"`
	TCPFlags        uint32 `json:"tcp_flags"`
	InIf            uint32 `json:"in_if"`
	OutIf           uint32 `json:"out_if"`
	SequenceNum     uint32 `json:"sequence_num"`

	// Populated by NetFlow v9 and IPFIX, zero/empty in v5
	Etype               string `json:"etype"` // "IPv4" or "IPv6"
	SrcVlan             uint32 `json:"src_vlan"`
	DstVlan             uint32 `json:"dst_vlan"`
	ForwardingStatus    uint32 `json:"forwarding_status"`
	IPTos               uint32 `json:"ip_tos"`
	IPTTL               uint32 `json:"ip_ttl"`
	ObservationDomainId uint32 `json:"observation_domain_id"` // IPFIX only
}

// EnrichedFlow extends FlowMessage with fields added by each enricher stage.
// Week 6 will add dedup status and Prometheus metrics.
type EnrichedFlow struct {
	FlowMessage
	SrcGeo          GeoData
	DstGeo          GeoData
	TenantID        uint32 // tenant owning SrcAddr (outbound attribution)
	TenantName      string
	DstTenantID     uint32 // tenant owning DstAddr (inbound attribution)
	DstTenantName   string
	SrcMACToken     string // device/user behind SrcAddr (pseudonymous tokens)
	SrcUserToken    string
	DstMACToken     string // device/user behind DstAddr (return half of a conversation)
	DstUserToken    string
	SrcHostname     string // hostname the peer resolved for SrcAddr (DNS what-side)
	DstHostname     string // hostname the client resolved for DstAddr
	IsThreatSrc     bool
	IsThreatDst     bool
	ThreatLabel     string
	IsSampled       bool
	ExpandedBytes   uint64
	ExpandedPackets uint64
}

func enrich(flow FlowMessage, geo *GeoStore, tenant *TenantStore, threat *ThreatStore, identity *IdentityStore, dns *DNSStore) EnrichedFlow {
	e := EnrichedFlow{FlowMessage: flow}

	// Parse once and share across enrichers — ParseIP allocates, so skip it
	// entirely when no enricher needs it.
	if geo != nil || tenant != nil {
		srcIP := net.ParseIP(flow.SrcAddr)
		dstIP := net.ParseIP(flow.DstAddr)

		if geo != nil {
			e.SrcGeo = geo.Lookup(srcIP)
			e.DstGeo = geo.Lookup(dstIP)
		}

		if tenant != nil {
			// Attribute both directions: src match covers outbound traffic,
			// dst match covers the return/inbound half of the conversation.
			e.TenantID, e.TenantName = tenant.Lookup(srcIP)
			e.DstTenantID, e.DstTenantName = tenant.Lookup(dstIP)
		}
	}

	// Identity (who-side) tagging: resolve BOTH addresses to pseudonymous
	// device/user tokens. The client is the source on the outbound half of a
	// conversation and the destination on the return half, same as dst-tenant
	// attribution. Two cheap RWMutex map reads each, no I/O; unbound addresses
	// yield empty tokens and the flow proceeds untouched (fail open).
	if identity != nil {
		e.SrcMACToken, e.SrcUserToken = identity.Lookup(flow.SrcAddr)
		e.DstMACToken, e.DstUserToken = identity.Lookup(flow.DstAddr)
		if e.SrcMACToken != "" || e.DstMACToken != "" {
			identityTagHits.Inc()
		} else {
			identityTagMisses.Inc()
		}
	}

	// DNS (what-side) tagging: the client that resolved an address is the source
	// on the outbound half and the destination on the return half — same
	// both-directions pattern as identity/dst-tenant. src=client resolving dst
	// gives dst_hostname; the reverse orientation gives src_hostname. Two cheap
	// RWMutex map reads, no I/O; a miss leaves the field empty (fail open).
	if dns != nil {
		e.DstHostname = dns.Lookup(flow.SrcAddr, flow.DstAddr)
		e.SrcHostname = dns.Lookup(flow.DstAddr, flow.SrcAddr)
		if e.SrcHostname != "" || e.DstHostname != "" {
			dnsTagHits.Inc()
		} else {
			dnsTagMisses.Inc()
		}
	}

	if threat != nil {
		if ok, label := threat.Lookup(flow.SrcAddr); ok {
			e.IsThreatSrc = true
			e.ThreatLabel = label
		}
		if ok, label := threat.Lookup(flow.DstAddr); ok {
			e.IsThreatDst = true
			if e.ThreatLabel == "" {
				e.ThreatLabel = label
			}
		}
	}

	// Expand sampled counts by the sampling rate. This applies to sFlow
	// (Type "SFLOW_5") and to sampled NetFlow v9 / IPFIX alike — goflow2
	// reports the per-flow SamplingRate from the options template for all of
	// them, so gate on the rate rather than the flow type. A rate of 0 or 1
	// means unsampled (or rate unknown), so leave the counts untouched.
	if flow.SamplingRate > 1 {
		e.IsSampled = true
		e.ExpandedBytes = flow.Bytes * flow.SamplingRate
		e.ExpandedPackets = flow.Packets * flow.SamplingRate
	}

	return e
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func durEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	setupLogger()

	// GeoIP is optional: set GEOIP_CITY_PATH and GEOIP_ASN_PATH to enable.
	var geo *GeoStore
	cityPath := os.Getenv("GEOIP_CITY_PATH")
	asnPath := os.Getenv("GEOIP_ASN_PATH")
	if cityPath != "" && asnPath != "" {
		var err error
		geo, err = NewGeoStore(cityPath, asnPath)
		if err != nil {
			slog.Error("geoip init failed, continuing without geo enrichment", "err", err)
		} else {
			slog.Info("geoip loaded")
			geo.StartRefresh(ctx, cityPath, asnPath)
		}
	} else {
		slog.Info("geo enrichment disabled", "reason", "GEOIP_CITY_PATH / GEOIP_ASN_PATH not set")
	}

	// Tenant mapping — optional, set TENANT_CONFIG_PATH to enable.
	var tenant *TenantStore
	if tenantPath := os.Getenv("TENANT_CONFIG_PATH"); tenantPath != "" {
		var err error
		tenant, err = NewTenantStore(tenantPath)
		if err != nil {
			slog.Error("tenant store init failed, continuing without tenant mapping", "err", err)
		} else {
			slog.Info("tenant config loaded")
			tenant.StartRefresh(ctx, tenantPath)
		}
	} else {
		slog.Info("tenant mapping disabled", "reason", "TENANT_CONFIG_PATH not set")
	}

	// Threat intelligence — optional, set THREAT_FEED_URL to override default.
	var threat *ThreatStore
	feedURL := os.Getenv("THREAT_FEED_URL")
	if feedURL == "" {
		feedURL = defaultThreatFeedURL
	}
	var err error
	threat, err = NewThreatStore(feedURL)
	if err != nil {
		slog.Error("threat store init failed, continuing without threat intel", "err", err)
	} else {
		threat.StartRefresh(ctx, feedURL)
	}

	// ClickHouse batch writer — optional, set CLICKHOUSE_ADDR to enable.
	var writer *BatchWriter
	chAddr := os.Getenv("CLICKHOUSE_ADDR")
	if chAddr == "" {
		chAddr = "localhost:9000"
	}
	writer, err = NewBatchWriter(
		chAddr,
		getenv("CLICKHOUSE_DB", "default"),
		getenv("CLICKHOUSE_USER", "default"),
		os.Getenv("CLICKHOUSE_PASSWORD"),
	)
	if err != nil {
		slog.Error("clickhouse init failed, continuing without ClickHouse", "err", err)
		writer = nil
	} else {
		writer.StartFlushTimer(ctx)
	}

	// Identity (who-side) enrichment — optional and FAIL CLOSED. Normal mode is
	// enabled only when IDENTITY_TOKEN_KEY_FILE plus at least one log dir are set;
	// if the token key can't be loaded the subsystem stays off entirely so no raw
	// username/MAC can ever be written. IDENTITY_UPSTREAM_ANONYMIZED=true switches
	// to pass-through mode: the logs already carry pseudonyms scrubbed upstream, so
	// values are stored VERBATIM with no key required (see UpstreamPseudonymTokenizer).
	// Flows keep flowing regardless (identity stays nil on any failure).
	//
	// STRICT-true: only the exact literal "true" enables pass-through — a non-empty
	// value must not silently turn off local tokenization.
	var identity *IdentityStore
	keyFile := os.Getenv("IDENTITY_TOKEN_KEY_FILE")
	npsDir := os.Getenv("IDENTITY_NPS_DIR")
	dhcpDir := os.Getenv("IDENTITY_DHCP_DIR")
	keaDir := os.Getenv("IDENTITY_KEA_DIR") // ISC Kea memfile lease dir (kea-leases4.csv)
	upstreamAnon := os.Getenv("IDENTITY_UPSTREAM_ANONYMIZED") == "true"

	mode, fatal := decideIdentityMode(upstreamAnon, keyFile != "", npsDir != "" || dhcpDir != "" || keaDir != "")
	switch {
	case fatal:
		// Both the pass-through flag and a token key are set. Refuse to pick a
		// winner: one stores verbatim, the other salts — either silent choice is a
		// privacy downgrade or a silently-broken mapping (matches the fail-loud TZ
		// precedent above).
		slog.Error("identity: IDENTITY_UPSTREAM_ANONYMIZED=true is incompatible with IDENTITY_TOKEN_KEY_FILE — one stores upstream pseudonyms verbatim, the other salts; unset exactly one")
		os.Exit(1)
	case mode == identityOff:
		slog.Info("identity enrichment disabled", "reason", "no log dir set, or normal mode without IDENTITY_TOKEN_KEY_FILE")
	default:
		var tok identityTokenizer
		switch mode {
		case identityPassthrough:
			tok = UpstreamPseudonymTokenizer{}
			// Loud, because this silently stores whatever the logs contain: if the
			// operator's "already anonymized" assertion is wrong, or the dirs point
			// at un-scrubbed logs, raw identifiers land in ClickHouse. Log resolved
			// ABSOLUTE paths so a wrong-dir misconfiguration is visible.
			slog.Warn("identity: UPSTREAM-ANONYMIZED pass-through — storing upstream pseudonyms VERBATIM with NO local tokenization; operator asserts inputs are already anonymized",
				"nps_dir", absPathForLog(npsDir), "dhcp_dir", absPathForLog(dhcpDir), "kea_dir", absPathForLog(keaDir))
		case identityHashed:
			t, terr := NewTokenizer(keyFile)
			if terr != nil {
				slog.Error("identity token key load failed, continuing without identity (fail closed)", "err", terr)
			} else {
				tok = t
			}
		}
		if tok != nil {
			// Resolve the log timezones before wiring the store. An invalid zone is
			// fatal: a silent UTC fallback would mis-join local-time forensic logs.
			npsLoc, nerr := logLocation("NPS_LOG_TZ")
			if nerr != nil {
				slog.Error("identity: invalid NPS log timezone", "err", nerr)
				os.Exit(1)
			}
			dhcpLoc, derr := logLocation("DHCP_LOG_TZ")
			if derr != nil {
				slog.Error("identity: invalid DHCP log timezone", "err", derr)
				os.Exit(1)
			}
			var conn driver.Conn
			if writer != nil {
				conn = writer.conn
			}
			identity = NewIdentityStore(tok, npsDir, dhcpDir, keaDir, npsLoc, dhcpLoc,
				durEnv("IDENTITY_MAX_LEASE", 24*time.Hour),
				durEnv("IDENTITY_MAX_SESSION", 24*time.Hour),
				conn)
			identity.StartPoller(ctx)
			slog.Info("identity enrichment enabled", "upstream_anonymized", mode == identityPassthrough,
				"nps_dir", npsDir, "dhcp_dir", dhcpDir, "kea_dir", keaDir, "clickhouse", conn != nil)
		}
	}

	// DNS (what-side) enrichment — optional, env-gated on DNS_LOG_DIR. Hostnames
	// are not personal data here, so there is no token key: the dir alone turns it
	// on. Fail open — a lookup miss leaves the flow untagged.
	var dns *DNSStore
	if dnsDir := os.Getenv("DNS_LOG_DIR"); dnsDir != "" {
		// Resolve the DNS log timezone; an invalid zone is fatal (see identity above).
		dnsLoc, lerr := logLocation("DNS_LOG_TZ")
		if lerr != nil {
			slog.Error("dns: invalid DNS log timezone", "err", lerr)
			os.Exit(1)
		}
		var conn driver.Conn
		if writer != nil {
			conn = writer.conn
		}
		// DNS_LOG_FORMAT selects the parser: bind (default) reads BIND9 resolver
		// logs; tcpdump reads `tcpdump -v` verbose text. An unknown value is fatal
		// (fail loud, like a bad TZ) rather than silently ingesting nothing.
		switch format := getenv("DNS_LOG_FORMAT", "bind"); format {
		case "bind":
			dns = NewDNSStore(dnsDir, dnsLoc, conn)
			slog.Info("dns enrichment enabled", "dns_dir", dnsDir, "format", format, "clickhouse", conn != nil)
		case "tcpdump":
			// tcpdump text prints no date; anchor to DNS_TCPDUMP_DATE (YYYY-MM-DD in
			// the DNS log location) or today. DNS_TCPDUMP_RESOLVER_IP, if set, drops
			// the upstream leg to the public forwarder.
			resolverIP := os.Getenv("DNS_TCPDUMP_RESOLVER_IP")
			baseDate := time.Now().In(dnsLoc)
			if ds := os.Getenv("DNS_TCPDUMP_DATE"); ds != "" {
				d, derr := time.ParseInLocation("2006-01-02", ds, dnsLoc)
				if derr != nil {
					slog.Error("dns: invalid DNS_TCPDUMP_DATE (want YYYY-MM-DD)", "value", ds, "err", derr)
					os.Exit(1)
				}
				baseDate = d
			} else {
				// tcpdump text carries no date, so a live tail anchors to today — but
				// replaying a historical capture then mis-dates every event. Warn loudly.
				slog.Warn("dns: DNS_TCPDUMP_DATE unset, defaulting capture date to today — set it when replaying a historical capture",
					"date", baseDate.Format("2006-01-02"))
			}
			dns = NewDNSStoreTcpdump(dnsDir, dnsLoc, baseDate, resolverIP, conn)
			slog.Info("dns enrichment enabled", "dns_dir", dnsDir, "format", format,
				"date", baseDate.Format("2006-01-02"), "resolver_ip", resolverIP, "clickhouse", conn != nil)
		case "dnstap":
			// dnstap-read -y YAML: no extra knobs — the timestamps carry an explicit
			// zone (so no date anchor) and the CLIENT/FORWARDER kind gate is the
			// upstream-leg filter (so no resolver IP).
			dns = NewDNSStoreDnstap(dnsDir, dnsLoc, conn)
			slog.Info("dns enrichment enabled", "dns_dir", dnsDir, "format", format, "clickhouse", conn != nil)
		default:
			slog.Error("dns: invalid DNS_LOG_FORMAT (want bind, tcpdump or dnstap)", "value", format)
			os.Exit(1)
		}
		dns.StartPoller(ctx)
	} else {
		slog.Info("dns enrichment disabled", "reason", "DNS_LOG_DIR not set")
	}

	dedup := NewDedupStore(
		intEnv("DEDUP_SIZE", 1_000_000),
		time.Duration(intEnv("DEDUP_TTL_SECONDS", 60))*time.Second,
	)
	// DEDUP_DISABLE=true bypasses dedup so every flow reaches enrich+write —
	// used for load testing the write path when a low-cardinality generator
	// would otherwise dedup ~90% of flows. Not for production.
	dedupEnabled := !boolEnv("DEDUP_DISABLE", false)
	if !dedupEnabled {
		slog.Warn("dedup bypassed (load-test mode)", "reason", "DEDUP_DISABLE set")
	}

	registerMetrics()
	StartMetricsServer(ctx, getenv("METRICS_ADDR", ":9090"))

	// Without ClickHouse there is nowhere to store enriched flows; emit them at
	// debug level only, so the no-CH dev fallback can't cost a write syscall per
	// flow at the default level. The level is fixed for the run, so gate once.
	logFlows := writer == nil && slog.Default().Enabled(ctx, slog.LevelDebug)
	if writer == nil && !logFlows {
		slog.Info("ClickHouse unavailable; per-flow records suppressed (set LOG_LEVEL=debug to print them)")
	}

	workerCount := intEnv("ENRICH_WORKERS", runtime.NumCPU())
	// The channel carries raw Kafka payloads, not parsed flows: JSON decode and
	// dedup are the heaviest serial costs, so they run inside the worker pool to
	// spread across all cores rather than bottlenecking the single reader.
	rawChan := make(chan []byte, workerCount*100)

	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			for raw := range rawChan {
				var flow FlowMessage
				if err := json.Unmarshal(raw, &flow); err != nil {
					slog.Error("unmarshal error", "err", err)
					continue
				}

				flowsReceived.Inc()

				// Best-effort dedup: the LRU is concurrency-safe, but the
				// Get-then-Add across workers has a small race window where two
				// simultaneous duplicates can both pass once. Acceptable for a
				// TTL-bounded dedup — we never drop a real flow, only fail to
				// catch a rare duplicate.
				if dedupEnabled && dedup.IsDuplicate(flow) {
					flowsDeduplicated.Inc()
					continue
				}

				e := enrich(flow, geo, tenant, threat, identity, dns)
				if e.IsThreatSrc {
					threatHits.WithLabelValues("src").Inc()
				}
				if e.IsThreatDst {
					threatHits.WithLabelValues("dst").Inc()
				}
				if writer != nil {
					writer.Add(toFlowRow(e))
				} else if logFlows {
					slog.Debug("flow",
						"src", e.SrcAddr, "src_port", e.SrcPort,
						"dst", e.DstAddr, "dst_port", e.DstPort,
						"proto", e.Proto, "bytes", e.Bytes,
						"src_cc", e.SrcGeo.CountryCode, "src_asn", e.SrcGeo.ASN,
						"dst_cc", e.DstGeo.CountryCode, "dst_asn", e.DstGeo.ASN,
						"tenant_id", e.TenantID,
						"threat", e.IsThreatSrc || e.IsThreatDst, "threat_label", e.ThreatLabel)
				}
				flowsWritten.Inc()
			}
		})
	}

	// Reader pool. A consumer group lets multiple readers split the topic's
	// partitions and fetch in parallel: with one partition a single reader does
	// all the work, but once raw-flows is partitioned, KAFKA_READERS readers in
	// the same group lift the single-reader fetch ceiling (under load the workers
	// were starved waiting on one reader). Each reader owns its connection; the
	// group coordinator assigns partitions and rebalances automatically.
	readerCount := intEnv("KAFKA_READERS", 1)
	var readerWg sync.WaitGroup
	for range readerCount {
		r := kafka.NewReader(kafka.ReaderConfig{
			Brokers: []string{getenv("REDPANDA_ADDR", "localhost:9092")},
			GroupID: "enricher-group",
			Topic:   "raw-flows",
			// Without CommitInterval, ReadMessage commits the offset synchronously
			// after every message — one broker round-trip per flow, which throttles
			// consumption to ~1/latency (~58 flows/s on a LAN). Commit asynchronously
			// on an interval instead. Delivery is read-committed, not write-committed:
			// offsets are committed ~1s after read, independent of the ClickHouse flush.
			// A transient ClickHouse failure does NOT lose flows — flush() re-queues
			// them into a bounded buffer (see batchwriter.go) — but a hard process
			// crash can lose flows already committed yet still buffered (watch the
			// enricher_clickhouse_buffer_rows gauge for that window). True
			// write-committed delivery would commit offsets only after batch.Send
			// succeeds; deferred as a documented limitation (see README Reliability).
			CommitInterval: time.Second,
			// Let the broker return a batch of records per fetch rather than dribbling
			// them out, so the reader goroutine isn't round-trip bound.
			MinBytes: 10e3, // 10 KB
			MaxBytes: 10e6, // 10 MB
		})
		readerWg.Go(func() {
			defer r.Close()
			for {
				msg, err := r.ReadMessage(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					slog.Error("kafka read error", "err", err)
					continue
				}
				// kafka-go allocates a fresh Value per message, so it is safe to
				// hand the slice to a worker goroutine without copying.
				rawChan <- msg.Value
			}
		})
	}

	slog.Info("connected to Redpanda, reading from raw-flows", "readers", readerCount, "workers", workerCount)

	readerWg.Wait()
	close(rawChan)
	wg.Wait()
	if writer != nil {
		// Drain rows added by workers after the flush timer stopped. Force past the
		// back-off and retry a few times so a failure in the last window doesn't
		// strand buffered rows; whatever remains after that is unavoidably lost.
		if lost := writer.FinalDrain(5); lost > 0 {
			slog.Error("shutdown: clickhouse unreachable, rows lost", "rows", lost)
		}
	}
	if identity != nil {
		// The poller stopped on ctx cancel with its last scan's events possibly
		// still buffered — drain them to the forensic event tables before exit.
		if lost := identity.FinalFlush(5); lost > 0 {
			slog.Error("shutdown: clickhouse unreachable, identity events lost", "events", lost)
		}
	}
	if dns != nil {
		if lost := dns.FinalFlush(5); lost > 0 {
			slog.Error("shutdown: clickhouse unreachable, dns events lost", "events", lost)
		}
	}
	slog.Info("shutting down")
}
