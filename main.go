package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

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
	Etype               string `json:"etype"`                 // "IPv4" or "IPv6"
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
	TenantID        uint32
	TenantName      string
	IsThreatSrc     bool
	IsThreatDst     bool
	ThreatLabel     string
	IsSampled       bool
	ExpandedBytes   uint64
	ExpandedPackets uint64
}

func enrich(flow FlowMessage, geo *GeoStore, tenant *TenantStore, threat *ThreatStore) EnrichedFlow {
	e := EnrichedFlow{FlowMessage: flow}

	// Parse once and share across enrichers — ParseIP allocates, so skip it
	// entirely when no enricher needs it.
	if geo != nil || tenant != nil {
		srcIP := net.ParseIP(flow.SrcAddr)

		if geo != nil {
			e.SrcGeo = geo.Lookup(srcIP)
			e.DstGeo = geo.Lookup(net.ParseIP(flow.DstAddr))
		}

		if tenant != nil {
			e.TenantID, e.TenantName = tenant.Lookup(srcIP)
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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// GeoIP is optional: set GEOIP_CITY_PATH and GEOIP_ASN_PATH to enable.
	var geo *GeoStore
	cityPath := os.Getenv("GEOIP_CITY_PATH")
	asnPath := os.Getenv("GEOIP_ASN_PATH")
	if cityPath != "" && asnPath != "" {
		var err error
		geo, err = NewGeoStore(cityPath, asnPath)
		if err != nil {
			log.Printf("geoip init failed, continuing without geo enrichment: %v", err)
		} else {
			log.Println("geoip loaded")
			geo.StartRefresh(ctx, cityPath, asnPath)
		}
	} else {
		log.Println("GEOIP_CITY_PATH / GEOIP_ASN_PATH not set — skipping geo enrichment")
	}

	// Tenant mapping — optional, set TENANT_CONFIG_PATH to enable.
	var tenant *TenantStore
	if tenantPath := os.Getenv("TENANT_CONFIG_PATH"); tenantPath != "" {
		var err error
		tenant, err = NewTenantStore(tenantPath)
		if err != nil {
			log.Printf("tenant store init failed, continuing without tenant mapping: %v", err)
		} else {
			log.Println("tenant config loaded")
			tenant.StartRefresh(ctx, tenantPath)
		}
	} else {
		log.Println("TENANT_CONFIG_PATH not set — skipping tenant mapping")
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
		log.Printf("threat store init failed, continuing without threat intel: %v", err)
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
		log.Printf("clickhouse init failed, continuing without ClickHouse: %v", err)
		writer = nil
	} else {
		writer.StartFlushTimer(ctx)
	}

	dedup := NewDedupStore(
		intEnv("DEDUP_SIZE", 1_000_000),
		time.Duration(intEnv("DEDUP_TTL_SECONDS", 60))*time.Second,
	)

	registerMetrics()
	StartMetricsServer(ctx, getenv("METRICS_ADDR", ":9090"))

	workerCount := intEnv("ENRICH_WORKERS", runtime.NumCPU())
	flowChan := make(chan FlowMessage, workerCount*100)

	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			for flow := range flowChan {
				e := enrich(flow, geo, tenant, threat)
				if e.IsThreatSrc {
					threatHits.WithLabelValues("src").Inc()
				}
				if e.IsThreatDst {
					threatHits.WithLabelValues("dst").Inc()
				}
				if writer != nil {
					writer.Add(toFlowRow(e))
				} else {
					threatFlag := ""
					if e.IsThreatSrc || e.IsThreatDst {
						threatFlag = fmt.Sprintf("  THREAT=%s", e.ThreatLabel)
					}
					fmt.Printf("%s:%d → %s:%d  proto=%s  bytes=%d  src=%s/%d  dst=%s/%d  tenant=%d%s\n",
						e.SrcAddr, e.SrcPort, e.DstAddr, e.DstPort,
						e.Proto, e.Bytes,
						e.SrcGeo.CountryCode, e.SrcGeo.ASN,
						e.DstGeo.CountryCode, e.DstGeo.ASN,
						e.TenantID, threatFlag)
				}
				flowsWritten.Inc()
			}
		})
	}

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{getenv("REDPANDA_ADDR", "localhost:9092")},
		GroupID: "enricher-group",
		Topic:   "raw-flows",
	})
	defer r.Close()

	log.Printf("connected to Redpanda, reading from raw-flows (workers=%d)...", workerCount)

	for {
		msg, err := r.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("read error: %v", err)
			continue
		}

		var flow FlowMessage
		if err := json.Unmarshal(msg.Value, &flow); err != nil {
			log.Printf("unmarshal error: %v", err)
			continue
		}

		flowsReceived.Inc()

		if dedup.IsDuplicate(flow) {
			flowsDeduplicated.Inc()
			continue
		}

		flowChan <- flow
	}

	close(flowChan)
	wg.Wait()
	if writer != nil {
		writer.flush() // drain rows added by workers after the flush timer stopped
	}
	log.Println("shutting down")
}
