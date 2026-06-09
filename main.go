package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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
// Weeks 4–6 will add tenant_id, threat flags, dedup status, etc.
type EnrichedFlow struct {
	FlowMessage
	SrcGeo GeoData
	DstGeo GeoData
}

func enrich(flow FlowMessage, geo *GeoStore) EnrichedFlow {
	e := EnrichedFlow{FlowMessage: flow}
	if geo != nil {
		e.SrcGeo = geo.Lookup(net.ParseIP(flow.SrcAddr))
		e.DstGeo = geo.Lookup(net.ParseIP(flow.DstAddr))
	}
	return e
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

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"localhost:9092"},
		GroupID: "enricher-group",
		Topic:   "raw-flows",
	})
	defer r.Close()

	log.Println("connected to Redpanda, reading from raw-flows...")

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

		e := enrich(flow, geo)

		fmt.Printf("%s:%d → %s:%d  proto=%s  bytes=%d  src_country=%s  dst_country=%s  src_asn=%d  dst_asn=%d\n",
			e.SrcAddr, e.SrcPort, e.DstAddr, e.DstPort,
			e.Proto, e.Bytes,
			e.SrcGeo.CountryCode, e.DstGeo.CountryCode,
			e.SrcGeo.ASN, e.DstGeo.ASN)
	}

	log.Println("shutting down")
}
