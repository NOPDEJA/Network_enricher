package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

		fmt.Printf("%s:%d → %s:%d  proto=%s  etype=%s  bytes=%d  packets=%d  exporter=%s\n",
			flow.SrcAddr, flow.SrcPort, flow.DstAddr, flow.DstPort,
			flow.Proto, flow.Etype, flow.Bytes, flow.Packets, flow.SamplerAddress)
	}

	log.Println("shutting down")
}
