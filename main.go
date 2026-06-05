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
	Type          string `json:"Type"`
	TimeFlowStart uint64 `json:"TimeFlowStart"`
	TimeFlowEnd   uint64 `json:"TimeFlowEnd"`
	SrcAddr       string `json:"SrcAddr"`
	DstAddr       string `json:"DstAddr"`
	SrcPort       uint32 `json:"SrcPort"`
	DstPort       uint32 `json:"DstPort"`
	Proto         uint32 `json:"Proto"`
	Bytes         uint64 `json:"Bytes"`
	Packets       uint64 `json:"Packets"`
	SamplingRate  uint64 `json:"SamplingRate"`
	ExporterAddr  string `json:"ExporterAddr"`
	NextHop       string `json:"NextHop"`
	SrcAS         uint32 `json:"SrcAS"`
	DstAS         uint32 `json:"DstAS"`
	TCPFlags      uint32 `json:"TCPFlags"`
	InIf          uint32 `json:"InIf"`
	OutIf         uint32 `json:"OutIf"`

	// Populated by NetFlow v9 and IPFIX, zero in v5
	Etype               uint32 `json:"Etype"`         // 0x0800=IPv4, 0x86DD=IPv6
	FlowDirection       uint32 `json:"FlowDirection"` // 0=ingress, 1=egress
	SrcVlan             uint32 `json:"SrcVlan"`
	DstVlan             uint32 `json:"DstVlan"`
	ForwardingStatus    uint32 `json:"ForwardingStatus"`
	IPTos               uint32 `json:"IPTos"`
	IPTTL               uint32 `json:"IPTTL"`
	ObservationDomainId uint32 `json:"ObservationDomainId"` // IPFIX only
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

		fmt.Printf("%s:%d → %s:%d  proto=%d  bytes=%d  packets=%d  exporter=%s  sampling=%d\n",
			flow.SrcAddr, flow.SrcPort, flow.DstAddr, flow.DstPort,
			flow.Proto, flow.Bytes, flow.Packets, flow.ExporterAddr, flow.SamplingRate)
	}

	log.Println("shutting down")
}
