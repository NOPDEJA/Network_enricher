package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/netsampler/goflow2/v2/pb"
	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
)

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

		var flow pb.FlowMessage
		if err := proto.Unmarshal(msg.Value, &flow); err != nil {
			log.Printf("unmarshal error: %v", err)
			continue
		}

		src := net.IP(flow.SrcAddr).String()
		dst := net.IP(flow.DstAddr).String()
		fmt.Printf("%s → %s  proto=%d  bytes=%d  packets=%d\n",
			src, dst, flow.Proto, flow.Bytes, flow.Packets)
	}

	log.Println("shutting down")
}
