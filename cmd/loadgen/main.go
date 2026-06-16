// Command loadgen floods the raw-flows Kafka topic with high-cardinality
// synthetic NetFlow JSON, so the enricher can be load-tested without depending
// on nflow-generator (which emits a tiny repeating set and starves the
// pipeline). Each record has a distinct 7-tuple so dedup does not mask it.
//
//	go run ./cmd/loadgen -addr <ip>:9092 -count 5000000
//
// Then start the enricher and watch enricher_flows_received_total rate +
// a CPU profile to find the real consume->enrich->write ceiling.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// flowJSON builds one goflow2-style NetFlow v9 record with a unique 7-tuple
// derived from i (16M+ distinct src addresses, varied ports).
func flowJSON(i int) []byte {
	now := time.Now().UnixNano()
	return fmt.Appendf(nil,
		`{"type":"NETFLOW_V9","time_received_ns":%d,"sequence_num":%d,`+
			`"sampling_rate":1000,"sampler_address":"10.0.0.1",`+
			`"time_flow_start_ns":%d,"time_flow_end_ns":%d,"bytes":%d,"packets":%d,`+
			`"src_addr":"10.%d.%d.%d","dst_addr":"203.0.%d.%d","etype":"IPv4",`+
			`"proto":"TCP","src_port":%d,"dst_port":%d,"in_if":12,"out_if":7,`+
			`"src_as":13335,"dst_as":15169,"tcp_flags":24,"ip_ttl":58}`,
		now, i, now, now+500000, 1500, 3,
		(i>>16)&0xFF, (i>>8)&0xFF, i&0xFF, // src 10.x.y.z
		(i>>8)&0xFF, i&0xFF, // dst 203.0.x.y
		1024+(i&0x7FFF), 443, // src/dst ports
	)
}

func main() {
	count := flag.Int("count", 1_000_000, "number of flow records to publish")
	addr := flag.String("addr", getenv("REDPANDA_ADDR", "localhost:9092"), "kafka broker address")
	topic := flag.String("topic", "raw-flows", "kafka topic")
	batch := flag.Int("batch", 10_000, "messages per WriteMessages call")
	flag.Parse()

	w := &kafka.Writer{
		Addr:         kafka.TCP(*addr),
		Topic:        *topic,
		Balancer:     &kafka.LeastBytes{},
		BatchSize:    *batch,
		BatchTimeout: 50 * time.Millisecond,
		RequiredAcks: kafka.RequireOne,
		Async:        false,
	}
	defer w.Close()

	log.Printf("publishing %d records to %q on %s (batch=%d)...", *count, *topic, *addr, *batch)
	start := time.Now()

	msgs := make([]kafka.Message, 0, *batch)
	flush := func() error {
		if len(msgs) == 0 {
			return nil
		}
		if err := w.WriteMessages(context.Background(), msgs...); err != nil {
			return err
		}
		msgs = msgs[:0]
		return nil
	}

	for i := 0; i < *count; i++ {
		msgs = append(msgs, kafka.Message{Value: flowJSON(i)})
		if len(msgs) == *batch {
			if err := flush(); err != nil {
				log.Fatalf("write error at %d: %v", i, err)
			}
			if (i+1)%500_000 == 0 {
				rate := float64(i+1) / time.Since(start).Seconds()
				log.Printf("  %d published (%.0f msg/s)", i+1, rate)
			}
		}
	}
	if err := flush(); err != nil {
		log.Fatalf("final flush error: %v", err)
	}

	elapsed := time.Since(start)
	log.Printf("done: %d records in %s (%.0f msg/s)", *count, elapsed.Round(time.Millisecond),
		float64(*count)/elapsed.Seconds())
}
