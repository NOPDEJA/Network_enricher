package main

import (
	"testing"
	"time"
)

// sampleFlow returns a realistic flow for benchmarks.
// baseFlow() from dedup_test.go is also available since both files share package main.
func sampleFlow(i int) FlowMessage {
	return FlowMessage{
		SrcAddr: "203.0.113.1", DstAddr: "198.51.100.2",
		SrcPort: uint32(i & 0xFFFF), DstPort: uint32(i>>16) & 0xFFFF,
		Proto: "TCP", SamplerAddress: "10.0.0.1", Type: "NETFLOW_V5",
		Bytes: 1500, Packets: 1, SamplingRate: 1,
	}
}

// BenchmarkEnrich measures the enrichment pipeline with all stores nil
// (baseline for the pure struct manipulation and sFlow expansion path).
func BenchmarkEnrich(b *testing.B) {
	flow := sampleFlow(0)
	for b.Loop() {
		enrich(flow, nil, nil, nil, nil, nil)
	}
}

// BenchmarkDedupMiss measures cache misses — each iteration is a unique 7-tuple.
func BenchmarkDedupMiss(b *testing.B) {
	d := NewDedupStore(b.N+1, 60*time.Second)
	flows := make([]FlowMessage, b.N)
	for i := range flows {
		flows[i] = sampleFlow(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.IsDuplicate(flows[i])
	}
}

// BenchmarkDedupHit measures cache hits — same 7-tuple every iteration.
func BenchmarkDedupHit(b *testing.B) {
	d := NewDedupStore(1_000_000, 60*time.Second)
	flow := sampleFlow(0)
	d.IsDuplicate(flow) // prime
	for b.Loop() {
		d.IsDuplicate(flow)
	}
}

// BenchmarkDedupMissParallel stresses dedup the way the worker pool does after
// Fix A: every core calls IsDuplicate concurrently. With one shared LRU mutex
// (Get+Add under a single lock) this saturates and ns/op stops improving with
// more cores; sharding by 7-tuple hash should let it scale. Compare ns/op
// before/after the sharding change at the same -cpu.
func BenchmarkDedupMissParallel(b *testing.B) {
	const pool = 1 << 16 // 65536 distinct 7-tuples
	flows := make([]FlowMessage, pool)
	for i := range flows {
		flows[i] = sampleFlow(i)
	}
	d := NewDedupStore(pool, 60*time.Second)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			d.IsDuplicate(flows[i&(pool-1)])
			i++
		}
	})
}
