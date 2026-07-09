package main

import (
	"fmt"
	"testing"
	"time"

	// Match main.go's decoder so these benchmarks measure the production path.
	json "github.com/goccy/go-json"
)

// Load test for the in-process consume path: decode -> dedup -> enrich ->
// row-build. It excludes the two external hops (Kafka read, ClickHouse write)
// because those need the infra stack; everything here is pure CPU and runs with
// no network. The goal is to find which stage dominates the per-flow budget.
//
// Run just these:
//   go test -bench 'Unmarshal|EnrichReal|ConsumePath' -benchmem -benchtime=2s

// rawFlowJSON is a representative goflow2 JSON record (NetFlow v9, sampled).
// It carries the full field set goflow2 emits — including fields the enricher
// ignores — so the Unmarshal cost reflects production, where the decoder must
// still scan and skip unknown keys.
func rawFlowJSON(srcPort, dstPort int) []byte {
	return fmt.Appendf(nil, `{"type":"NETFLOW_V9","time_received_ns":1718000000000000000,`+
		`"sequence_num":12345,"sampling_rate":1000,"sampler_address":"10.0.0.1",`+
		`"time_flow_start_ns":1718000000000000000,"time_flow_end_ns":1718000000500000000,`+
		`"bytes":1500,"packets":3,"src_addr":"203.0.113.%d","dst_addr":"198.51.100.%d",`+
		`"etype":"IPv4","proto":"TCP","src_port":%d,"dst_port":%d,"in_if":12,"out_if":7,`+
		`"src_mac":"00:11:22:33:44:55","dst_mac":"66:77:88:99:aa:bb","src_vlan":100,`+
		`"dst_vlan":200,"ip_tos":0,"forwarding_status":64,"ip_ttl":58,"tcp_flags":24,`+
		`"src_as":13335,"dst_as":15169,"next_hop":"10.0.0.254","observation_domain_id":1}`,
		srcPort&0xFF, dstPort&0xFF, srcPort, dstPort)
}

// loadRealStores loads GeoIP + tenant from the standard local paths. Threat is
// left nil (its feed needs network). Skips the benchmark if files are absent.
func loadRealStores(tb testing.TB) (*GeoStore, *TenantStore) {
	tb.Helper()
	geo, err := NewGeoStore("geoip/GeoLite2-City.mmdb", "geoip/GeoLite2-ASN.mmdb")
	if err != nil {
		tb.Skipf("geoip not available, skipping real-store load test: %v", err)
	}
	tenant, err := NewTenantStore("tenants.yaml")
	if err != nil {
		tb.Skipf("tenants.yaml not available: %v", err)
	}
	return geo, tenant
}

// BenchmarkUnmarshal isolates the per-message JSON decode cost — runs once for
// every Kafka message in main.go's consume loop, but was previously unmeasured.
func BenchmarkUnmarshal(b *testing.B) {
	raw := rawFlowJSON(12345, 443)
	b.ReportAllocs()
	for b.Loop() {
		var f FlowMessage
		if err := json.Unmarshal(raw, &f); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnrichRealStores measures enrich() with GeoIP + tenant actually
// loaded — the realistic counterpart to BenchmarkEnrich (nil stores).
func BenchmarkEnrichRealStores(b *testing.B) {
	geo, tenant := loadRealStores(b)
	flow := sampleFlow(0)
	b.ReportAllocs()
	for b.Loop() {
		enrich(flow, geo, tenant, nil, nil, nil)
	}
}

// BenchmarkConsumePath measures the whole per-message path as main.go runs it:
// Unmarshal -> dedup -> enrich -> toFlowRow, with real GeoIP + tenant stores.
//
// A pool of distinct payloads cycled past an undersized dedup LRU keeps the
// dedup branch on its (expensive) miss path with bounded memory — matching
// steady-state traffic of mostly-distinct flows.
func BenchmarkConsumePath(b *testing.B) {
	geo, tenant := loadRealStores(b)

	const poolSize = 4096
	pool := make([][]byte, poolSize)
	for i := range pool {
		pool[i] = rawFlowJSON(i, (i*7)&0xFFFF)
	}
	dedup := NewDedupStore(poolSize/8, 60*time.Second) // < poolSize => sustained misses

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		var f FlowMessage
		if err := json.Unmarshal(pool[i%poolSize], &f); err != nil {
			b.Fatal(err)
		}
		if dedup.IsDuplicate(f) {
			continue
		}
		e := enrich(f, geo, tenant, nil, nil, nil)
		_ = toFlowRow(e)
	}
}

// BenchmarkConsumePathParallel runs the same per-message path across GOMAXPROCS
// goroutines, mirroring main.go's worker pool after Fix A (decode + dedup moved
// into the workers). Compare its ns/op against the serial BenchmarkConsumePath:
// the ratio is the speedup from spreading JSON decode across cores.
func BenchmarkConsumePathParallel(b *testing.B) {
	geo, tenant := loadRealStores(b)

	const poolSize = 4096
	pool := make([][]byte, poolSize)
	for i := range pool {
		pool[i] = rawFlowJSON(i, (i*7)&0xFFFF)
	}
	dedup := NewDedupStore(poolSize/8, 60*time.Second)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			var f FlowMessage
			if err := json.Unmarshal(pool[i%poolSize], &f); err != nil {
				b.Fatal(err)
			}
			if !dedup.IsDuplicate(f) {
				e := enrich(f, geo, tenant, nil, nil, nil)
				_ = toFlowRow(e)
			}
			i++
		}
	})
}
