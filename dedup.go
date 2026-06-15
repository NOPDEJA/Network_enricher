package main

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// dedupShards is the number of independent LRU shards. Each shard has its own
// mutex, so concurrent IsDuplicate calls whose keys hash to different shards no
// longer serialize. Must be a power of two so the hash can be masked. 16 keeps
// lock contention low across the worker pool while staying cheap to allocate.
const dedupShards = 16

// dedupKey is the 7-tuple that identifies a unique flow.
// Using a comparable struct avoids string allocations in the hot path.
type dedupKey struct {
	SrcAddr  string
	DstAddr  string
	SrcPort  uint32
	DstPort  uint32
	Proto    string
	Exporter string
	Type     string
}

// DedupStore is a hash-sharded set of expirable LRUs. Sharding spreads the
// single-mutex pressure of one expirable.LRU across dedupShards locks, which is
// what restores scaling past ~4 cores once decode+dedup run in the worker pool.
//
// Tradeoff: capacity and eviction are per-shard, so a hot shard can evict while
// others have headroom. For dedup that only means a rare duplicate slips through
// (fail-open) — we never drop a real flow, so it is an acceptable trade for the
// lock-contention win.
type DedupStore struct {
	shards [dedupShards]*expirable.LRU[dedupKey, struct{}]
}

// NewDedupStore creates a cache that remembers up to size flow 7-tuples for ttl
// duration, split evenly across dedupShards independent LRUs.
// expirable.LRU is safe for concurrent use.
func NewDedupStore(size int, ttl time.Duration) *DedupStore {
	perShard := max(size/dedupShards, 1)
	d := &DedupStore{}
	for i := range d.shards {
		d.shards[i] = expirable.NewLRU[dedupKey, struct{}](perShard, nil, ttl)
	}
	return d
}

// IsDuplicate returns true if this flow's 7-tuple was already seen within the TTL
// window. On first sight it records the key; subsequent calls within TTL return
// true.
func (d *DedupStore) IsDuplicate(flow FlowMessage) bool {
	key := dedupKey{
		SrcAddr:  flow.SrcAddr,
		DstAddr:  flow.DstAddr,
		SrcPort:  flow.SrcPort,
		DstPort:  flow.DstPort,
		Proto:    flow.Proto,
		Exporter: flow.SamplerAddress,
		Type:     flow.Type,
	}
	shard := d.shards[shardIndex(key)&(dedupShards-1)]
	if _, ok := shard.Get(key); ok {
		return true
	}
	shard.Add(key, struct{}{})
	return false
}

// shardIndex hashes the 7-tuple with FNV-1a. It is written inline (no slice of
// fields, no hash.Hash allocation) to stay allocation-free on the hot path.
func shardIndex(k dedupKey) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	h = fnvString(h, k.SrcAddr)
	h = fnvString(h, k.DstAddr)
	h = fnvString(h, k.Proto)
	h = fnvString(h, k.Exporter)
	h = fnvString(h, k.Type)
	h ^= uint64(k.SrcPort)
	h *= prime64
	h ^= uint64(k.DstPort)
	h *= prime64
	return h
}

func fnvString(h uint64, s string) uint64 {
	const prime64 = 1099511628211
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}
