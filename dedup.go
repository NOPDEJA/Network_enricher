package main

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

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

type DedupStore struct {
	cache *expirable.LRU[dedupKey, struct{}]
}

// NewDedupStore creates a cache that remembers up to size flow 7-tuples for ttl duration.
// expirable.LRU is safe for concurrent use.
func NewDedupStore(size int, ttl time.Duration) *DedupStore {
	return &DedupStore{
		cache: expirable.NewLRU[dedupKey, struct{}](size, nil, ttl),
	}
}

// IsDuplicate returns true if this flow's 7-tuple was already seen within the TTL window.
// On first sight it records the key; subsequent calls within TTL return true.
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
	if _, ok := d.cache.Get(key); ok {
		return true
	}
	d.cache.Add(key, struct{}{})
	return false
}
