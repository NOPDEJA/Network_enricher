package main

import (
	"testing"
	"time"
)

func baseFlow() FlowMessage {
	return FlowMessage{
		SrcAddr: "1.2.3.4", DstAddr: "5.6.7.8",
		SrcPort: 12345, DstPort: 443,
		Proto: "TCP", SamplerAddress: "10.0.0.1", Type: "NETFLOW_V5",
	}
}

func TestDedupStore_FirstSeenNotDuplicate(t *testing.T) {
	d := NewDedupStore(100, 60*time.Second)
	if d.IsDuplicate(baseFlow()) {
		t.Fatal("first sight should not be a duplicate")
	}
}

func TestDedupStore_SecondSeenIsDuplicate(t *testing.T) {
	d := NewDedupStore(100, 60*time.Second)
	flow := baseFlow()
	d.IsDuplicate(flow)
	if !d.IsDuplicate(flow) {
		t.Fatal("second sight within TTL should be a duplicate")
	}
}

func TestDedupStore_DifferentTupleNotDuplicate(t *testing.T) {
	d := NewDedupStore(100, 60*time.Second)
	f1 := baseFlow()
	f2 := baseFlow()
	f2.DstPort = 80
	d.IsDuplicate(f1)
	if d.IsDuplicate(f2) {
		t.Fatal("different 7-tuple should not be a duplicate")
	}
}

func TestDedupStore_ExpiresAfterTTL(t *testing.T) {
	d := NewDedupStore(100, 50*time.Millisecond)
	flow := baseFlow()
	d.IsDuplicate(flow)
	time.Sleep(100 * time.Millisecond)
	if d.IsDuplicate(flow) {
		t.Fatal("flow should not be a duplicate after TTL expiry")
	}
}

func TestDedupStore_DistinguishesExporter(t *testing.T) {
	d := NewDedupStore(100, 60*time.Second)
	f1 := baseFlow()
	f2 := baseFlow()
	f2.SamplerAddress = "10.0.0.2"
	d.IsDuplicate(f1)
	if d.IsDuplicate(f2) {
		t.Fatal("same 5-tuple from different exporter should not be a duplicate")
	}
}
