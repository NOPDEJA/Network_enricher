package main

import (
	"net"
	"os"
	"testing"
)

const sampleTenantYAML = `
tenants:
  - id: 1001
    name: "Acme Corp"
    subnets: ["10.0.1.0/24", "10.0.2.0/24"]
  - id: 1002
    name: "Beta LLC"
    subnets: ["10.0.3.0/24", "203.0.113.0/28"]
  - id: 1003
    name: "Overlap Test"
    subnets: ["10.0.1.0/16"]
`

func newTenantStoreFromYAML(t *testing.T, yml string) *TenantStore {
	t.Helper()
	f, err := os.CreateTemp("", "tenants-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yml)
	f.Close()

	s, err := NewTenantStore(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTenantStoreLookup(t *testing.T) {
	s := newTenantStoreFromYAML(t, sampleTenantYAML)

	tests := []struct {
		ip   string
		id   uint32
		name string
	}{
		{"10.0.1.5", 1001, "Acme Corp"},      // matches /24 and /16 — most specific wins
		{"10.0.2.200", 1001, "Acme Corp"},
		{"10.0.3.1", 1002, "Beta LLC"},
		{"203.0.113.10", 1002, "Beta LLC"},
		{"8.8.8.8", 0, ""},                   // no match
		{"192.168.1.1", 0, ""},               // no match
	}

	for _, tc := range tests {
		id, name := s.Lookup(net.ParseIP(tc.ip))
		if id != tc.id || name != tc.name {
			t.Errorf("Lookup(%s) = (%d, %q), want (%d, %q)", tc.ip, id, name, tc.id, tc.name)
		}
	}
}

// Both directions of a conversation must attribute: src match for outbound,
// dst match for the inbound/return half (which previously got tenant 0).
func TestEnrich_TenantBothDirections(t *testing.T) {
	s := newTenantStoreFromYAML(t, sampleTenantYAML)

	tests := []struct {
		name             string
		src, dst         string
		srcID, dstID     uint32
		srcName, dstName string
	}{
		{"outbound: tenant src, external dst", "10.0.1.5", "8.8.8.8", 1001, 0, "Acme Corp", ""},
		{"inbound: external src, tenant dst", "8.8.8.8", "10.0.1.5", 0, 1001, "", "Acme Corp"},
		{"tenant to tenant", "10.0.1.5", "10.0.3.1", 1001, 1002, "Acme Corp", "Beta LLC"},
		{"no tenant either side", "8.8.8.8", "1.1.1.1", 0, 0, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := enrich(FlowMessage{SrcAddr: tc.src, DstAddr: tc.dst}, nil, s, nil, nil)
			if e.TenantID != tc.srcID || e.TenantName != tc.srcName {
				t.Errorf("src tenant = (%d, %q), want (%d, %q)", e.TenantID, e.TenantName, tc.srcID, tc.srcName)
			}
			if e.DstTenantID != tc.dstID || e.DstTenantName != tc.dstName {
				t.Errorf("dst tenant = (%d, %q), want (%d, %q)", e.DstTenantID, e.DstTenantName, tc.dstID, tc.dstName)
			}
		})
	}
}

func TestTenantStoreLookupNil(t *testing.T) {
	s := newTenantStoreFromYAML(t, sampleTenantYAML)
	id, name := s.Lookup(nil)
	if id != 0 || name != "" {
		t.Errorf("Lookup(nil) = (%d, %q), want (0, \"\")", id, name)
	}
}
