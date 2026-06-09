package main

import (
	"net"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.0.1", true}, // link-local
		{"::1", true},
		{"fc00::1", true},

		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
		{"2606:4700:4700::1111", false},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		got := isPrivate(ip)
		if got != tc.private {
			t.Errorf("isPrivate(%s) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}

func TestGeoStoreLookupPrivate(t *testing.T) {
	// GeoStore.Lookup must return "private" label for RFC1918 addresses
	// without hitting the mmdb file — so we test this with a zero-value GeoStore.
	// (A nil cityDB/asnDB is never reached because isPrivate short-circuits.)
	g := &GeoStore{}

	privateIPs := []string{"10.0.0.1", "192.168.0.1", "172.20.0.5"}
	for _, raw := range privateIPs {
		ip := net.ParseIP(raw)
		got := g.Lookup(ip)
		if got.CountryCode != "private" {
			t.Errorf("Lookup(%s).CountryCode = %q, want \"private\"", raw, got.CountryCode)
		}
	}
}

func TestGeoStoreLookupNil(t *testing.T) {
	g := &GeoStore{}
	got := g.Lookup(nil)
	if got.CountryCode != "private" {
		t.Errorf("Lookup(nil).CountryCode = %q, want \"private\"", got.CountryCode)
	}
}
