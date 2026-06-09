package main

import "testing"

func TestThreatStoreLookup(t *testing.T) {
	s := &ThreatStore{ips: map[string]string{
		"185.220.101.1": "Dridex",
		"91.219.28.77":  "Emotet",
	}}

	tests := []struct {
		ip       string
		isThreat bool
		label    string
	}{
		{"185.220.101.1", true, "Dridex"},
		{"91.219.28.77", true, "Emotet"},
		{"8.8.8.8", false, ""},
		{"10.0.0.1", false, ""},
	}

	for _, tc := range tests {
		got, label := s.Lookup(tc.ip)
		if got != tc.isThreat || label != tc.label {
			t.Errorf("Lookup(%s) = (%v, %q), want (%v, %q)", tc.ip, got, label, tc.isThreat, tc.label)
		}
	}
}
