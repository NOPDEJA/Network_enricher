package main

import "testing"

func TestEnrich_SamplingExpansion(t *testing.T) {
	tests := []struct {
		name         string
		flowType     string
		samplingRate uint64
		bytes        uint64
		packets      uint64
		wantSampled  bool
		wantBytes    uint64
		wantPackets  uint64
	}{
		{
			name:     "sflow expands",
			flowType: "SFLOW_5", samplingRate: 1000, bytes: 100, packets: 2,
			wantSampled: true, wantBytes: 100_000, wantPackets: 2_000,
		},
		{
			name:     "sampled netflow v9 expands",
			flowType: "NETFLOW_V9", samplingRate: 4096, bytes: 100, packets: 2,
			wantSampled: true, wantBytes: 409_600, wantPackets: 8_192,
		},
		{
			name:     "sampled ipfix expands",
			flowType: "IPFIX", samplingRate: 256, bytes: 50, packets: 1,
			wantSampled: true, wantBytes: 12_800, wantPackets: 256,
		},
		{
			name:     "rate 1 is unsampled",
			flowType: "NETFLOW_V9", samplingRate: 1, bytes: 100, packets: 2,
			wantSampled: false, wantBytes: 0, wantPackets: 0,
		},
		{
			name:     "rate 0 (unknown) is unsampled",
			flowType: "NETFLOW_V5", samplingRate: 0, bytes: 100, packets: 2,
			wantSampled: false, wantBytes: 0, wantPackets: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := FlowMessage{
				Type:         tt.flowType,
				SamplingRate: tt.samplingRate,
				Bytes:        tt.bytes,
				Packets:      tt.packets,
			}
			// No enrichers — isolate the sampling logic.
			e := enrich(flow, nil, nil, nil)
			if e.IsSampled != tt.wantSampled {
				t.Errorf("IsSampled = %v, want %v", e.IsSampled, tt.wantSampled)
			}
			if e.ExpandedBytes != tt.wantBytes {
				t.Errorf("ExpandedBytes = %d, want %d", e.ExpandedBytes, tt.wantBytes)
			}
			if e.ExpandedPackets != tt.wantPackets {
				t.Errorf("ExpandedPackets = %d, want %d", e.ExpandedPackets, tt.wantPackets)
			}
		})
	}
}
