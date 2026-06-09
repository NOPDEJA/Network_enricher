package main

import (
	"bufio"
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultThreatFeedURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

type ThreatStore struct {
	mu  sync.RWMutex
	ips map[string]string // ip → threat_label
}

func NewThreatStore(feedURL string) (*ThreatStore, error) {
	s := &ThreatStore{}
	if err := s.refresh(feedURL); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ThreatStore) refresh(feedURL string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(feedURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	ips := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// CSV format: ip_address,port,last_online,malware
		fields := strings.SplitN(line, ",", 5)
		if len(fields) < 1 {
			continue
		}
		ip := strings.TrimSpace(fields[0])
		label := "botnet_c2"
		if len(fields) >= 4 {
			label = strings.TrimSpace(fields[3])
		}
		ips[ip] = label
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.ips = ips
	s.mu.Unlock()
	log.Printf("threat feed loaded: %d IPs", len(ips))
	return nil
}

// Lookup returns whether the IP is a known threat and its label.
func (s *ThreatStore) Lookup(ip string) (isThreat bool, label string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	label, ok := s.ips[ip]
	return ok, label
}

// StartRefresh re-downloads the threat feed every hour in the background.
func (s *ThreatStore) StartRefresh(ctx context.Context, feedURL string) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.refresh(feedURL); err != nil {
					log.Printf("threat feed refresh failed: %v", err)
				}
			}
		}
	}()
}
