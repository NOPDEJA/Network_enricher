package main

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
	"gopkg.in/yaml.v3"
)

type tenantEntry struct {
	network net.IPNet
	id      uint32
	name    string
}

func (e *tenantEntry) Network() net.IPNet { return e.network }

type TenantStore struct {
	mu     sync.RWMutex
	ranger cidranger.Ranger
}

type tenantConfig struct {
	Tenants []struct {
		ID      uint32   `yaml:"id"`
		Name    string   `yaml:"name"`
		Subnets []string `yaml:"subnets"`
	} `yaml:"tenants"`
}

func NewTenantStore(path string) (*TenantStore, error) {
	s := &TenantStore{}
	if err := s.load(path); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *TenantStore) load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg tenantConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	r := cidranger.NewPCTrieRanger()
	for _, t := range cfg.Tenants {
		for _, subnet := range t.Subnets {
			_, network, err := net.ParseCIDR(subnet)
			if err != nil {
				log.Printf("tenant %d: skipping bad subnet %q: %v", t.ID, subnet, err)
				continue
			}
			r.Insert(&tenantEntry{network: *network, id: t.ID, name: t.Name})
		}
	}

	s.mu.Lock()
	s.ranger = r
	s.mu.Unlock()
	return nil
}

// Lookup matches ip against the tenant CIDR table and returns the most-specific match.
// Returns id=0 and empty name if no subnet matches.
func (s *TenantStore) Lookup(ip net.IP) (id uint32, name string) {
	if ip == nil {
		return 0, ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return 0, ""
	}

	// pick the longest-prefix (most specific) match
	best := entries[0].(*tenantEntry)
	for _, e := range entries[1:] {
		te := e.(*tenantEntry)
		bl, _ := best.network.Mask.Size()
		tl, _ := te.network.Mask.Size()
		if tl > bl {
			best = te
		}
	}
	return best.id, best.name
}

// StartRefresh reloads the tenant config file every 5 minutes in the background.
func (s *TenantStore) StartRefresh(ctx context.Context, path string) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.load(path); err != nil {
					log.Printf("tenant config reload failed: %v", err)
				} else {
					log.Println("tenant config reloaded")
				}
			}
		}
	}()
}
