package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type GeoData struct {
	CountryCode string
	City        string
	Lat         float64
	Lon         float64
	ASN         uint32
	OrgName     string
}

type GeoStore struct {
	mu     sync.RWMutex
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
}

// package-level private ranges — no init() needed
var privateRanges = mustParseCIDRs([]string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, len(cidrs))
	for i, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets[i] = n
	}
	return nets
}

func isPrivate(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func NewGeoStore(cityPath, asnPath string) (*GeoStore, error) {
	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, err
	}
	asnDB, err := geoip2.Open(asnPath)
	if err != nil {
		cityDB.Close()
		return nil, err
	}
	return &GeoStore{cityDB: cityDB, asnDB: asnDB}, nil
}

func (g *GeoStore) Lookup(ip net.IP) GeoData {
	if ip == nil || isPrivate(ip) {
		return GeoData{CountryCode: "private"}
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	var data GeoData

	if city, err := g.cityDB.City(ip); err == nil {
		data.CountryCode = city.Country.IsoCode
		if data.CountryCode == "" {
			data.CountryCode = "unknown"
		}
		if len(city.City.Names) > 0 {
			data.City = city.City.Names["en"]
		}
		data.Lat = city.Location.Latitude
		data.Lon = city.Location.Longitude
	}

	if asn, err := g.asnDB.ASN(ip); err == nil {
		data.ASN = uint32(asn.AutonomousSystemNumber)
		data.OrgName = asn.AutonomousSystemOrganization
	}

	return data
}

// Refresh swaps in new database files atomically without downtime.
func (g *GeoStore) Refresh(cityPath, asnPath string) error {
	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return err
	}
	asnDB, err := geoip2.Open(asnPath)
	if err != nil {
		cityDB.Close()
		return err
	}

	g.mu.Lock()
	old := g.cityDB
	oldASN := g.asnDB
	g.cityDB = cityDB
	g.asnDB = asnDB
	g.mu.Unlock()

	old.Close()
	oldASN.Close()
	return nil
}

// StartRefresh runs a background goroutine that reloads the databases every 24 hours.
func (g *GeoStore) StartRefresh(ctx context.Context, cityPath, asnPath string) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := g.Refresh(cityPath, asnPath); err != nil {
					log.Printf("geoip refresh failed: %v", err)
				} else {
					log.Println("geoip databases refreshed")
				}
			}
		}
	}()
}
