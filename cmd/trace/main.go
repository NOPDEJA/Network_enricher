// Command trace is a read-only forensic attribution lookup over the enriched
// flows already stored in ClickHouse. It answers: "which internal host reached a
// given external destination (e.g. Facebook) around time T?"
//
//	# By friendly service name, ±15m around a time:
//	go run ./cmd/trace -service facebook -around "2026-06-16 14:30:00" -window 15m
//
//	# By ASN, explicit window, narrowed to one suspect source:
//	go run ./cmd/trace -dst-asn 15169 -from "2026-06-16 00:00:00" -to "2026-06-16 23:59:59" -src-ip 10.3.7.21
//
//	# By destination org substring (case-insensitive), as JSON lines:
//	go run ./cmd/trace -dst-org cloudflare -around 2026-06-16 -json
//
// Connects with the same CLICKHOUSE_* env vars as the enricher
// (CLICKHOUSE_ADDR, CLICKHOUSE_DB, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD).
//
// Scope: trace answers *which internal IP*, not *who*. Mapping an IP to a person
// is a separate, confidential join against DHCP/RADIUS records and is out of
// scope here.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// knownServices maps a friendly name to the destination ASN(s) that serve it, so
// `-service facebook` works without memorizing AS numbers. Confirm these match
// your deployment's GeoIP/ASN DB before relying on them (32934 is Meta's primary
// ASN; 15169 is Google; 13335 is Cloudflare).
var knownServices = map[string][]uint32{
	"facebook":   {32934},
	"meta":       {32934},
	"instagram":  {32934},
	"whatsapp":   {32934},
	"google":     {15169},
	"youtube":    {15169},
	"cloudflare": {13335},
}

// filter holds the resolved, validated query parameters. Exactly one destination
// field is set; the time window is always set.
type filter struct {
	from, to time.Time

	// destination predicate — exactly one of these is active
	dstASNs []uint32 // dst_asn IN (...)
	dstOrg  string   // substring match on dst_org
	dstIP   string   // exact dst_ip

	srcIP string // optional narrowing
	limit int
}

// resolveService maps a friendly service name to its ASN(s).
func resolveService(name string) ([]uint32, error) {
	asns, ok := knownServices[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		known := make([]string, 0, len(knownServices))
		for k := range knownServices {
			known = append(known, k)
		}
		return nil, fmt.Errorf("unknown service %q (known: %s)", name, strings.Join(known, ", "))
	}
	return asns, nil
}

var timeLayouts = []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02"}

// parseTime accepts a few human-friendly layouts, in local time.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range timeLayouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q (try \"2006-01-02 15:04:05\", RFC3339, or 2006-01-02)", s)
}

// buildQuery turns a filter into a parameterized SQL string plus its arg slice.
// Every user-supplied value is bound as a ? arg — never concatenated into the
// SQL — so -dst-org / -src-ip cannot inject. The timestamp BETWEEN bound drives
// partition pruning (flows is PARTITION BY toYYYYMMDD(timestamp)).
func buildQuery(f filter) (string, []any, error) {
	var sb strings.Builder
	args := make([]any, 0, 6)

	sb.WriteString(`SELECT timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes,
       dst_asn, dst_org, exporter_ip, tenant_name
FROM flows
WHERE timestamp BETWEEN ? AND ?`)
	args = append(args, f.from, f.to)

	switch {
	case len(f.dstASNs) > 0:
		sb.WriteString("\n  AND dst_asn IN (?)")
		args = append(args, f.dstASNs)
	case f.dstOrg != "":
		sb.WriteString("\n  AND positionCaseInsensitive(dst_org, ?) > 0")
		args = append(args, f.dstOrg)
	case f.dstIP != "":
		sb.WriteString("\n  AND dst_ip = ?")
		args = append(args, f.dstIP)
	default:
		return "", nil, fmt.Errorf("no destination predicate set")
	}

	if f.srcIP != "" {
		sb.WriteString("\n  AND src_ip = ?")
		args = append(args, f.srcIP)
	}

	sb.WriteString("\nORDER BY timestamp\nLIMIT ?")
	args = append(args, f.limit)

	return sb.String(), args, nil
}

// row mirrors the SELECT column order in buildQuery.
type row struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	SrcPort    uint32    `json:"src_port"`
	DstIP      string    `json:"dst_ip"`
	DstPort    uint32    `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	Bytes      uint64    `json:"bytes"`
	DstASN     uint32    `json:"dst_asn"`
	DstOrg     string    `json:"dst_org"`
	ExporterIP string    `json:"exporter_ip"`
	TenantName string    `json:"tenant_name"`
}

func main() {
	var (
		service = flag.String("service", "", "friendly destination service name (facebook, google, cloudflare, ...)")
		dstASN  = flag.Uint("dst-asn", 0, "destination ASN to match")
		dstOrg  = flag.String("dst-org", "", "destination org substring (case-insensitive)")
		dstIP   = flag.String("dst-ip", "", "exact destination IP")

		around = flag.String("around", "", "center of the time window")
		window = flag.Duration("window", 10*time.Minute, "half-width is window/2 each side of -around")
		from   = flag.String("from", "", "window start (alternative to -around/-window)")
		to     = flag.String("to", "", "window end (alternative to -around/-window)")

		srcIP  = flag.String("src-ip", "", "narrow to a single source (suspect) IP")
		limit  = flag.Int("limit", 1000, "max rows to return")
		asJSON = flag.Bool("json", false, "emit JSON lines instead of a table")
	)
	flag.Parse()

	f, err := buildFilter(*service, *dstASN, *dstOrg, *dstIP, *around, *window, *from, *to, *srcIP, *limit)
	if err != nil {
		log.Fatalf("trace: %v", err)
	}

	query, args, err := buildQuery(f)
	if err != nil {
		log.Fatalf("trace: %v", err)
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{getenv("CLICKHOUSE_ADDR", "localhost:9000")},
		Auth: clickhouse.Auth{
			Database: getenv("CLICKHOUSE_DB", "default"),
			Username: getenv("CLICKHOUSE_USER", "default"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("trace: clickhouse open: %v", err)
	}
	defer conn.Close()

	ctx := context.Background()
	if err := conn.Ping(ctx); err != nil {
		log.Fatalf("trace: clickhouse ping: %v", err)
	}

	rows, err := conn.Query(ctx, query, args...)
	if err != nil {
		log.Fatalf("trace: query: %v", err)
	}
	defer rows.Close()

	if err := render(rows, *asJSON); err != nil {
		log.Fatalf("trace: %v", err)
	}
}

// buildFilter validates flags and resolves them into a filter. Exactly one
// destination flag and exactly one time-window form must be supplied.
func buildFilter(service string, dstASN uint, dstOrg, dstIP, around string, window time.Duration, from, to, srcIP string, limit int) (filter, error) {
	var f filter

	// Destination — exactly one.
	n := 0
	if service != "" {
		asns, err := resolveService(service)
		if err != nil {
			return f, err
		}
		f.dstASNs = asns
		n++
	}
	if dstASN != 0 {
		f.dstASNs = []uint32{uint32(dstASN)}
		n++
	}
	if dstOrg != "" {
		f.dstOrg = dstOrg
		n++
	}
	if dstIP != "" {
		if net.ParseIP(dstIP) == nil {
			return f, fmt.Errorf("invalid -dst-ip %q", dstIP)
		}
		f.dstIP = dstIP
		n++
	}
	if n != 1 {
		return f, fmt.Errorf("specify exactly one destination: -service, -dst-asn, -dst-org, or -dst-ip")
	}

	// Time window — either -around/-window or -from/-to.
	switch {
	case around != "":
		if from != "" || to != "" {
			return f, fmt.Errorf("use either -around/-window or -from/-to, not both")
		}
		center, err := parseTime(around)
		if err != nil {
			return f, err
		}
		half := window / 2
		f.from = center.Add(-half)
		f.to = center.Add(half)
	case from != "" && to != "":
		var err error
		if f.from, err = parseTime(from); err != nil {
			return f, err
		}
		if f.to, err = parseTime(to); err != nil {
			return f, err
		}
		if f.to.Before(f.from) {
			return f, fmt.Errorf("-to is before -from")
		}
	default:
		return f, fmt.Errorf("specify a time window: -around T (with optional -window), or both -from and -to")
	}

	if srcIP != "" {
		if net.ParseIP(srcIP) == nil {
			return f, fmt.Errorf("invalid -src-ip %q", srcIP)
		}
		f.srcIP = srcIP
	}

	if limit <= 0 {
		return f, fmt.Errorf("-limit must be positive")
	}
	f.limit = limit

	return f, nil
}

// chRows is the minimal subset of driver.Rows that render needs, so it can be
// faked in a test without a ClickHouse connection if ever desired.
type chRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func render(rows chRows, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		for rows.Next() {
			var r row
			if err := scanRow(rows, &r); err != nil {
				return err
			}
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return rows.Err()
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TIMESTAMP\tSRC_IP\tSPORT\tDST_IP\tDPORT\tPROTO\tBYTES\tDST_ASN\tDST_ORG\tEXPORTER\tTENANT")
	count := 0
	for rows.Next() {
		var r row
		if err := scanRow(rows, &r); err != nil {
			return err
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%s\t%d\t%d\t%s\t%s\t%s\n",
			r.Timestamp.Format("2006-01-02 15:04:05"), r.SrcIP, r.SrcPort,
			r.DstIP, r.DstPort, r.Protocol, r.Bytes, r.DstASN, r.DstOrg,
			r.ExporterIP, r.TenantName)
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d flow(s)\n", count)
	return nil
}

func scanRow(rows chRows, r *row) error {
	return rows.Scan(&r.Timestamp, &r.SrcIP, &r.SrcPort, &r.DstIP, &r.DstPort,
		&r.Protocol, &r.Bytes, &r.DstASN, &r.DstOrg, &r.ExporterIP, &r.TenantName)
}
