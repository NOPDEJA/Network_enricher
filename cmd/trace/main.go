// Command trace is a read-only forensic attribution lookup over the enriched
// flows and identity/DNS event tables already stored in ClickHouse. It has two
// modes.
//
// Flows mode (default) answers "which internal host reached a given external
// destination (e.g. Facebook) around time T?":
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
// Who mode (-who) answers the "who" half for the legal scenario "given a time
// and an external service (domain or answered IP), which internal device/user
// was it?". It chains dns_events (who resolved the name/IP) -> DHCP leases
// (client IP -> device) -> RADIUS sessions (device -> user), evaluating each
// binding as-of the resolution time:
//
//	# By resolved domain (exact or suffix match), ±10m around a time:
//	go run ./cmd/trace -who -qname facebook.com -around "2026-07-13 15:45" -window 20m
//
//	# By answered IP:
//	go run ./cmd/trace -who -dst-ip 157.240.1.35 -from "2026-07-13 00:00:00" -to "2026-07-13 23:59:59"
//
// Who mode is pseudonymous by construction: it emits only mac_token / user_token
// (HMAC pseudonyms), never a raw MAC or username. Reverse-lookup of a token to a
// real identity is a separate, key-gated step and is out of scope here.
//
// Connects with the same CLICKHOUSE_* env vars as the enricher
// (CLICKHOUSE_ADDR, CLICKHOUSE_DB, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD). Who
// mode's lease/session trust horizons come from IDENTITY_MAX_LEASE /
// IDENTITY_MAX_SESSION (Go duration strings, default 24h) — the same knobs the
// enricher uses.
//
// All time inputs (-around/-from/-to) and displayed timestamps are UTC, matching
// how ClickHouse stores timestamps. A narrow window in the wrong zone would
// silently miss records, so this tool is UTC-only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
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
	dstASNs []uint32 // dst_asn IN (...)        (flows mode)
	dstOrg  string   // substring match on dst_org (flows mode)
	dstIP   string   // exact dst_ip (flows mode) / answer_ip (who mode)

	srcIP string // optional narrowing (flows mode only)
	limit int

	// who mode (-who): resolve an internal device/user instead of a flow.
	// Exactly one of qname or dstIP is the destination predicate here.
	who   bool
	qname string // normalized: lowercase, no trailing dot
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

// parseTime accepts a few human-friendly layouts. Zone-less inputs are
// interpreted as UTC (ClickHouse stores flow timestamps in UTC); an explicit
// offset in an RFC3339 value is honored.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
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

// normalizeQName lowercases and strips a trailing dot so a -qname flag matches
// how qnames are stored in dns_events (normalized lowercase, no trailing dot).
func normalizeQName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// buildDNSQuery is who-mode query 1: the DNS candidates that resolved the target
// name or IP in the window. dns_events is a ReplacingMergeTree, so FINAL is
// mandatory for exact forensic counts (schema.sql:104-108). Every user value is
// a bound ? arg. A -qname matches the exact name OR any subdomain via
// endsWith(qname, "."+qname); a -dst-ip matches answer_ip exactly (which
// naturally excludes query-only fallback rows whose answer_ip is empty).
func buildDNSQuery(f filter) (string, []any) {
	var sb strings.Builder
	args := make([]any, 0, 5)

	sb.WriteString(`SELECT client_ip, qname, answer_ip, count() AS resolutions,
       min(event_time) AS first_seen, max(event_time) AS last_seen
FROM dns_events FINAL
WHERE event_time BETWEEN ? AND ?`)
	args = append(args, f.from, f.to)

	if f.qname != "" {
		sb.WriteString("\n  AND (qname = ? OR endsWith(qname, ?))")
		args = append(args, f.qname, "."+f.qname)
	} else {
		sb.WriteString("\n  AND answer_ip = ?")
		args = append(args, f.dstIP)
	}

	sb.WriteString("\nGROUP BY client_ip, qname, answer_ip\nORDER BY client_ip, last_seen\nLIMIT ?")
	args = append(args, f.limit)

	return sb.String(), args
}

// buildDHCPQuery is who-mode query 2: every lease event for the candidate client
// IPs, over a window widened back by maxLease so a lease that opened before the
// DNS window still covers the resolution instant. FINAL is mandatory (ReplacingMergeTree).
func buildDHCPQuery(ips []string, from, to time.Time) (string, []any) {
	const q = `SELECT event_time, event_id, ip, mac_token
FROM identity_dhcp_events FINAL
WHERE ip IN (?) AND event_time BETWEEN ? AND ?
ORDER BY ip, event_time`
	return q, []any{ips, from, to}
}

// buildRADIUSQuery is who-mode query 3: every accounting event for the candidate
// mac_tokens, over a window widened back by maxSession. FINAL is mandatory.
func buildRADIUSQuery(macTokens []string, from, to time.Time) (string, []any) {
	const q = `SELECT event_time, acct_status, session_id, user_token, mac_token
FROM identity_radius_events FINAL
WHERE mac_token IN (?) AND event_time BETWEEN ? AND ?
ORDER BY mac_token, event_time`
	return q, []any{macTokens, from, to}
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
		who   = flag.Bool("who", false, "who mode: resolve an internal device/user (mac_token/user_token) instead of a flow")
		qname = flag.String("qname", "", "who mode: resolved domain to trace (exact or subdomain match)")

		service = flag.String("service", "", "friendly destination service name (facebook, google, cloudflare, ...)")
		dstASN  = flag.Uint("dst-asn", 0, "destination ASN to match")
		dstOrg  = flag.String("dst-org", "", "destination org substring (case-insensitive)")
		dstIP   = flag.String("dst-ip", "", "exact destination IP (flows mode) / answered IP (who mode)")

		around = flag.String("around", "", "center of the time window (UTC)")
		window = flag.Duration("window", 10*time.Minute, "half-width is window/2 each side of -around")
		from   = flag.String("from", "", "window start, UTC (alternative to -around/-window)")
		to     = flag.String("to", "", "window end, UTC (alternative to -around/-window)")

		srcIP  = flag.String("src-ip", "", "narrow to a single source (suspect) IP")
		limit  = flag.Int("limit", 1000, "max rows to return")
		asJSON = flag.Bool("json", false, "emit JSON lines instead of a table")
	)
	flag.Parse()

	f, err := buildFilter(*who, *qname, *service, *dstASN, *dstOrg, *dstIP, *around, *window, *from, *to, *srcIP, *limit)
	if err != nil {
		log.Fatalf("trace: %v", err)
	}

	// Build the flows-mode query up front so a malformed query fails before we
	// dial ClickHouse. Who mode builds its queries inside runWho.
	var query string
	var args []any
	if !f.who {
		if query, args, err = buildQuery(f); err != nil {
			log.Fatalf("trace: %v", err)
		}
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

	if f.who {
		if err := runWho(ctx, conn, f, *asJSON); err != nil {
			log.Fatalf("trace: %v", err)
		}
		return
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

// durEnv reads a Go duration string from the environment, falling back on unset
// or unparseable values. It mirrors the enricher's IDENTITY_MAX_LEASE /
// IDENTITY_MAX_SESSION knobs (default 24h), reusing the getenv helper.
func durEnv(key string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(getenv(key, "")); err == nil {
		return d
	}
	return fallback
}

// buildFilter validates flags and resolves them into a filter. Exactly one
// destination flag and exactly one time-window form must be supplied.
func buildFilter(who bool, qname, service string, dstASN uint, dstOrg, dstIP, around string, window time.Duration, from, to, srcIP string, limit int) (filter, error) {
	var f filter
	f.who = who

	if who {
		// -service/-dst-asn/-dst-org/-src-ip are flows-table concepts with no
		// meaning against the identity/DNS event tables — reject them outright.
		if service != "" || dstASN != 0 || dstOrg != "" || srcIP != "" {
			return f, fmt.Errorf("-service, -dst-asn, -dst-org, and -src-ip are not valid with -who; use -qname or -dst-ip")
		}
		// Destination — exactly one of -qname or -dst-ip.
		n := 0
		if qname != "" {
			if f.qname = normalizeQName(qname); f.qname == "" {
				return f, fmt.Errorf("invalid -qname %q", qname)
			}
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
			return f, fmt.Errorf("with -who, specify exactly one destination: -qname or -dst-ip")
		}
	} else {
		// Flows-mode destination — exactly one.
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
	fmt.Fprintln(tw, "TIMESTAMP(UTC)\tSRC_IP\tSPORT\tDST_IP\tDPORT\tPROTO\tBYTES\tDST_ASN\tDST_ORG\tEXPORTER\tTENANT")
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
	if err := rows.Scan(&r.Timestamp, &r.SrcIP, &r.SrcPort, &r.DstIP, &r.DstPort,
		&r.Protocol, &r.Bytes, &r.DstASN, &r.DstOrg, &r.ExporterIP, &r.TenantName); err != nil {
		return err
	}
	r.Timestamp = r.Timestamp.UTC()
	return nil
}

// whoRow is one attributed DNS resolution: the candidate row plus the device and
// user bound to it at last_seen. mac_token/user_token are HMAC pseudonyms and
// stay pseudonymous; "" means no trusted binding covered that instant.
type whoRow struct {
	ClientIP    string    `json:"client_ip"`
	QName       string    `json:"qname"`
	AnswerIP    string    `json:"answer_ip"`
	Resolutions uint64    `json:"resolutions"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	MACToken    string    `json:"mac_token"`
	UserToken   string    `json:"user_token"`
}

// runWho executes the three-query who-mode join: DNS candidates -> DHCP leases
// -> RADIUS sessions, reducing each identity binding as-of the resolution time
// in Go (release/session supersession is fragile in SQL). It fails open on an
// empty candidate set (nothing resolved the target in the window).
func runWho(ctx context.Context, conn driver.Conn, f filter, asJSON bool) error {
	maxLease := durEnv("IDENTITY_MAX_LEASE", 24*time.Hour)
	maxSession := durEnv("IDENTITY_MAX_SESSION", 24*time.Hour)

	// Query 1: DNS candidates.
	dnsSQL, dnsArgs := buildDNSQuery(f)
	dnsRows, err := conn.Query(ctx, dnsSQL, dnsArgs...)
	if err != nil {
		return fmt.Errorf("dns query: %w", err)
	}
	var cands []whoRow
	ipSet := make(map[string]struct{})
	for dnsRows.Next() {
		var w whoRow
		if err := dnsRows.Scan(&w.ClientIP, &w.QName, &w.AnswerIP, &w.Resolutions, &w.FirstSeen, &w.LastSeen); err != nil {
			dnsRows.Close()
			return err
		}
		w.FirstSeen, w.LastSeen = w.FirstSeen.UTC(), w.LastSeen.UTC()
		cands = append(cands, w)
		ipSet[w.ClientIP] = struct{}{}
	}
	if err := dnsRows.Err(); err != nil {
		dnsRows.Close()
		return err
	}
	dnsRows.Close()

	// Query 2: DHCP leases for the candidate client IPs, widened back by maxLease.
	if len(ipSet) > 0 {
		ips := keysOf(ipSet)
		dhcpSQL, dhcpArgs := buildDHCPQuery(ips, f.from.Add(-maxLease), f.to)
		dhcpRows, err := conn.Query(ctx, dhcpSQL, dhcpArgs...)
		if err != nil {
			return fmt.Errorf("dhcp query: %w", err)
		}
		var dhcp []dhcpEvent
		for dhcpRows.Next() {
			var e dhcpEvent
			if err := dhcpRows.Scan(&e.Time, &e.EventID, &e.IP, &e.MACToken); err != nil {
				dhcpRows.Close()
				return err
			}
			e.Time = e.Time.UTC()
			dhcp = append(dhcp, e)
		}
		if err := dhcpRows.Err(); err != nil {
			dhcpRows.Close()
			return err
		}
		dhcpRows.Close()

		// Reduce each candidate's device as-of its last_seen.
		macSet := make(map[string]struct{})
		for i := range cands {
			mac := dhcpBindingAt(dhcp, cands[i].ClientIP, cands[i].LastSeen, maxLease)
			cands[i].MACToken = mac
			if mac != "" {
				macSet[mac] = struct{}{}
			}
		}

		// Query 3: RADIUS sessions for the resolved mac_tokens, widened by maxSession.
		if len(macSet) > 0 {
			macs := keysOf(macSet)
			radSQL, radArgs := buildRADIUSQuery(macs, f.from.Add(-maxSession), f.to)
			radRows, err := conn.Query(ctx, radSQL, radArgs...)
			if err != nil {
				return fmt.Errorf("radius query: %w", err)
			}
			var rad []radiusEvent
			for radRows.Next() {
				var e radiusEvent
				if err := radRows.Scan(&e.Time, &e.AcctStatus, &e.SessionID, &e.UserToken, &e.MACToken); err != nil {
					radRows.Close()
					return err
				}
				e.Time = e.Time.UTC()
				rad = append(rad, e)
			}
			if err := radRows.Err(); err != nil {
				radRows.Close()
				return err
			}
			radRows.Close()

			for i := range cands {
				if cands[i].MACToken != "" {
					cands[i].UserToken = radiusBindingAt(rad, cands[i].MACToken, cands[i].LastSeen, maxSession)
				}
			}
		}
	}

	return renderWho(cands, asJSON)
}

// keysOf returns the keys of a set in a stable (sorted) order so the IN (?) arg
// and any test assertions are deterministic.
func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func renderWho(rows []whoRow, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range rows {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "%d resolution(s)\n", len(rows))
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT_IP\tQNAME\tANSWER_IP\tRESOLUTIONS\tFIRST_SEEN(UTC)\tLAST_SEEN(UTC)\tMAC_TOKEN\tUSER_TOKEN")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			r.ClientIP, r.QName, r.AnswerIP, r.Resolutions,
			r.FirstSeen.Format("2006-01-02 15:04:05"), r.LastSeen.Format("2006-01-02 15:04:05"),
			unknownIfEmpty(r.MACToken), unknownIfEmpty(r.UserToken))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d resolution(s)\n", len(rows))
	return nil
}

// unknownIfEmpty renders an unresolved token as a clear placeholder in the table
// (the JSON form keeps the empty string).
func unknownIfEmpty(s string) string {
	if s == "" {
		return "unknown at that time"
	}
	return s
}
