package main

import (
	"fmt"
	"os"
	"time"
)

// logLocation resolves the *time.Location a log parser should interpret naive
// (zone-less) timestamps in. It reads the per-source override env var named by
// sourceEnv (e.g. NPS_LOG_TZ, DHCP_LOG_TZ, DNS_LOG_TZ) if set, otherwise the
// global LOG_TZ, otherwise "UTC". The value is an IANA zone name
// (e.g. "Asia/Bangkok").
//
// FAIL LOUD: an unparseable zone name is a fatal startup error, not a silent
// fallback. Real Windows/BIND servers write local time; interpreting an
// Asia/Bangkok log as UTC skews every timestamp by 7h and would silently
// mis-join forensic records. Like the fail-closed tokenizer key, this is a
// deliberate inversion of the project's fail-open rule — a mis-parse here
// corrupts evidence rather than merely dropping enrichment.
//
// IANA lookups require the zone database; main imports _ "time/tzdata" so this
// works on Windows dev boxes as well as the Ubuntu deploy host.
//
// Caveat: interpreting a naive (zone-less) local timestamp via ParseInLocation
// is inherently ambiguous across a DST fall-back fold — the same wall-clock hour
// occurs twice, and Go resolves it to one of the two instants. Asia/Bangkok has
// no DST so this never bites MUIC, but a deployment in a DST zone should expect
// up to a one-hour skew for timestamps inside the fold.
func logLocation(sourceEnv string) (*time.Location, error) {
	name := os.Getenv(sourceEnv)
	if name == "" {
		name = getenv("LOG_TZ", "UTC")
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("invalid log timezone %q (from %s / LOG_TZ): %w", name, sourceEnv, err)
	}
	return loc, nil
}
