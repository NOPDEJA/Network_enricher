package main

import "path/filepath"

// identityMode is the outcome of the identity-wiring decision in main.
type identityMode int

const (
	identityOff         identityMode = iota // identity subsystem stays disabled
	identityHashed                          // salted-hash tokenizer (key file required)
	identityPassthrough                     // store upstream pseudonyms verbatim, no key
)

// decideIdentityMode is the pure, unit-testable core of the identity wiring
// decision (main.go). Inputs are the STRICT-parsed IDENTITY_UPSTREAM_ANONYMIZED
// flag and whether IDENTITY_TOKEN_KEY_FILE / at least one log dir are set.
//
// The second return (fatal) means the config is contradictory and the process
// must exit rather than pick a winner: honoring one flag silently downgrades
// privacy (store raw where the operator expected hashing) or silently breaks the
// mentor's mapping (hash where verbatim was expected). We refuse to guess.
//
// But fatal fires ONLY when identity is actually being enabled (a log dir is
// set). Identity is opt-in via its log dirs; with none set the subsystem is off
// and the flag/key are inert, so a contradiction has no effect — crashing there
// would drop ALL flows over a moot config, violating the fail-open rule (packet
// loss is worse than enrichment failure).
//
// FAIL CLOSED is preserved: when upstreamAnon is false, pass-through is
// unreachable — the only way to store values without local hashing is the
// explicit flag. "No key" in normal mode yields identityOff, never raw storage.
func decideIdentityMode(upstreamAnon, keyFileSet, anyLogDir bool) (mode identityMode, fatal bool) {
	if !anyLogDir {
		return identityOff, false
	}
	if upstreamAnon && keyFileSet {
		return identityOff, true
	}
	if upstreamAnon {
		return identityPassthrough, false
	}
	if keyFileSet {
		return identityHashed, false
	}
	return identityOff, false
}

func hasConflictingLeaseDirs(dhcpDir, keaDir string) bool {
	return dhcpDir != "" && keaDir != ""
}

// absPathForLog resolves dir to an absolute path for startup logging so a
// pass-through misconfiguration pointed at the wrong directory is visible in the
// logs. An empty dir logs as "(unset)"; an unresolvable path falls back to the
// raw value rather than failing.
func absPathForLog(dir string) string {
	if dir == "" {
		return "(unset)"
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}
