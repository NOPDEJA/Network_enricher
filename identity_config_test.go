package main

import "testing"

// decideIdentityMode is the testable core of the main.go identity wiring. It must
// preserve the FAIL-CLOSED invariant (no key + no flag => off, never raw) and
// fail loud on the contradictory both-set config.
func TestDecideIdentityMode(t *testing.T) {
	cases := []struct {
		name       string
		upstream   bool
		keyFileSet bool
		anyLogDir  bool
		wantMode   identityMode
		wantFatal  bool
	}{
		// Contradictory: pass-through flag AND a token key. Fatal only when identity
		// is actually active (a dir is set); with no dir the subsystem is off and
		// the contradiction is inert, so we must NOT crash the whole enricher.
		{"both set, dir set", true, true, true, identityOff, true},
		{"both set, no dir", true, true, false, identityOff, false},

		// Pass-through: flag true, no key, dir set -> verbatim, no key required.
		{"passthrough enabled", true, false, true, identityPassthrough, false},
		{"passthrough flag but no dir", true, false, false, identityOff, false},

		// Normal hashed mode unchanged: key + dir.
		{"hashed enabled", false, true, true, identityHashed, false},
		{"key set but no dir", false, true, false, identityOff, false},

		// FAIL CLOSED: no key and no flag must be OFF even with a dir — never raw.
		{"no key no flag, dir set", false, false, true, identityOff, false},
		{"nothing set", false, false, false, identityOff, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, fatal := decideIdentityMode(tc.upstream, tc.keyFileSet, tc.anyLogDir)
			if mode != tc.wantMode || fatal != tc.wantFatal {
				t.Errorf("decideIdentityMode(%v,%v,%v) = (%d,%v), want (%d,%v)",
					tc.upstream, tc.keyFileSet, tc.anyLogDir, mode, fatal, tc.wantMode, tc.wantFatal)
			}
		})
	}
}
