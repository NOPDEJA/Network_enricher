package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestTokenizer writes a key file and returns a Tokenizer over it.
func newTestTokenizer(t *testing.T, key string) *Tokenizer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := NewTokenizer(path)
	if err != nil {
		t.Fatalf("NewTokenizer: %v", err)
	}
	return tok
}

func isToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// A token must be 32 lowercase hex chars and stable across calls and across two
// tokenizers holding the same key.
func TestTokenizerDeterministic(t *testing.T) {
	a := newTestTokenizer(t, "super-secret-key")
	b := newTestTokenizer(t, "super-secret-key")

	got := a.UserToken("MUIC\\jdoe")
	if !isToken(got) {
		t.Fatalf("token %q is not 32 hex chars", got)
	}
	if again := a.UserToken("MUIC\\jdoe"); again != got {
		t.Errorf("non-deterministic: %q != %q", again, got)
	}
	if other := b.UserToken("MUIC\\jdoe"); other != got {
		t.Errorf("same key gave different token: %q != %q", other, got)
	}
}

// Different keys must produce different tokens for the same identifier.
func TestTokenizerKeySeparation(t *testing.T) {
	a := newTestTokenizer(t, "key-one")
	b := newTestTokenizer(t, "key-two")
	if a.MACToken("aa:bb:cc:dd:ee:ff") == b.MACToken("aa:bb:cc:dd:ee:ff") {
		t.Error("different keys produced the same token")
	}
}

// All notations of one MAC, and all spellings of one username, must collapse to
// a single token.
func TestNormalizationCollapses(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	macForms := []string{"AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", "AABB.CCDD.EEFF", "aabbccddeeff"}
	wantMAC := tok.MACToken(macForms[0])
	for _, m := range macForms[1:] {
		if got := tok.MACToken(m); got != wantMAC {
			t.Errorf("MAC form %q -> %q, want %q", m, got, wantMAC)
		}
	}

	userForms := []string{"MUIC\\jdoe", "jdoe@muic.mahidol.ac.th", "JDoe", "jdoe"}
	wantUser := tok.UserToken(userForms[0])
	for _, u := range userForms[1:] {
		if got := tok.UserToken(u); got != wantUser {
			t.Errorf("user form %q -> %q, want %q", u, got, wantUser)
		}
	}
}

// Empty / separator-only inputs yield no token, so callers read "" as "no identity".
func TestNormalizationEmpty(t *testing.T) {
	tok := newTestTokenizer(t, "k")
	for _, in := range []string{"", "   ", "-:.", "@", "\\"} {
		if got := tok.MACToken(in); got != "" {
			t.Errorf("MACToken(%q) = %q, want empty", in, got)
		}
	}
	for _, in := range []string{"", "   ", "@realm"} {
		if got := tok.UserToken(in); got != "" {
			t.Errorf("UserToken(%q) = %q, want empty", in, got)
		}
	}
}

// FAIL CLOSED: a missing or empty key file must make NewTokenizer fail so the
// caller keeps identity disabled — never silently enabled with a weak key.
func TestNewTokenizerFailsClosed(t *testing.T) {
	if _, err := NewTokenizer(filepath.Join(t.TempDir(), "nope.key")); err == nil {
		t.Error("missing key file: expected error, got nil")
	}

	empty := filepath.Join(t.TempDir(), "empty.key")
	if err := os.WriteFile(empty, []byte("   \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTokenizer(empty); err == nil {
		t.Error("whitespace-only key file: expected error, got nil")
	}
}

// Grep-proof: after a full parse of realistic log lines, no raw identifier
// (username, MAC hex, hostname) may appear anywhere in the resulting event —
// only tokens. This is the core privacy guarantee.
func TestNoRawIdentifierLeaksThroughParsers(t *testing.T) {
	tok := newTestTokenizer(t, "k")

	rawUser := "jdoe"
	rawMACHex := "aabbccddeeff"
	rawHost := "laptop-01"

	npsLine := `<Event><Timestamp data_type="4">07/08/2026 09:15:00.100</Timestamp>` +
		`<User-Name data_type="1">MUIC\jdoe</User-Name>` +
		`<Calling-Station-Id data_type="1">AA-BB-CC-DD-EE-FF</Calling-Station-Id>` +
		`<Acct-Status-Type data_type="0">1</Acct-Status-Type>` +
		`<Acct-Session-Id data_type="1">SESSION-A</Acct-Session-Id></Event>`
	re, ok, err := parseNPSLine(npsLine, tok)
	if err != nil || !ok {
		t.Fatalf("parseNPSLine ok=%v err=%v", ok, err)
	}
	dhcpLine := "10,07/08/26,09:16:00,Assign,10.10.20.30,laptop-01.muic.local,AABBCCDDEEFF,,1,6,0,,"
	de, ok, err := parseDHCPLine(dhcpLine, tok)
	if err != nil || !ok {
		t.Fatalf("parseDHCPLine ok=%v err=%v", ok, err)
	}

	// Every stringy field of both events, concatenated, must be free of raw
	// identifiers.
	haystacks := []string{
		re.UserToken, re.MACToken, re.SessionID, re.NASIP, re.AcctStatus,
		de.IP, de.MACToken, de.HostToken,
	}
	blob := strings.ToLower(strings.Join(haystacks, "|"))
	for _, raw := range []string{rawUser, rawMACHex, rawHost} {
		if strings.Contains(blob, raw) {
			t.Errorf("raw identifier %q leaked into parsed output: %q", raw, blob)
		}
	}

	// The tokens must actually be tokens, and the same MAC from both sources must
	// resolve to the same token (this is what makes the DHCP<->RADIUS join work).
	if !isToken(re.MACToken) || !isToken(re.UserToken) || !isToken(de.MACToken) || !isToken(de.HostToken) {
		t.Error("expected 32-hex tokens on all identity fields")
	}
	if re.MACToken != de.MACToken {
		t.Errorf("same MAC tokenized differently across sources: nps=%q dhcp=%q", re.MACToken, de.MACToken)
	}
}
