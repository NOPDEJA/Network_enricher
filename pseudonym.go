package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// Tokenizer turns sensitive identifiers (usernames, MACs, hostnames) into
// stable pseudonymous tokens so raw values never reach ClickHouse, logs, or
// metrics. The token is the HMAC-SHA256 of the normalized identifier, keyed by
// a secret loaded from disk:
//
//	token = hex(HMAC-SHA256(key, normalize(identifier)))[:32]
//
// FAIL CLOSED: this is the one deliberate inversion of the project's fail-open
// rule. If the key file is missing or empty NewTokenizer returns an error and
// the caller keeps the whole identity subsystem disabled — a raw identifier
// must never be persisted under any code path. Flows keep flowing regardless.
type Tokenizer struct {
	key []byte
}

// NewTokenizer loads the HMAC key from keyPath. A missing, unreadable, or
// empty/whitespace-only file is an error, so the caller leaves identity
// disabled (fail closed). The key is trimmed of surrounding whitespace so a
// trailing newline in the key file doesn't silently shift every token.
func NewTokenizer(keyPath string) (*Tokenizer, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key := bytes.TrimSpace(data)
	if len(key) == 0 {
		return nil, errors.New("identity token key file is empty")
	}
	return &Tokenizer{key: append([]byte(nil), key...)}, nil
}

// token computes the keyed digest of an already-normalized identifier.
func (t *Tokenizer) token(normalized string) string {
	mac := hmac.New(sha256.New, t.key)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// MACToken normalizes and tokenizes a MAC address. An empty/separator-only
// input yields "" (no token), so callers can treat "" as "no identity".
func (t *Tokenizer) MACToken(mac string) string {
	n := normalizeMAC(mac)
	if n == "" {
		return ""
	}
	return t.token(n)
}

// UserToken normalizes and tokenizes a username.
func (t *Tokenizer) UserToken(user string) string {
	n := normalizeUser(user)
	if n == "" {
		return ""
	}
	return t.token(n)
}

// HostToken normalizes and tokenizes a hostname.
func (t *Tokenizer) HostToken(host string) string {
	n := normalizeHost(host)
	if n == "" {
		return ""
	}
	return t.token(n)
}

// normalizeMAC lowercases a MAC and strips every separator so the same hardware
// address written in any notation collapses to one token: "AA-BB-CC-DD-EE-FF",
// "AA:BB:CC:DD:EE:FF", and "aabb.ccdd.eeff" all become "aabbccddeeff". This is
// what lets a DHCP Calling-Station-Id join a RADIUS Calling-Station-Id even
// though the two logs format MACs differently.
//
// The result must be exactly 12 hex digits; anything else (too short, too long,
// non-MAC garbage) yields "" so it produces no token. Length validation matters
// because some WLCs append the SSID to Calling-Station-Id, e.g.
// "AA-BB-CC-DD-EE-FF:MUIC-WiFi" — without it, stray hex characters from the SSID
// (the C in MUIC, the F in WiFi) would corrupt the token and silently break the
// DHCP<->RADIUS join. When the text before the first ':' is already a complete
// 12-hex MAC, the remainder is treated as an SSID suffix and dropped. A
// colon-separated MAC ("aa:bb:cc:dd:ee:ff") has only 2 hex before its first ':'
// so it falls through to normalizing the whole string.
func normalizeMAC(mac string) string {
	if i := strings.IndexByte(mac, ':'); i >= 0 {
		if head := hexOnly(mac[:i]); len(head) == 12 {
			return head
		}
	}
	h := hexOnly(mac)
	if len(h) != 12 {
		return ""
	}
	return h
}

// hexOnly returns the lowercased hex digits of s, dropping every other rune.
func hexOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}

// normalizeUser lowercases a username and strips a single realm qualifier so
// the down-level ("DOMAIN\jdoe"), UPN ("jdoe@muic.mahidol.ac.th"), and bare
// ("jdoe") spellings collapse to one token. Only one leading DOMAIN\ prefix and
// one trailing @realm suffix are removed — the smallest rule that covers the
// forms NPS emits.
func normalizeUser(user string) string {
	u := strings.TrimSpace(user)
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

// normalizeHost lowercases a hostname and trims a trailing FQDN dot. It does
// NOT strip the DNS domain: two machines can share a short name across domains,
// and the host token is only forensic context (the MAC, not the hostname, is
// the join key), so distinct FQDNs are kept distinct.
func normalizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}
