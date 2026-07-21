package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// wrote. renderWho prints straight to os.Stdout, so this is the only way to
// assert the rendered text without reshaping the function.
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	err = fn()
	os.Stdout = orig
	w.Close()
	out := <-done
	r.Close()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// The whole point of the ambiguity return is that a reader can tell "the
// evidence names several devices" apart from "the evidence names none". If both
// rendered as "unknown at that time", the distinction would exist in the
// reducers and be thrown away at the last step — so pin the rendering, not just
// the reducers.
func TestRenderWhoDistinguishesAmbiguousFromUnknown(t *testing.T) {
	seen := time.Date(2026, 7, 13, 15, 45, 0, 0, time.UTC)
	rows := []whoRow{
		{ClientIP: "10.0.0.1", QName: "facebook.com", Resolutions: 1, FirstSeen: seen, LastSeen: seen,
			MACToken: "macRESOLVED", UserToken: "userRESOLVED"},
		{ClientIP: "10.0.0.2", QName: "facebook.com", Resolutions: 1, FirstSeen: seen, LastSeen: seen,
			MACToken: "", UserToken: ""}, // nothing bound
		{ClientIP: "10.0.0.3", QName: "facebook.com", Resolutions: 1, FirstSeen: seen, LastSeen: seen,
			MACToken: "", MACAmbiguous: true}, // several devices; RADIUS join skipped
		{ClientIP: "10.0.0.4", QName: "facebook.com", Resolutions: 1, FirstSeen: seen, LastSeen: seen,
			MACToken: "macRESOLVED", UserToken: "", UserAmbiguous: true}, // device known, user ambiguous
	}

	t.Run("table output", func(t *testing.T) {
		out := captureStdout(t, func() error { return renderWho(rows, false) })

		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		byIP := map[string]string{}
		for _, ln := range lines {
			for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
				if strings.HasPrefix(ln, ip) {
					byIP[ip] = ln
				}
			}
		}
		if len(byIP) != 4 {
			t.Fatalf("expected a line per client, got %d:\n%s", len(byIP), out)
		}

		if !strings.Contains(byIP["10.0.0.1"], "macRESOLVED") || !strings.Contains(byIP["10.0.0.1"], "userRESOLVED") {
			t.Errorf("resolved row lost its tokens: %q", byIP["10.0.0.1"])
		}
		if strings.Count(byIP["10.0.0.2"], "unknown at that time") != 2 {
			t.Errorf("unbound row must read unknown for both columns: %q", byIP["10.0.0.2"])
		}
		if !strings.Contains(byIP["10.0.0.3"], "ambiguous at that time") {
			t.Errorf("ambiguous device must render as ambiguous, not unknown: %q", byIP["10.0.0.3"])
		}
		if strings.Contains(byIP["10.0.0.3"], "unknown at that time") {
			// An ambiguous device skips the RADIUS join entirely, so its user
			// column is genuinely unknown — but the DEVICE column must not be.
			if strings.Index(byIP["10.0.0.3"], "unknown at that time") <
				strings.Index(byIP["10.0.0.3"], "ambiguous at that time") {
				t.Errorf("device column must be the ambiguous one: %q", byIP["10.0.0.3"])
			}
		}
		if !strings.Contains(byIP["10.0.0.4"], "ambiguous at that time") {
			t.Errorf("ambiguous user must render as ambiguous: %q", byIP["10.0.0.4"])
		}
	})

	t.Run("json output carries the flags", func(t *testing.T) {
		out := captureStdout(t, func() error { return renderWho(rows, true) })

		var got []whoRow
		for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			var w whoRow
			if err := json.Unmarshal([]byte(ln), &w); err != nil {
				t.Fatalf("bad JSON line %q: %v", ln, err)
			}
			got = append(got, w)
		}
		if len(got) != len(rows) {
			t.Fatalf("got %d JSON rows, want %d", len(got), len(rows))
		}
		// JSON keeps the empty token and expresses ambiguity as a flag, so a
		// consumer can tell the two apart without parsing display strings.
		if got[1].MACAmbiguous || got[1].UserAmbiguous {
			t.Errorf("unbound row must not be flagged ambiguous: %+v", got[1])
		}
		if !got[2].MACAmbiguous || got[2].MACToken != "" {
			t.Errorf("ambiguous device must be flagged with an empty token: %+v", got[2])
		}
		if !got[3].UserAmbiguous || got[3].UserToken != "" {
			t.Errorf("ambiguous user must be flagged with an empty token: %+v", got[3])
		}
	})
}
