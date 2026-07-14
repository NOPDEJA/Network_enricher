package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// maxScanReadBytes caps how much of one file's unread tail a single scan pulls
// into memory, so a cold start over a large backlog can't OOM. Shared by every
// log poller (NPS, DHCP, DNS).
const maxScanReadBytes = 8 << 20 // 8 MB

// scanAppendedDir tails every file in dir, feeding each newly-appended complete
// line to handle. It is the shared incremental-scan core for the identity
// (NPS + DHCP) and DNS pollers: offsets tracks per-file read position across
// scans and is owned by the single poller goroutine that calls this (no lock).
// source is used only for log context. handle receives the file path alongside
// each line so a stateful per-file parser can keep files separate (the DNS
// tcpdump parser needs this); line-stateless callers ignore path. It never
// recovers panics — the caller's scan() owns the recover so a bad line is
// counted, not silently fatal.
func scanAppendedDir(dir, source string, offsets map[string]int64, handle func(path, line string)) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Error("poller: cannot read log dir", "source", source, "dir", dir, "err", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		readAppendedFile(filepath.Join(dir, entry.Name()), source, offsets, handle)
	}
}

// readAppendedFile reads the bytes added to one file since the last scan and
// feeds only complete lines to handle (a trailing partial line is held back for
// the next scan). A file smaller than its stored offset was rotated/truncated,
// so it is re-read from 0. The read is bounded by maxScanReadBytes; the offset
// advances only past the last complete line so the next scan continues cleanly.
func readAppendedFile(path, source string, offsets map[string]int64, handle func(path, line string)) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	size := fi.Size()
	off := offsets[path]
	if size < off {
		off = 0 // rotation or truncation: start over
	}
	if size == off {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		slog.Error("poller: cannot open log file", "source", source, "path", path, "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxScanReadBytes))
	if err != nil {
		return
	}

	// Only advance past the last newline; hold back any partial final line.
	nl := bytes.LastIndexByte(data, '\n')
	if nl < 0 {
		return
	}
	offsets[path] = off + int64(nl+1)

	for _, raw := range bytes.Split(data[:nl+1], []byte{'\n'}) {
		line := strings.TrimRight(string(raw), "\r")
		if line == "" {
			continue
		}
		handle(path, line)
	}
}
