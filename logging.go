package main

import (
	"log/slog"
	"os"
	"strings"
)

// setupLogger builds the process-wide structured logger and installs it as the
// slog default, so every package logs through it. Two env knobs:
//
//	LOG_FORMAT=text|json  (default text — key=value, human-readable for dev;
//	                       json is the searchable production format)
//	LOG_LEVEL=debug|info|warn|error  (default info)
//
// Logs go to stderr so they stay separate from any data a tool writes to stdout.
func setupLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(getenv("LOG_FORMAT", "text")) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}

	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
