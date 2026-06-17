package server

import (
	"io"
	"log/slog"
	"testing"
)

// discardLogger returns a slog.Logger that drops all output, so tests don't
// spam the terminal with HTTP/Migrate logs.
func discardLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
