package noop

import (
	"context"
	"log/slog"
	"testing"

	"github.com/lusopoint/lusoiam/internal/email"
)

// TestNoop_Send: happy path. Valid message → nil error.
func TestNoop_Send(t *testing.T) {
	t.Parallel()
	s := New(slog.Default())
	err := s.Send(context.Background(), email.Message{
		To:      "user@example.com",
		Subject: "Hello",
		Text:    "test",
	})
	if err != nil {
		t.Errorf("noop send should always succeed, got %v", err)
	}
}

// TestNoop_ValidateFirst: even the noop sender must reject invalid
// messages, so callers writing tests against the interface get the
// same error shape regardless of implementation.
func TestNoop_ValidateFirst(t *testing.T) {
	t.Parallel()
	s := New(slog.Default())
	err := s.Send(context.Background(), email.Message{})
	if err == nil {
		t.Error("noop send must reject invalid messages")
	}
}

// TestNoop_NilLogger: nil logger defaults to slog.Default. Common
// caller mistake; should not panic.
func TestNoop_NilLogger(t *testing.T) {
	t.Parallel()
	s := New(nil)
	if err := s.Send(context.Background(), email.Message{
		To: "x@y", Subject: "s", Text: "t",
	}); err != nil {
		t.Errorf("nil logger should default, got %v", err)
	}
}
