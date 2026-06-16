package noop

import (
	"context"
	"log/slog"

	"github.com/lusopoint/lusoiam/internal/email"
)

type Sender struct {
	logger *slog.Logger
}

func New(logger *slog.Logger) *Sender {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sender{logger: logger}
}

// Send records the message at info level and returns nil
// always succeeds (after Validate), since there's nothing to fail
func (s *Sender) Send(_ context.Context, msg email.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	s.logger.Info("email (noop sender, not actually delivered)",
		"to", msg.To,
		"subject", msg.Subject,
		"text", msg.Text,
	)
	return nil
}
