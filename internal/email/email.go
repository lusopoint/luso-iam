package email

import (
	"context"
	"errors"
)

// Message is one email to be delivered. To, Subject, and at least one
// of Text/HTML must be non-empty; senders return an error otherwise.
//
// Text is the plaintext alternative. HTML is the rich version. When
// both are present we send a multipart/alternative MIME message and
// the recipient's mail client picks one. Most modern clients pick
// HTML; some accessibility tools and CLI mail clients fall back to
// text, including both is the right default.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Validate returns an error if the message is missing required fields.
// Called by all senders before transport-specific work.
func (m Message) Validate() error {
	if m.To == "" {
		return errors.New("email: To is required")
	}
	if m.Subject == "" {
		return errors.New("email: Subject is required")
	}
	if m.Text == "" && m.HTML == "" {
		return errors.New("email: at least one of Text or HTML is required")
	}
	return nil
}

// Sender is the abstract email transport. Implementations are in
// sub-packages: smtp for real delivery, noop for dev/tests.
//
// Implementations should:
//   - validate the message before attempting send
//   - return promptly on context cancellation
//   - distinguish transient (retryable) from permanent failures via
//     wrapped errors; for now callers don't branch on type, so any
//     non-nil error means "delivery failed, log it"
type Sender interface {
	Send(ctx context.Context, msg Message) error
}
