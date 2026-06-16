package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/email"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string

	// Timeout caps the entire dial+handshake+send sequence
	Timeout time.Duration
}

type Sender struct {
	host        string
	port        int
	addr        string // "host:port"
	from        string
	auth        smtp.Auth
	timeout     time.Duration
	implicitTLS bool // port 465 -> connect TLS directly
}

// New validates the config and returns a Sender, returns an error if
// the configuration is unusable
// (missing host, missing From, invalid port)
func New(c Config) (*Sender, error) {
	if c.Host == "" {
		return nil, errors.New("smtp: Host is required")
	}
	if c.From == "" {
		return nil, errors.New("smtp: From is required")
	}
	port := c.Port
	if port == 0 {
		port = 587
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("smtp: invalid port %d", port)
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	s := &Sender{
		host:        c.Host,
		port:        port,
		addr:        net.JoinHostPort(c.Host, strconv.Itoa(port)),
		from:        c.From,
		timeout:     timeout,
		implicitTLS: port == 465,
	}
	if c.Username != "" {
		s.auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	return s, nil
}

// Send delivers msg via SMTP, returns an error on connection failure
func (s *Sender) Send(ctx context.Context, msg email.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	// apply the timeout / honour context cancellation, we can't pass
	// ctx into net/smtp directly, so we wrap the operation in a goroutine
	// and race it against ctx.Done()
	// on cancel we close the conn so the goroutine unblocks
	// the leaked goroutine returns quickly
	deadline, hasDeadline := ctx.Deadline()
	timeout := s.timeout
	if hasDeadline {
		if d := time.Until(deadline); d > 0 && d < timeout {
			timeout = d
		}
	}

	errCh := make(chan error, 1)
	var conn net.Conn
	go func() {
		errCh <- s.dialAndSend(&conn, msg, timeout)
	}()

	select {
	case <-ctx.Done():
		if conn != nil {
			_ = conn.Close()
		}
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// dialAndSend is the synchronous SMTP exchange
func (s *Sender) dialAndSend(connOut *net.Conn, msg email.Message, timeout time.Duration) error {
	dialer := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if s.implicitTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", s.addr, &tls.Config{ServerName: s.host})
	} else {
		conn, err = dialer.Dial("tcp", s.addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", s.addr, err)
	}
	*connOut = conn
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("smtp: new client: %w", err)
	}
	defer func() { _ = client.Quit() }()

	// STARTTLS for explicit-TLS ports (587, 25). Skip when we're
	// already on an implicit-TLS connection (465).
	if !s.implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.host}); err != nil {
				return fmt.Errorf("smtp: STARTTLS: %w", err)
			}
		}
	}

	if s.auth != nil {
		if err := client.Auth(s.auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}

	// Envelope sender/recipient, the From header is a separate thing
	// (display name + address); MAIL FROM is just the bare address
	// extracted from it. Mail servers don't accept "Foo <bar@baz>" as
	// the envelope; they want bar@baz
	envelopeFrom := extractAddress(s.from)
	if err := client.Mail(envelopeFrom); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp: RCPT TO: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(buildBody(s.from, msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp: body write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: body close: %w", err)
	}
	return nil
}

// extractAddress pulls "user@host" out of a possibly-display-formatted
// from string ("Name <user@host>" → "user@host")
func extractAddress(s string) string {
	if i := strings.LastIndexByte(s, '<'); i >= 0 {
		if j := strings.IndexByte(s[i:], '>'); j > 0 {
			return s[i+1 : i+j]
		}
	}
	return strings.TrimSpace(s)
}

// buildBody renders a Message into RFC 5322 bytes, when both Text and
// HTML are present we emit multipart/alternative; otherwise single-part
func buildBody(from string, msg email.Message) []byte {
	subject := sanitizeHeader(msg.Subject)
	to := sanitizeHeader(msg.To)
	fromHeader := sanitizeHeader(from)

	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(fromHeader)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(to)
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(subject)
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Date: ")
	b.WriteString(time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("\r\n")

	hasText := msg.Text != ""
	hasHTML := msg.HTML != ""

	switch {
	case hasText && hasHTML:
		// Picked a stable boundary that won't collide with realistic
		// body content. Boundary uniqueness only needs to hold within
		// one message, not across messages.
		const boundary = "iam-mail-alt-boundary-7Hf8sLp2"
		b.WriteString("Content-Type: multipart/alternative; boundary=\"")
		b.WriteString(boundary)
		b.WriteString("\"\r\n\r\n")
		// Text part
		b.WriteString("--")
		b.WriteString(boundary)
		b.WriteString("\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(msg.Text)
		b.WriteString("\r\n")
		// HTML part
		b.WriteString("--")
		b.WriteString(boundary)
		b.WriteString("\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(msg.HTML)
		b.WriteString("\r\n--")
		b.WriteString(boundary)
		b.WriteString("--\r\n")
	case hasHTML:
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(msg.HTML)
	default:
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(msg.Text)
	}
	return []byte(b.String())
}

func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}
