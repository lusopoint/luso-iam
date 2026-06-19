package passwordreset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/email"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

var (
	ErrInvalidToken = errors.New("passwordreset: token is unknown, expired, or already used")
	ErrWeakPassword = errors.New("passwordreset: password does not meet requirements")
)

// Config plugs the service into its dependencies
type Config struct {
	Store             *postgres.Store
	Sender            email.Sender
	BaseURL           string        // for building the reset link in emails
	From              string        // display From header for outgoing emails
	TokenTTL          time.Duration // TokenTTL is how long a generated token remains valid, defaults to 30 minutes
	MinPasswordLength int
}

type Service struct {
	store             *postgres.Store
	sender            email.Sender
	baseURL           string
	from              string
	tokenTTL          time.Duration
	minPasswordLength int
}

func New(c Config) (*Service, error) {
	if c.Store == nil {
		return nil, errors.New("passwordreset: Store is required")
	}
	if c.Sender == nil {
		return nil, errors.New("passwordreset: Sender is required")
	}
	if c.BaseURL == "" {
		return nil, errors.New("passwordreset: BaseURL is required")
	}
	if c.From == "" {
		return nil, errors.New("passwordreset: From is required")
	}
	ttl := c.TokenTTL
	if ttl == 0 {
		ttl = 30 * time.Minute
	}
	minLen := c.MinPasswordLength
	if minLen == 0 {
		minLen = 12
	}
	return &Service{
		store:             c.Store,
		sender:            c.Sender,
		baseURL:           strings.TrimRight(c.BaseURL, "/"),
		from:              c.From,
		tokenTTL:          ttl,
		minPasswordLength: minLen,
	}, nil
}

// Request generates a reset token for the user with this email and
// sends the reset link in an email, returns nil whether or not an
// account exists
//
// concurrency note: if the user requests multiple resets, each gets
// its own token row, the most recent click wins
func (s *Service) Request(ctx context.Context, email string, requestIP, userAgent string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil // silently no-op; same response as nonexistent email
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		// Not-found is the common case, not an error from our perspective
		// other errors (DB down) propagate up to be logged
		if errors.Is(err, postgres.ErrNotFound) {
			slog.InfoContext(ctx, "password-reset: requested for unknown email",
				"email_hash", emailHash(email))
			return nil
		}
		return fmt.Errorf("lookup user: %w", err)
	}

	// generate 256-bit token which returns hex-encoded bytes
	// (easy to use on URL query string)
	token, err := crypto.RandomToken(32)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	tokenHash := hashToken(token)

	expiresAt := time.Now().Add(s.tokenTTL)
	if err := s.store.CreatePasswordResetToken(ctx, tokenHash, user.ID, expiresAt, requestIP, userAgent); err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	resetURL := s.baseURL + "/password/reset?token=" + url.QueryEscape(token)

	// send the email, failure here is the operators problem (SMTP down, credentials wrong)
	// the user can re request, meanwhile we log the error
	if user.Email == nil {
		// shouldn't happen given the lookup-by-email path
		return nil
	}
	msg := email_message(s.from, *user.Email, resetURL, s.tokenTTL)
	if err := s.sender.Send(ctx, msg); err != nil {
		slog.ErrorContext(ctx, "password-reset: send email failed",
			"err", err,
			"user_id", user.ID,
		)
		return fmt.Errorf("send reset email: %w", err)
	}

	slog.InfoContext(ctx, "password-reset: email sent",
		"user_id", user.ID,
		"expires_at", expiresAt,
	)
	return nil
}

// Verify checks that the token is real, unexpired, and unused
func (s *Service) Verify(ctx context.Context, token string) (postgres.User, error) {
	if token == "" {
		return postgres.User{}, ErrInvalidToken
	}
	row, err := s.store.GetPasswordResetToken(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return postgres.User{}, ErrInvalidToken
		}
		return postgres.User{}, fmt.Errorf("load token: %w", err)
	}
	if row.UsedAt != nil {
		return postgres.User{}, ErrInvalidToken
	}
	if time.Now().After(row.ExpiresAt) {
		return postgres.User{}, ErrInvalidToken
	}
	user, err := s.store.GetUserByID(ctx, row.UserID)
	if err != nil {
		// user was deleted between request and click: invalid
		if errors.Is(err, postgres.ErrNotFound) {
			return postgres.User{}, ErrInvalidToken
		}
		return postgres.User{}, fmt.Errorf("load user: %w", err)
	}
	return *user, nil
}

// Reset consumes the token and updates the password atomically
// (in the sense that all db writes happen before any session-revocation network
// effect). On success:
// - the password hash is replaced
// - failed-attempts counter is zeroed
// - active sessions are revoked
// - the consumed token is marked used
// - all OTHER outstanding reset tokens for this user are deleted
func (s *Service) Reset(ctx context.Context, token, newPassword string) error {
	user, err := s.Verify(ctx, token)
	if err != nil {
		return err
	}
	if len(newPassword) < s.minPasswordLength {
		return ErrWeakPassword
	}

	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := s.store.UpsertCredential(ctx, user.ID, hash); err != nil {
		return fmt.Errorf("upsert credential: %w", err)
	}
	_ = s.store.ResetFailedAttempts(ctx, user.ID)
	_, _ = s.store.RevokeAllSessionsForUser(ctx, user.ID)

	// consumed token and any other tokens for this user
	if err := s.store.MarkPasswordResetTokenUsed(ctx, hashToken(token)); err != nil {
		// we already changed the password, not fatal, log and move on
		slog.ErrorContext(ctx, "password-reset: mark token used failed",
			"err", err, "user_id", user.ID)
	}
	if err := s.store.DeletePasswordResetTokensForUser(ctx, user.ID); err != nil {
		slog.ErrorContext(ctx, "password-reset: cleanup outstanding tokens failed",
			"err", err, "user_id", user.ID)
	}
	return nil
}

// MinPasswordLength exposes the configured password floor so handlers
// can mirror the rule in their validation error messages
func (s *Service) MinPasswordLength() int { return s.minPasswordLength }

// TokenTTL exposes the configured TTL so handlers / templates can
// surface "expires in N minutes" copy
func (s *Service) TokenTTL() time.Duration { return s.tokenTTL }

// hashToken returns the sha256-hex of a token
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// emailHash returns a one-way digest of the email for log lines
func emailHash(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:8])
}

// email body
func email_message(from, to, resetURL string, ttl time.Duration) email.Message {
	mins := int(ttl.Minutes())
	subject := "Reset your password"
	text := fmt.Sprintf(`Hello,

Someone requested a password reset for your account. If that was you,
click the link below to choose a new password. The link expires in
%d minutes.

%s

If you didn't request this, you can safely ignore this email.
`, mins, resetURL)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:560px;margin:24px auto;color:#111;line-height:1.5">
<p>Hello,</p>
<p>Someone requested a password reset for your account. If that was you,
click the link below to choose a new password. The link expires in
<strong>%d minutes</strong>.</p>
<p><a href="%s" style="display:inline-block;padding:10px 16px;background:#0b5fff;color:#fff;text-decoration:none;border-radius:6px">Reset password</a></p>
<p style="font-size:13px;color:#666">If the button doesn't work, copy this URL into your browser:<br>
<code>%s</code></p>
<p style="font-size:13px;color:#666">If you didn't request this, you can safely ignore this email.</p>
</body></html>
`, mins, resetURL, resetURL)

	return email.Message{
		To:      to,
		Subject: subject,
		Text:    text,
		HTML:    html,
	}
}
