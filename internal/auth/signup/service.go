package signup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/email"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

var (
	// ErrEmailInUse the submitted email is already registered.
	ErrEmailInUse = errors.New("signup: email already in use")

	// ErrInvalidEmail invalid email address
	ErrInvalidEmail = errors.New("signup: invalid email address")

	// ErrWeakPassword submitted password is shorter than the configured minimum
	ErrWeakPassword = errors.New("signup: password does not meet requirements")

	// ErrInvalidToken verification token is unknown, expired, already used, OR points to an email that no longer matches
	ErrInvalidToken = errors.New("signup: token is unknown, expired, already used, or stale")

	// ErrMissingName first name and/or last name was blank
	ErrMissingName = errors.New("signup: first and last name are required")
)

type Config struct {
	Store   *postgres.Store
	Sender  email.Sender
	BaseURL string
	From    string
	// TokenTTL is how long a verification token remains valid, default 24h
	TokenTTL time.Duration
	// MinPasswordLength is the floor for the chosen password
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
		return nil, errors.New("signup: store is required")
	}
	if c.Sender == nil {
		return nil, errors.New("signup: sender is required (use the noop sender if you don't want SMTP)")
	}
	if c.BaseURL == "" {
		return nil, errors.New("signup: BaseURL is required (the verification link needs an absolute URL)")
	}

	ttl := c.TokenTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	minLen := c.MinPasswordLength
	if minLen <= 0 {
		minLen = 12
	}
	from := c.From
	if from == "" {
		// TODO: default should be re-thinked
		from = "IAM <noreply@localhost>"
	}

	return &Service{
		store:             c.Store,
		sender:            c.Sender,
		baseURL:           strings.TrimRight(c.BaseURL, "/"),
		from:              from,
		tokenTTL:          ttl,
		minPasswordLength: minLen,
	}, nil
}

// MinPasswordLength surfaces the minimum-length
func (s *Service) MinPasswordLength() int { return s.minPasswordLength }

// TokenTTL surfaces the verification token lifetime
func (s *Service) TokenTTL() time.Duration { return s.tokenTTL }

// maxNameLength caps the stored length of first/last name
// generous enough for real names, tight enough to reject junk paste-bombs
const maxNameLength = 100

type RegisterParams struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
	RequestIP string
	UserAgent string
}

// Register creates a new user, stores their hashed password, generates
// a verification token, and emails the verification link
func (s *Service) Register(ctx context.Context, p RegisterParams) (*postgres.User, error) {
	// normalise + validate email
	addr := strings.TrimSpace(strings.ToLower(p.Email))
	if _, err := mail.ParseAddress(addr); err != nil {
		return nil, ErrInvalidEmail
	}

	password := p.Password
	if len(password) < s.minPasswordLength {
		return nil, ErrWeakPassword
	}

	// first + last name are required at self signup
	firstName := strings.TrimSpace(p.FirstName)
	lastName := strings.TrimSpace(p.LastName)
	if firstName == "" || lastName == "" {
		return nil, ErrMissingName
	}
	if len(firstName) > maxNameLength || len(lastName) > maxNameLength {
		return nil, ErrMissingName
	}

	// duplicate check
	// race condition note: another request could insert the same email between
	// this check and our own insert
	// we re-detect that case by catching the unique constraint
	// violation on insert and translating it back to ErrEmailInUse
	// defensive double-check, not a substitute for the db constraint
	existing, err := s.store.GetUserByEmail(ctx, addr)
	if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		return nil, fmt.Errorf("lookup existing email: %w", err)
	}
	if existing != nil {
		return nil, ErrEmailInUse
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// derive a display name from the two parts so the existing displayName-based surfaces
	// (CAS principal fallback, admin list, OIDC profile) have something sensible without a separate field
	displayName := firstName + " " + lastName

	user, err := s.store.CreateUser(ctx, postgres.CreateUserParams{
		Email:       &addr,
		DisplayName: &displayName,
		FirstName:   &firstName,
		LastName:    &lastName,
	})
	if err != nil {
		// unique-violation translation, the error string check is
		// not great but pgx does not expose a clean "unique violation"
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, ErrEmailInUse
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	// store the credential, UpsertCredential ensures only one row
	// per user, no risk of multiple credentials on a single account
	if err := s.store.UpsertCredential(ctx, user.ID, hash); err != nil {
		return nil, fmt.Errorf("store credential: %w", err)
	}

	// generate and store verification token
	token, err := crypto.RandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(s.tokenTTL)
	if err := s.store.CreateEmailVerificationToken(ctx, tokenHash, user.ID, addr, expiresAt, p.RequestIP, p.UserAgent); err != nil {
		return nil, fmt.Errorf("store token: %w", err)
	}

	// send the email, same as passwordreset
	// failure here is logged but propagated, because the user ca not continue without the link
	verifyURL := s.baseURL + "/verify?token=" + url.QueryEscape(token)
	if err := s.sender.Send(ctx, verifyMessage(addr, verifyURL, s.tokenTTL)); err != nil {
		slog.ErrorContext(ctx, "signup: send verification email failed",
			"err", err,
			"user_id", user.ID,
		)
		return nil, fmt.Errorf("send verification email: %w", err)
	}

	slog.InfoContext(ctx, "signup: registered",
		"user_id", user.ID,
		"email_hash", emailHash(addr),
		"expires_at", expiresAt,
	)
	return user, nil
}

// Verify consumes a verification token. on success:
//   - the token is marked used (replay proof)
//   - the user's email_verified_at is set to NOW()
//   - all outstanding tokens for the user are deleted (so a second
//     emailed link can't be activated later)
func (s *Service) Verify(ctx context.Context, token string) (*postgres.User, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	row, err := s.store.GetEmailVerificationToken(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("lookup token: %w", err)
	}
	if row.UsedAt != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrInvalidToken
	}

	user, err := s.store.GetUserByID(ctx, row.UserID)
	if err != nil {
		// user deleted between issue and click are invalid
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	// email guard, if the user changed their address after
	// the token was issued, this token verifies the OLD address and
	// must not mark the new one verified, comparing case-insensitively
	// because citext stores it case preserving but compares case- insensitive at the SQL level
	if user.Email == nil || !strings.EqualFold(*user.Email, row.Email) {
		return nil, ErrInvalidToken
	}

	if err := s.store.MarkEmailVerificationTokenUsed(ctx, row.TokenHash); err != nil {
		return nil, fmt.Errorf("mark token used: %w", err)
	}
	if err := s.store.MarkUserEmailVerified(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("mark user verified: %w", err)
	}
	// Best-effort cleanup; failure here doesn't break the verification.
	if err := s.store.DeleteEmailVerificationTokensForUser(ctx, user.ID); err != nil {
		slog.WarnContext(ctx, "signup: cleanup other verification tokens failed",
			"err", err, "user_id", user.ID)
	}

	slog.InfoContext(ctx, "signup: email verified",
		"user_id", user.ID,
		"email_hash", emailHash(*user.Email),
	)
	return user, nil
}

// hashToken returns hex(sha256(token)) store in the db
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// emailHash returns hex(sha256(email)), used in log lines so we can
// correlate without printing the plain email, just to be GDPR complaint
func emailHash(addr string) string {
	sum := sha256.Sum256([]byte(addr))
	return hex.EncodeToString(sum[:8])
}

// verifyMessage builds the verification email
func verifyMessage(to, verifyURL string, ttl time.Duration) email.Message {
	hours := int(ttl.Hours())
	if hours < 1 {
		hours = 1
	}
	subject := "Confirm your email address"
	text := fmt.Sprintf(`Welcome!

Thanks for signing up. To finish creating your account, please confirm
your email address by clicking the link below. The link expires in
%d hours.

%s

If you didn't sign up, you can safely ignore this email, no account
will be activated without confirmation.
`, hours, verifyURL)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:560px;margin:24px auto;color:#111;line-height:1.5">
<p>Welcome!</p>
<p>Thanks for signing up. To finish creating your account, please confirm
your email address by clicking the link below. The link expires in
<strong>%d hours</strong>.</p>
<p><a href="%s" style="display:inline-block;padding:10px 16px;background:#0b5fff;color:#fff;text-decoration:none;border-radius:6px">Confirm email</a></p>
<p style="color:#666;font-size:13px">If the button doesn't work, copy and paste this URL into your browser:<br>
<code style="word-break:break-all">%s</code></p>
<p style="color:#666;font-size:13px;margin-top:24px">If you didn't sign up, you can safely ignore this email, no account will be activated without confirmation.</p>
</body></html>`, hours, verifyURL, verifyURL)

	return email.Message{
		To:      to,
		Subject: subject,
		Text:    text,
		HTML:    html,
	}
}
