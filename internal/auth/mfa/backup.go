package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
)

// backupCodeCount and backupCodeLen are per project guidelines section 9:
// 10 codes × 8 chars. The character set excludes visually-confusing pairs
// (0/O, 1/I/l) to make manual copy easier.
const (
	backupCodeCount = 10
	backupCodeLen   = 8
	backupAlphabet  = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// GenerateBackupCodes creates a fresh set, replaces any existing codes,
// and returns the plaintext codes for one-time display. The plaintext
// is never persisted — only argon2id hashes. If the user loses these,
// they regenerate (which revokes the old set atomically).
func (s *Service) GenerateBackupCodes(ctx context.Context, userID pgtype.UUID) ([]string, error) {
	codes := make([]string, backupCodeCount)
	hashes := make([]string, backupCodeCount)

	for i := 0; i < backupCodeCount; i++ {
		c, err := randomCode(backupCodeLen)
		if err != nil {
			return nil, fmt.Errorf("generate code: %w", err)
		}
		codes[i] = c
		// Normalize before hashing so the verifier can normalize the
		// user's input the same way (case + dashes).
		h, err := crypto.HashPassword(normalizeCode(c))
		if err != nil {
			return nil, fmt.Errorf("hash code: %w", err)
		}
		hashes[i] = h
	}

	if err := s.store.ReplaceBackupCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("persist codes: %w", err)
	}
	return codes, nil
}

// VerifyBackupCode validates the user-submitted code against any unused
// hash for the user. On success, the matched row is marked used and
// cannot be replayed.
//
// Loading all hashes is O(n) where n ≤ 10 — fine for backup codes; we
// don't index by hash because argon2id salts make each hash unique.
func (s *Service) VerifyBackupCode(ctx context.Context, userID pgtype.UUID, code string) error {
	candidate := normalizeCode(code)
	if candidate == "" {
		return ErrInvalidCode
	}

	codes, err := s.store.ListUnusedBackupCodes(ctx, userID)
	if err != nil {
		return fmt.Errorf("list backup codes: %w", err)
	}

	for i := range codes {
		row := &codes[i]
		ok, vErr := crypto.VerifyPassword(candidate, row.CodeHash)
		if vErr != nil {
			// Skip malformed rows — should never happen in practice.
			continue
		}
		if ok {
			if err := s.store.MarkBackupCodeUsed(ctx, row.ID); err != nil {
				// Race: another concurrent verification just consumed
				// this same code. Treat as failure to be safe.
				return ErrInvalidCode
			}
			return nil
		}
	}
	return ErrInvalidCode
}

// helpers

// randomCode returns n characters from backupAlphabet using crypto/rand.
// Uniform: alphabet length is 31, so rejection sampling would be tidier
// but 256 mod 31 = 8 gives ≤ 3% bias — acceptable for these codes since
// they're only checked against a 10-element list with rate limiting.
func randomCode(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = backupAlphabet[int(b)%len(backupAlphabet)]
	}
	// Insert a dash in the middle for readability: "ABCD-EFGH".
	if n == 8 {
		return string(out[:4]) + "-" + string(out[4:]), nil
	}
	return string(out), nil
}

// normalizeCode strips dashes/whitespace and uppercases the input.
// Lets users paste "abcd-efgh", "abcdefgh", or "ABCD EFGH" interchangeably.
func normalizeCode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == ' ', r == '-', r == '\t':
			// skip
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32) // uppercase
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
