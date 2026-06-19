package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
)

// 10 codes × 8 chars
// 0/O and 1/I/l are excluded to remove confusion when manual copying
const (
	backupCodeCount = 10
	backupCodeLen   = 8
	backupAlphabet  = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// GenerateBackupCodes creates a fresh set, replaces any existing codes,
// and returns the plaintext codes for one-time display
func (s *Service) GenerateBackupCodes(ctx context.Context, userID pgtype.UUID) ([]string, error) {
	codes := make([]string, backupCodeCount)
	hashes := make([]string, backupCodeCount)

	for i := 0; i < backupCodeCount; i++ {
		c, err := randomCode(backupCodeLen)
		if err != nil {
			return nil, fmt.Errorf("generate code: %w", err)
		}
		codes[i] = c
		// normalize before hashing so the verifier can normalize the
		// users input the same way (case + dashes)
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

// VerifyBackupCode validates the user submitted code against any unused hash for the user
// on success, the matched row is marked used and cannot be replayed
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
			// skip malformed rows, should never happen in practice
			continue
		}
		if ok {
			if err := s.store.MarkBackupCodeUsed(ctx, row.ID); err != nil {
				// race, another concurrent verification just consumed this same code
				return ErrInvalidCode
			}
			return nil
		}
	}
	return ErrInvalidCode
}

// randomCode returns n characters from backupAlphabet using crypto/rand
func randomCode(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = backupAlphabet[int(b)%len(backupAlphabet)]
	}
	// insert a dash in the middle for readability: "ABCD-EFGH"
	if n == 8 {
		return string(out[:4]) + "-" + string(out[4:]), nil
	}
	return string(out), nil
}

// normalizeCode strips dashes/whitespace and uppercases the input
// lets users paste "abcd-efgh", "abcdefgh", or "ABCD EFGH"
func normalizeCode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == ' ', r == '-', r == '\t':
			// skip
		case r >= 'a' && r <= 'z':
			// uppercase
			b.WriteRune(r - 32)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
