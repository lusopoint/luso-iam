// command seed-user creates a local user account (email + password) and
// Usage:
//
//	go run ./cmd/seed-user -email l@mail.com -password password123 -admin
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/config"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

func main() {
	var (
		email    = flag.String("email", "", "email address (required, case-insensitive)")
		password = flag.String("password", "", "initial password (required, min 12 chars recommended)")
		name     = flag.String("name", "", "display name (optional)")
		admin    = flag.Bool("admin", false, "promote the user to admin")
		username = flag.String("username", "", "username (optional)")
	)
	flag.Parse()

	if err := run(*email, *password, *username, *name, *admin); err != nil {
		fmt.Fprintf(os.Stderr, "seed-user: %v\n", err)
		os.Exit(1)
	}
}

func run(email, password, username, displayName string, admin bool) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return errors.New("-email is required")
	}
	if password == "" {
		return errors.New("-password is required")
	}
	if len(password) < 8 {
		// The admin API requires 12+; the CLI is looser for dev convenience
		// but flags very short passwords as a footgun.
		log.Printf("warning: password is %d chars; consider 12+ for production use", len(password))
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := postgres.Connect(ctx, config.DBConfig{
		URL:      dbURL,
		MaxConns: 2,
		MinConns: 1,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	store := postgres.NewStore(pool)

	// Idempotency: if a user already exists for this email, skip the
	// insert and proceed straight to credential upsert + admin flag.
	// This lets folks re-run the command to reset a forgotten password.
	existing, err := store.GetUserByEmail(ctx, email)
	var user *postgres.User
	switch {
	case err == nil:
		user = existing
		log.Printf("user already exists (id=%s); updating credential", uuidString(user.ID))
	case errors.Is(err, postgres.ErrNotFound):
		p := postgres.CreateUserParams{Email: &email}
		if displayName != "" {
			p.DisplayName = &displayName
		}
		if username != "" {
			p.Username = &username
		}
		user, err = store.CreateUser(ctx, p)
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		log.Printf("user created (id=%s)", uuidString(user.ID))
	default:
		return fmt.Errorf("lookup user: %w", err)
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := store.UpsertCredential(ctx, user.ID, hash); err != nil {
		return fmt.Errorf("upsert credential: %w", err)
	}
	log.Printf("password set")

	if admin {
		// Promotion is a one-line update — keep it in the CLI rather
		// than adding a store method just for this bootstrap path.
		tag, err := pool.Exec(ctx,
			`UPDATE users SET is_admin = true WHERE id = $1 AND deleted_at IS NULL`,
			user.ID)
		if err != nil {
			return fmt.Errorf("promote to admin: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return errors.New("promote: no rows affected")
		}
		log.Printf("admin flag set")
	}

	fmt.Printf("\nDone.\n  email:    %s\n  id:       %s\n  is_admin: %t\n",
		email, uuidString(user.ID), admin)
	fmt.Printf("\nSign in at: http://localhost:8080/cas/login\n")
	if admin {
		fmt.Printf("Then visit: http://localhost:8080/admin/\n")
	}
	return nil
}

// uuidString renders a pgtype.UUID in canonical 8-4-4-4-12 hex form.
// Inlined here because the seed-user CLI is a single-file utility and
// doesn't justify a shared helper package.
func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	const hx = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, b := range u.Bytes {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hx[b>>4]
		out[pos+1] = hx[b&0x0f]
		pos += 2
	}
	return string(out)
}
