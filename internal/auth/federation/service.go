package federation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/lusopoint/lusoiam/internal/federation"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

type Service struct {
	store *postgres.Store
}

func New(store *postgres.Store) *Service {
	return &Service{store: store}
}

// LinkOrCreate resolves the upstream Identity to an IAM User, creating
// or linking accounts as needed
//
// returns the IAM user and whether this was the first time we've seen
// this upstream identity (isNew=true -> optional "welcome" UX)
func (s *Service) LinkOrCreate(
	ctx context.Context,
	providerName string,
	identity *federation.Identity,
) (user *postgres.User, isNew bool, err error) {

	// known identity -> log in
	user, err = s.store.GetUserByProviderSub(ctx, providerName, identity.Sub)
	if err == nil {
		// refresh the cached profile fields (name, picture may have changed).
		if refreshErr := s.store.UpdateUserIdentity(ctx, postgres.UpdateUserIdentityParams{
			Provider:    providerName,
			Sub:         identity.Sub,
			Email:       emailPtr(identity.Email),
			DisplayName: namePtr(identity.Name),
			PictureURL:  picturePtr(identity.Picture),
			RawClaims:   identity.RawClaims,
		}); refreshErr != nil {
			slog.Warn("federation: refresh identity", "err", refreshErr)
		}
		if touchErr := s.store.TouchUserLastLogin(ctx, user.ID); touchErr != nil {
			slog.Warn("federation: touch last_login_at", "err", touchErr)
		}
		return user, false, nil
	}
	if !errors.Is(err, postgres.ErrNotFound) {
		return nil, false, fmt.Errorf("look up identity: %w", err)
	}

	// only trust email for auto linking when the provider itself already verified
	// an unverified claim is not proof of ownership, and linking on it would let
	// anyone who can get a provider to assert a victims email take over that victims account
	if identity.Email != "" && identity.EmailVerified {
		existing, emailErr := s.store.GetUserByEmail(ctx, identity.Email)
		if emailErr == nil {
			// auto-link: the email is already registered locally and the
			// provider verified it. We create the identity row to avoid
			// the lookup next time.
			if linkErr := s.createIdentity(ctx, existing, providerName, identity); linkErr != nil {
				slog.Warn("federation: auto-link identity", "err", linkErr)
				// non-fatal: the login still works; we'll retry next time.
			}
			if touchErr := s.store.TouchUserLastLogin(ctx, existing.ID); touchErr != nil {
				slog.Warn("federation: touch last_login_at", "err", touchErr)
			}
			slog.Info("federation: linked upstream identity to existing user",
				"provider", providerName, "user_id", existing.ID)
			return existing, false, nil
		}
		if !errors.Is(emailErr, postgres.ErrNotFound) {
			return nil, false, fmt.Errorf("look up user by email: %w", emailErr)
		}
	}

	email := emailPtr(identity.Email)
	name := namePtr(identity.Name)

	newUser, createErr := s.store.CreateUser(ctx, postgres.CreateUserParams{
		Email:       email,
		DisplayName: name,
	})
	if createErr != nil {
		return nil, false, fmt.Errorf("create user: %w", createErr)
	}

	if linkErr := s.createIdentity(ctx, newUser, providerName, identity); linkErr != nil {
		// this is serious, we created the user but couldn't link the identity
		// the user will be orphaned roll back the user row
		slog.Error("federation: create identity after user create, orphaned user",
			"user_id", newUser.ID, "provider", providerName, "err", linkErr)
		return nil, false, fmt.Errorf("create identity: %w", linkErr)
	}

	slog.Info("federation: created new user via upstream provider",
		"provider", providerName, "user_id", newUser.ID)
	return newUser, true, nil
}

func (s *Service) createIdentity(
	ctx context.Context,
	user *postgres.User,
	providerName string,
	identity *federation.Identity,
) error {
	_, err := s.store.CreateUserIdentity(ctx, postgres.CreateUserIdentityParams{
		UserID:      user.ID,
		Provider:    providerName,
		Sub:         identity.Sub,
		Email:       emailPtr(identity.Email),
		DisplayName: namePtr(identity.Name),
		PictureURL:  picturePtr(identity.Picture),
		RawClaims:   identity.RawClaims,
	})
	return err
}

func emailPtr(s string) *string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return nil
	}
	return &s
}

func namePtr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func picturePtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
