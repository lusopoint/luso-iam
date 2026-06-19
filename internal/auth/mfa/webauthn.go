package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// webauthnUser adapts a postgres.User + its credentials to the
// webauthn.User interface required by the library
// credentials are loaded lazily from the store on each ceremony never cached
// so revocations take effect immediately
type webauthnUser struct {
	id          []byte // raw 16-byte UUID the WebAuthn user handle
	name        string // username for the credential
	displayName string
	creds       []wa.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                   { return u.id }
func (u *webauthnUser) WebAuthnName() string                 { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string          { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []wa.Credential { return u.creds }
func (u *webauthnUser) WebAuthnIcon() string                 { return "" } // deprecated in spec

// buildWebAuthnUser loads the user and all confirmed WebAuthn methods
func (s *Service) buildWebAuthnUser(ctx context.Context, user *postgres.User) (*webauthnUser, []postgres.UserMFAMethod, error) {
	methods, err := s.store.ListConfirmedMFAMethods(ctx, user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("list methods: %w", err)
	}

	// filter to webauthn only and decode each credential blob
	creds := make([]wa.Credential, 0, len(methods))
	keep := make([]postgres.UserMFAMethod, 0, len(methods))
	for _, m := range methods {
		if m.Method != "webauthn" || len(m.Credential) == 0 {
			continue
		}
		var c wa.Credential
		if err := json.Unmarshal(m.Credential, &c); err != nil {
			// do not fail the whole ceremony we should log when we have a proper logger
			continue
		}
		creds = append(creds, c)
		keep = append(keep, m)
	}

	username := ""
	if user.Email != nil {
		username = *user.Email
	} else if user.Username != nil {
		username = *user.Username
	}
	display := username
	if user.DisplayName != nil {
		display = *user.DisplayName
	}

	return &webauthnUser{
		id:          user.ID.Bytes[:],
		name:        username,
		displayName: display,
		creds:       creds,
	}, keep, nil
}

const webauthnSessionCookieName = "iam_webauthn_session"

// BeginWebAuthnRegistration starts the registration ceremony for a user
// returns the CredentialCreation options to send to the browsers
// navigator.credentials.create() call, the opaque session blob must be
// round-tripped to FinishWebAuthnRegistration via the response writer
func (s *Service) BeginWebAuthnRegistration(
	ctx context.Context, w http.ResponseWriter, user *postgres.User, secure bool,
) (*protocol.CredentialCreation, error) {
	if s.webauthn == nil {
		return nil, ErrWebAuthnDisabled
	}

	waUser, _, err := s.buildWebAuthnUser(ctx, user)
	if err != nil {
		return nil, err
	}

	opts, sessionData, err := s.webauthn.BeginRegistration(waUser)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin registration: %w", err)
	}

	if err := s.writeWebAuthnSession(w, secure, sessionData); err != nil {
		return nil, err
	}
	return opts, nil
}

// FinishWebAuthnRegistration completes the registration ceremony by
// verifying the browsers attestation response against the saved SessionData
// on success it persists the new credential as a confirmed WebAuthn method
func (s *Service) FinishWebAuthnRegistration(
	ctx context.Context, r *http.Request, w http.ResponseWriter, user *postgres.User, label string,
) (*postgres.UserMFAMethod, error) {
	if s.webauthn == nil {
		return nil, ErrWebAuthnDisabled
	}

	sessionData, err := s.readWebAuthnSession(r)
	if err != nil {
		return nil, err
	}

	waUser, _, err := s.buildWebAuthnUser(ctx, user)
	if err != nil {
		return nil, err
	}

	parsed, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}

	cred, err := s.webauthn.CreateCredential(waUser, *sessionData, parsed)
	if err != nil {
		return nil, fmt.Errorf("verify attestation: %w", err)
	}

	// clear the session cookie now that we are done with it
	s.clearWebAuthnSession(w, secureFromRequest(r))

	blob, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("encode credential: %w", err)
	}

	var name *string
	if label != "" {
		name = &label
	}

	method, err := s.store.CreateWebAuthnMethod(ctx, postgres.CreateWebAuthnMethodParams{
		UserID:     user.ID,
		Name:       name,
		Credential: blob,
		Counter:    int64(cred.Authenticator.SignCount),
	})
	if err != nil {
		return nil, fmt.Errorf("persist credential: %w", err)
	}
	return method, nil
}

// BeginWebAuthnLogin starts the assertion ceremony for an already-known user
// example when they aredy had typed their password
// Returns the CredentialAssertion options for navigator.credentials.get()
func (s *Service) BeginWebAuthnLogin(
	ctx context.Context, w http.ResponseWriter, user *postgres.User, secure bool,
) (*protocol.CredentialAssertion, error) {
	if s.webauthn == nil {
		return nil, ErrWebAuthnDisabled
	}

	waUser, methods, err := s.buildWebAuthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	if len(methods) == 0 {
		return nil, ErrNoMethods
	}

	opts, sessionData, err := s.webauthn.BeginLogin(waUser)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin login: %w", err)
	}
	if err := s.writeWebAuthnSession(w, secure, sessionData); err != nil {
		return nil, err
	}
	return opts, nil
}

// FinishWebAuthnLogin completes the assertion ceremony, on success it
// returns the matching credentials method id so the caller can update
// last_used_at and the sign counter
func (s *Service) FinishWebAuthnLogin(
	ctx context.Context, r *http.Request, w http.ResponseWriter, user *postgres.User,
) (*postgres.UserMFAMethod, error) {
	if s.webauthn == nil {
		return nil, ErrWebAuthnDisabled
	}

	sessionData, err := s.readWebAuthnSession(r)
	if err != nil {
		return nil, err
	}

	waUser, methods, err := s.buildWebAuthnUser(ctx, user)
	if err != nil {
		return nil, err
	}

	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, fmt.Errorf("parse assertion: %w", err)
	}

	cred, err := s.webauthn.ValidateLogin(waUser, *sessionData, parsed)
	if err != nil {
		return nil, fmt.Errorf("verify assertion: %w", err)
	}
	s.clearWebAuthnSession(w, secureFromRequest(r))

	// find the matching method row to update its counter
	for i := range methods {
		var stored wa.Credential
		if err := json.Unmarshal(methods[i].Credential, &stored); err != nil {
			continue
		}
		if string(stored.ID) == string(cred.ID) {
			_ = s.store.UpdateWebAuthnCounter(ctx, methods[i].ID,
				int64(cred.Authenticator.SignCount))
			return &methods[i], nil
		}
	}
	// library verified it, but we can't find the row should never happen
	return nil, errors.New("mfa: webauthn credential not found after verification")
}

// writeWebAuthnSession persists the ceremony state in a signed cookie
func (s *Service) writeWebAuthnSession(w http.ResponseWriter, secure bool, sd *wa.SessionData) error {
	blob, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("encode session data: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnSessionCookieName,
		Value:    s.signer.Sign(string(blob)),
		Path:     "/",
		MaxAge:   300, // 5 min long enough for a touch, short enough to limit abuse
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Service) readWebAuthnSession(r *http.Request) (*wa.SessionData, error) {
	c, err := r.Cookie(webauthnSessionCookieName)
	if err != nil {
		return nil, errors.New("mfa: webauthn session expired; please retry")
	}
	payload, err := s.signer.Verify(c.Value)
	if err != nil {
		return nil, errors.New("mfa: invalid webauthn session")
	}
	var sd wa.SessionData
	if err := json.Unmarshal([]byte(payload), &sd); err != nil {
		return nil, errors.New("mfa: malformed webauthn session")
	}
	return &sd, nil
}

func (s *Service) clearWebAuthnSession(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// secureFromRequest infers whether to set the Secure flag based on the
// request scheme used when we don't have the config-derived value in scope
// TLS on r or X-Forwarded-Proto=https both qualify
func secureFromRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
