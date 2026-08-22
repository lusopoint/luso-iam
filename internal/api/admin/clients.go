package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// client is the wire shape for an OIDC client note that the secret is never included
// admins receive the plaintext exactly once, in the rotate response, and must store it themselves
type clientDTO struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	RedirectURIs      []string `json:"redirect_uris"`
	AllowedScopes     []string `json:"allowed_scopes"`
	AllowedGrantTypes []string `json:"allowed_grant_types"`
	IsPublic          bool     `json:"is_public"`
	RequirePKCE       bool     `json:"require_pkce"`
	RequireConsent    bool     `json:"require_consent"`
	RequireAllowlist  bool     `json:"require_allowlist"`
	// go duration string, ex "1h"
	AccessTokenTTL  string `json:"access_token_ttl"`
	RefreshTokenTTL string `json:"refresh_token_ttl"`
	IDTokenTTL      string `json:"id_token_ttl"`
	Enabled         bool   `json:"enabled"`
	HasSecret       bool   `json:"has_secret"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

func toClientDTO(c *postgres.OIDCClient) clientDTO {
	return clientDTO{
		ID:                c.ID,
		Name:              c.Name,
		RedirectURIs:      c.RedirectURIs,
		AllowedScopes:     c.AllowedScopes,
		AllowedGrantTypes: c.AllowedGrantTypes,
		IsPublic:          c.IsPublic,
		RequirePKCE:       c.RequirePKCE,
		RequireConsent:    c.RequireConsent,
		RequireAllowlist:  c.RequireAllowlist,
		AccessTokenTTL:    c.AccessTokenTTL.String(),
		RefreshTokenTTL:   c.RefreshTokenTTL.String(),
		IDTokenTTL:        c.IDTokenTTL.String(),
		Enabled:           c.Enabled,
		HasSecret:         c.SecretHash != nil,
		CreatedAt:         c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:         c.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// GET /admin/v1/clients
func (h *Handler) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.store.ListOIDCClients(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list clients.")
		return
	}
	out := make([]clientDTO, 0, len(clients))
	for i := range clients {
		out = append(out, toClientDTO(&clients[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

// GET /admin/v1/clients/{id}
func (h *Handler) getClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.store.GetOIDCClientAny(r.Context(), id)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Client not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load client.")
		return
	}
	writeJSON(w, http.StatusOK, toClientDTO(c))
}

type createClientRequest struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	RedirectURIs      []string `json:"redirect_uris"`
	AllowedScopes     []string `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes []string `json:"allowed_grant_types,omitempty"`
	IsPublic          bool     `json:"is_public"`
	RequirePKCE       *bool    `json:"require_pkce,omitempty"`
	RequireConsent    bool     `json:"require_consent"`
	AccessTokenTTL    string   `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL   string   `json:"refresh_token_ttl,omitempty"`
	IDTokenTTL        string   `json:"id_token_ttl,omitempty"`
}

// createClientResponse echoes the new client DTO plus a one-time plaintext
// secret for confidential clients. The SPA must capture this immediately
type createClientResponse struct {
	Client clientDTO `json:"client"`
	Secret string    `json:"secret,omitempty"`
}

// POST /admin/v1/clients
func (h *Handler) createClient(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}
	if err := validateNewClient(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}

	// Defaults
	scopes := req.AllowedScopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	grants := req.AllowedGrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	requirePKCE := true
	if req.RequirePKCE != nil {
		requirePKCE = *req.RequirePKCE
	}
	// public clients always require PKCE
	if req.IsPublic {
		requirePKCE = true
	}

	accessTTL, err := parseDurationOr(req.AccessTokenTTL, time.Hour)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_ttl",
			"access_token_ttl: "+err.Error())
		return
	}
	refreshTTL, err := parseDurationOr(req.RefreshTokenTTL, 30*24*time.Hour)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_ttl",
			"refresh_token_ttl: "+err.Error())
		return
	}
	idTTL, err := parseDurationOr(req.IDTokenTTL, time.Hour)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_ttl",
			"id_token_ttl: "+err.Error())
		return
	}

	// generate secret for confidential clients
	var plaintext string
	var secretHash *string
	if !req.IsPublic {
		s, err := crypto.RandomToken(32)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"Could not generate client secret.")
			return
		}
		plaintext = s
		hash, err := crypto.HashPassword(s)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"Could not hash client secret.")
			return
		}
		secretHash = &hash
	}

	c, err := h.store.CreateOIDCClient(r.Context(), postgres.CreateOIDCClientParams{
		ID:                req.ID,
		SecretHash:        secretHash,
		Name:              req.Name,
		RedirectURIs:      req.RedirectURIs,
		AllowedScopes:     scopes,
		AllowedGrantTypes: grants,
		IsPublic:          req.IsPublic,
		RequirePKCE:       requirePKCE,
		RequireConsent:    req.RequireConsent,
		AccessTokenTTL:    accessTTL,
		RefreshTokenTTL:   refreshTTL,
		IDTokenTTL:        idTTL,
	})
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "create_failed",
			"Could not create client. Is the id already in use?")
		return
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventClientCreated, Actor: &actor.ID,
		Metadata: map[string]any{"client_id": c.ID, "public": c.IsPublic},
	}))

	writeJSON(w, http.StatusCreated, createClientResponse{
		Client: toClientDTO(c),
		Secret: plaintext, // empty string for public clients
	})
}

// Update
type updateClientRequest struct {
	Name              *string   `json:"name,omitempty"`
	RedirectURIs      *[]string `json:"redirect_uris,omitempty"`
	AllowedScopes     *[]string `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes *[]string `json:"allowed_grant_types,omitempty"`
	RequirePKCE       *bool     `json:"require_pkce,omitempty"`
	RequireConsent    *bool     `json:"require_consent,omitempty"`
	RequireAllowlist  *bool     `json:"require_allowlist,omitempty"`
	Enabled           *bool     `json:"enabled,omitempty"`
}

// PATCH /admin/v1/clients/{id}
func (h *Handler) updateClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateClientRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}
	c, err := h.store.UpdateOIDCClient(r.Context(), postgres.UpdateOIDCClientParams{
		ID:                id,
		Name:              req.Name,
		RedirectURIs:      req.RedirectURIs,
		AllowedScopes:     req.AllowedScopes,
		AllowedGrantTypes: req.AllowedGrantTypes,
		RequirePKCE:       req.RequirePKCE,
		RequireConsent:    req.RequireConsent,
		RequireAllowlist:  req.RequireAllowlist,
		Enabled:           req.Enabled,
	})
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Client not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not update client.")
		return
	}
	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventClientUpdated, Actor: &actor.ID,
		Metadata: map[string]any{"client_id": c.ID},
	}))
	writeJSON(w, http.StatusOK, toClientDTO(c))
}

// DELETE /admin/v1/clients/{id}
func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.SoftDeleteOIDCClient(r.Context(), id); err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Client not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not delete client.")
		return
	}
	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventClientDeleted, Actor: &actor.ID,
		Metadata: map[string]any{"client_id": id},
	}))
	w.WriteHeader(http.StatusNoContent)
}

// rotateSecretResponse carries the one-time plaintext secret
type rotateSecretResponse struct {
	Secret string `json:"secret"`
}

// POST /admin/v1/clients/{id}/rotate
func (h *Handler) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.store.GetOIDCClientAny(r.Context(), id)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Client not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load client.")
		return
	}
	if c.IsPublic {
		writeProblem(w, http.StatusBadRequest, "public_client",
			"Public clients do not have secrets.")
		return
	}

	plaintext, err := crypto.RandomToken(32)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not generate secret.")
		return
	}
	hash, err := crypto.HashPassword(plaintext)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not hash secret.")
		return
	}
	if err := h.store.RotateOIDCClientSecret(r.Context(), id, hash); err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not store new secret.")
		return
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventClientSecretRotated, Actor: &actor.ID,
		Metadata: map[string]any{"client_id": id},
	}))

	writeJSON(w, http.StatusOK, rotateSecretResponse{Secret: plaintext})
}

// validation
func validateNewClient(req *createClientRequest) error {
	if strings.TrimSpace(req.ID) == "" {
		return errInvalid("id is required")
	}
	if strings.ContainsAny(req.ID, " \t\n/?#") {
		return errInvalid("id must not contain whitespace or URL-reserved characters")
	}
	if strings.TrimSpace(req.Name) == "" {
		return errInvalid("name is required")
	}
	if len(req.RedirectURIs) == 0 {
		return errInvalid("at least one redirect_uri is required")
	}
	for _, u := range req.RedirectURIs {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return errInvalid("redirect_uris must be absolute http(s) URLs")
		}
	}
	return nil
}

type errInvalidVal string

func (e errInvalidVal) Error() string { return string(e) }
func errInvalid(msg string) error     { return errInvalidVal(msg) }

// parseDurationOr returns d when s is empty, otherwise time.ParseDuration(s)
func parseDurationOr(s string, d time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return d, nil
	}
	return time.ParseDuration(s)
}
