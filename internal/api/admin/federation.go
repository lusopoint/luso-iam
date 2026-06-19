package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// federation admin endpoints
type providerDTO struct {
	Name        string `json:"name"`         // slug: "google", "github", ...
	DisplayName string `json:"display_name"` // "Google", "GitHub", ...
	RedirectURI string `json:"redirect_uri"`
}

type listProvidersResponse struct {
	Providers []providerDTO `json:"providers"`
}

// GET /admin/v1/federation/providers
func (h *Handler) listFederationProviders(w http.ResponseWriter, r *http.Request) {
	out := listProvidersResponse{Providers: []providerDTO{}}
	if h.federation == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	base := strings.TrimRight(h.baseURL, "/")
	for _, p := range h.federation.All() {
		name := p.Name()
		out.Providers = append(out.Providers, providerDTO{
			Name:        name,
			DisplayName: displayNameForProvider(name),
			RedirectURI: base + "/oauth/callback/" + name,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func displayNameForProvider(slug string) string {
	switch slug {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	case "gitlab":
		return "GitLab"
	case "microsoft":
		return "Microsoft"
	case "apple":
		return "Apple"
	case "generic_oidc":
		return "Generic OIDC"
	default:
		if slug == "" {
			return ""
		}
		// replace underscores with spaces and title-case each word
		parts := strings.Split(slug, "_")
		for i, p := range parts {
			if len(p) > 0 {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
		return strings.Join(parts, " ")
	}
}

// per user federation
type userFederationDTO struct {
	ID           string  `json:"id"`
	Provider     string  `json:"provider"`
	DisplayName  string  `json:"display_name"` // pretty provider label
	Sub          string  `json:"sub"`
	Email        *string `json:"email,omitempty"`
	ProviderName *string `json:"provider_name,omitempty"` // user's name as known by the provider
	PictureURL   *string `json:"picture_url,omitempty"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}

type listUserFederationResponse struct {
	Identities []userFederationDTO `json:"identities"`
}

// GET /admin/v1/users/{id}/federation
func (h *Handler) listUserFederation(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	identities, err := h.store.ListUserIdentities(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list identities.")
		return
	}
	out := listUserFederationResponse{
		Identities: make([]userFederationDTO, 0, len(identities)),
	}
	for _, ui := range identities {
		out.Identities = append(out.Identities, toUserFederationDTO(ui))
	}
	writeJSON(w, http.StatusOK, out)
}

func toUserFederationDTO(ui postgres.UserIdentity) userFederationDTO {
	return userFederationDTO{
		ID:           uuidString(ui.ID),
		Provider:     ui.Provider,
		DisplayName:  displayNameForProvider(ui.Provider),
		Sub:          ui.Sub,
		Email:        ui.Email,
		ProviderName: ui.DisplayName,
		PictureURL:   ui.PictureURL,
		CreatedAt:    ui.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:    ui.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// Unlink
// DELETE /admin/v1/users/{id}/federation/{linkId}
func (h *Handler) unlinkUserFederation(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	linkID, ok := parseUUID(r.PathValue("linkId"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid link id.")
		return
	}

	// load and verify ownership using a separate lookup over the
	// list+filter approach because the typical case has one or two
	// identities, the join cost isn't worth the cleanup
	link, err := h.store.GetUserIdentityByID(r.Context(), linkID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Identity not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load identity.")
		return
	}
	if link.UserID.Bytes != userID.Bytes {
		writeProblem(w, http.StatusNotFound, "not_found", "Identity not found.")
		return
	}

	hasPassword, err := h.userHasPasswordCredential(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not check credentials.")
		return
	}
	if !hasPassword {
		// need to ensure at least one OTHER identity will remain
		others, err := h.store.ListUserIdentities(r.Context(), userID)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"Could not list identities.")
			return
		}
		remaining := 0
		for _, o := range others {
			if o.ID.Bytes != link.ID.Bytes {
				remaining++
			}
		}
		if remaining == 0 {
			writeProblem(w, http.StatusConflict, "would_lock_out",
				"Removing this identity would leave the user with no way to sign in. "+
					"Reset their password first, then retry.")
			return
		}
	}

	if err := h.store.DeleteUserIdentity(r.Context(), linkID); err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not delete identity.")
		return
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:   audit.EventUpstreamUnlinked,
		Actor:  &actor.ID,
		Target: &userID,
		Metadata: map[string]any{
			"provider":    link.Provider,
			"sub":         link.Sub,
			"unlinked_by": "admin",
		},
	}))

	w.WriteHeader(http.StatusNoContent)
}

// userHasPasswordCredential reports whether the user has a usable password on file
// "usable" means the row exists, we don't try to distinguish a locked but set password from an unlocked one
func (h *Handler) userHasPasswordCredential(ctx context.Context, userID pgtype.UUID) (bool, error) {
	_, err := h.store.GetCredential(ctx, userID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, postgres.ErrNotFound) {
		return false, nil
	}
	return false, err
}
