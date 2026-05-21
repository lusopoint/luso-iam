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

// Federation admin endpoints. Two read-only surfaces plus one mutation:
//
//	GET    /admin/v1/federation/providers          — list configured providers
//	GET    /admin/v1/users/{id}/federation         — list a user's linked identities
//	DELETE /admin/v1/users/{id}/federation/{linkId} — unlink one identity
//
// Provider configuration itself is intentionally NOT manageable from the
// UI. Provider credentials are deployment-shaped (set once at boot, via
// env vars) and putting them in the database would widen the secret
// surface for marginal operator convenience. The UI just surfaces what's
// already wired up so admins can verify it without grepping env files.
//
// We don't expose client IDs either — they're not strictly secret, but
// the operator looking at this page doesn't need them for anything
// admin-shaped, and surfacing them would invite confusion ("why isn't
// my new client ID showing up?"). The page answers a single question:
// which providers can a user sign in with right now?

// Provider status

// providerDTO is the small public shape of a configured provider.
// Deliberately minimal: name, the friendly display label, and the
// redirect URI an admin would paste into the provider's console when
// registering the OAuth client.
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

// displayNameForProvider returns a polished label for a known slug, or
// title-cases the slug for unknown ones. Hard-coded for the providers
// that have an established brand capitalization ("GitHub", not "Github"),
// the rest fall through to Title-Case.
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
		// Replace underscores with spaces and Title-case each word.
		parts := strings.Split(slug, "_")
		for i, p := range parts {
			if len(p) > 0 {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
		return strings.Join(parts, " ")
	}
}

// Per-user federation

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
//
// Removes one provider link from a user. The lockout guard refuses the
// delete when removing this link would leave the user with no way to
// sign in:
//
//   - no password credential on file, AND
//   - this is their last (or only) federation identity
//
// In that case we return 409 Conflict with a code the SPA reads to show
// a friendlier "Set a password first" message. The admin can either
// trigger a password reset or use a different recovery path before
// retrying.
//
// We do NOT consider MFA enrollment in the lockout check. MFA is a
// second factor — without a first factor (password or federation) the
// user has no way to start authenticating, even with a perfectly valid
// TOTP secret. Skipping MFA here keeps the check focused on what
// actually unblocks login.
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

	// Load and verify ownership. Using a separate lookup over the
	// list+filter approach because the typical case has one or two
	// identities; the join cost isn't worth the cleanup.
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
		// 404, not 403: revealing "this exists but isn't yours" is a
		// minor probing oracle. The list endpoint is the legitimate
		// way to discover IDs.
		writeProblem(w, http.StatusNotFound, "not_found", "Identity not found.")
		return
	}

	// Lockout guard
	// Two checks: does the user have a password? And how many other
	// federation links would remain after this delete? If neither, we
	// refuse with a 409 + code the SPA can recognize.
	hasPassword, err := h.userHasPasswordCredential(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not check credentials.")
		return
	}
	if !hasPassword {
		// Need to ensure at least one OTHER identity will remain.
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

// userHasPasswordCredential reports whether the user has a usable
// password on file. "Usable" means the row exists; we don't try to
// distinguish a locked-but-set-password from an unlocked one — even a
// locked password can be administratively reset, so for lockout-check
// purposes any credential row counts as "they have a path".
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
