package cas

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	pkgcas "github.com/lusopoint/lusoiam/pkg/cas"
)

// CAS 1.0

// v1Validate handles GET /cas/validate (CAS 1.0 protocol).
//
// Response format (always HTTP 200):
//
//	"yes\n<username>\n"  on success
//	"no\n\n"             on any failure
//
// CAS 1.0 is retained for legacy clients. New integrations should use
// /cas/serviceValidate or /cas/p3/serviceValidate.
func (h *Handler) v1Validate(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	ticket := r.URL.Query().Get("ticket")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	result, err := h.cas.Validate(r.Context(), ticket, service)
	if err != nil {
		fmt.Fprint(w, "no\n\n")
		return
	}
	fmt.Fprintf(w, "yes\n%s\n", principalName(result))
}

// CAS 2.0 / 3.0

// serviceValidate returns an http.HandlerFunc that validates a service
// ticket and returns a CAS XML response.
//
// When p3 is false (CAS 2.0), the <cas:attributes> block is omitted.
// When p3 is true (CAS 3.0), released attributes are included.
//
// HTTP status is always 200 — success/failure is communicated in the
// XML body per the CAS protocol specification.
func (h *Handler) serviceValidate(p3 bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service := r.URL.Query().Get("service")
		ticket := r.URL.Query().Get("ticket")

		// Spec requires both parameters.
		if service == "" || ticket == "" {
			writeXMLFailure(w, pkgcas.FailureInvalidRequest,
				"Required parameters 'service' and 'ticket' are missing.")
			return
		}

		result, err := h.cas.Validate(r.Context(), ticket, service)
		if err != nil {
			code, msg := casErrorToXML(err)
			writeXMLFailure(w, code, msg)
			return
		}

		// Build the success response.
		var attrs map[string]string
		if p3 {
			attrs = releaseAttributes(result)
		}
		writeXMLSuccess(w, pkgcas.NewSuccess(principalName(result), attrs))
	}
}

// XML writers

func writeXMLSuccess(w http.ResponseWriter, resp pkgcas.SuccessResponse) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// CAS always returns 200, even for validation failures.
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(resp)
}

func writeXMLFailure(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(pkgcas.NewFailure(code, message))
}

// Domain helpers

// principalName returns the CAS principal identifier for the user.
// Prefers username, falls back to email.
func principalName(result *authcas.ValidationResult) string {
	if result.User.Username != nil && *result.User.Username != "" {
		return *result.User.Username
	}
	if result.User.Email != nil {
		return *result.User.Email
	}
	return "" // should never happen given DB constraints
}

// releaseAttributes builds the attribute map to include in a CAS 3.0
// response. If the service has a specific release policy, only listed
// attributes are emitted; otherwise all base attributes are released.
func releaseAttributes(result *authcas.ValidationResult) map[string]string {
	// Collect all available base attributes.
	all := make(map[string]string, 4)
	if result.User.Email != nil {
		all["email"] = *result.User.Email
	}
	if result.User.DisplayName != nil {
		all["displayName"] = *result.User.DisplayName
	}

	// Apply the service's attribute release policy (if any).
	if result.Service == nil || len(result.Service.ReleasedAttributes) == 0 {
		// No policy: release everything.
		return all
	}

	// Whitelist: keep only what the service has asked for.
	allowed := make(map[string]bool, len(result.Service.ReleasedAttributes))
	for _, a := range result.Service.ReleasedAttributes {
		allowed[a] = true
	}
	filtered := make(map[string]string, len(allowed))
	for k, v := range all {
		if allowed[k] {
			filtered[k] = v
		}
	}
	return filtered
}

// casErrorToXML maps auth/cas sentinel errors to CAS protocol failure
// codes and human-readable messages. The detail level is intentionally
// low to avoid leaking information to service back-channels.
func casErrorToXML(err error) (code, message string) {
	switch {
	case errors.Is(err, authcas.ErrInvalidTicket):
		return pkgcas.FailureInvalidTicket,
			"Ticket not recognized, has expired, or has already been used."
	case errors.Is(err, authcas.ErrServiceMismatch):
		return pkgcas.FailureInvalidService,
			"Ticket was not issued for this service URL."
	case errors.Is(err, authcas.ErrUnauthorizedService):
		return pkgcas.FailureUnauthorizedService,
			"The requested service is not authorized to use this CAS server."
	default:
		return pkgcas.FailureInternalError,
			"An internal error occurred during ticket validation."
	}
}
