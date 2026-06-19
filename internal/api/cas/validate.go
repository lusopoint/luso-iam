package cas

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	pkgcas "github.com/lusopoint/lusoiam/pkg/cas"
)

// CAS 1.0 is retained for legacy clients. New integrations should use
// /cas/serviceValidate or /cas/p3/serviceValidate
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
// Response format follows the `format` query parameter:
//   - `format=json`  -> Apereo-compatible JSON
//   - anything else  -> the canonical XML response (default)
func (h *Handler) serviceValidate(p3 bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service := r.URL.Query().Get("service")
		ticket := r.URL.Query().Get("ticket")
		jsonFormat := r.URL.Query().Get("format") == "json"

		// Spec requires both parameters.
		if service == "" || ticket == "" {
			writeFailure(w, jsonFormat, pkgcas.FailureInvalidRequest,
				"Required parameters 'service' and 'ticket' are missing.")
			return
		}

		result, err := h.cas.Validate(r.Context(), ticket, service)
		if err != nil {
			code, msg := casErrorToXML(err)
			writeFailure(w, jsonFormat, code, msg)
			return
		}

		var attrs map[string]string
		if p3 {
			attrs = releaseAttributes(result)
		}
		writeSuccess(w, jsonFormat, principalName(result), attrs)
	}
}

// writeSuccess dispatches to JSON or XML based on the format flag.
func writeSuccess(w http.ResponseWriter, jsonFormat bool, user string, attrs map[string]string) {
	if jsonFormat {
		body, err := marshalJSONSuccess(user, attrs)
		if err != nil {
			// Shouldn't happen — our types are JSON-clean. Fall through
			// to a generic 500 rather than a malformed envelope.
			http.Error(w, "could not encode response", http.StatusInternalServerError)
			return
		}
		writeJSON(w, body)
		return
	}
	writeXMLSuccess(w, pkgcas.NewSuccess(user, attrs))
}

// writeFailure dispatches to JSON or XML based on the format flag.
func writeFailure(w http.ResponseWriter, jsonFormat bool, code, message string) {
	if jsonFormat {
		body, err := marshalJSONFailure(code, message)
		if err != nil {
			http.Error(w, "could not encode response", http.StatusInternalServerError)
			return
		}
		writeJSON(w, body)
		return
	}
	writeXMLFailure(w, code, message)
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// XML writers (kept for the default path)

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

// principalName returns the CAS principal identifier for the user
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
	if result.User.Username != nil {
		all["username"] = *result.User.Username
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
// low to avoid leaking information to service back-channels
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
