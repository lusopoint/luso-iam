package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDHeader is the canonical header used for tracing request IDs
// across the proxy and downstream services.
const RequestIDHeader = "X-Request-Id"

// RequestID either propagates an incoming X-Request-Id or generates a new
// 16-byte random ID, attaches it to the request context, and echoes it on
// the response so clients/proxies can correlate.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext returns the request ID set by the RequestID
// middleware, or "" if not present.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func newRequestID() string {
	var b [16]byte
	// crypto/rand.Read is documented to never fail on modern platforms;
	// if it ever did, returning an empty string is the least bad option
	// because we'd rather serve the request than fail it.
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
