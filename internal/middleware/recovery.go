package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recovery turns a panic in any downstream handler into a 500 response and
// logs the stack at error level. Without this, a panic crashes the whole
// process.
func Recovery(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic recovered",
						"err", rec,
						"path", r.URL.Path,
						"method", r.Method,
						"request_id", RequestIDFromContext(r.Context()),
						"stack", string(debug.Stack()),
					)
					// Best-effort: if a response has already started, this
					// will be a no-op or produce a harmless error in logs.
					http.Error(w, `{"type":"about:blank","title":"Internal Server Error","status":500}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
