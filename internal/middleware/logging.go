package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// statusRecorder wraps ResponseWriter to capture the status code and bytes
// written for access logging. The zero value of status (200) is the
// default Go behavior when WriteHeader is never called.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// AccessLog emits one structured log line per request after the handler
// completes. Logs are at info level for normal traffic, warn for 4xx, error
// for 5xx.
func AccessLog(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", clientIP(r),
				"request_id", RequestIDFromContext(r.Context()),
			}

			switch {
			case rec.status >= 500:
				logger.Error("http", attrs...)
			case rec.status >= 400:
				logger.Warn("http", attrs...)
			default:
				logger.Info("http", attrs...)
			}
		})
	}
}

// clientIP returns the best-effort client IP. It trusts X-Forwarded-For
// only when present — this is fine when running behind a known proxy
// (Caddy/Traefik). Anything stricter belongs in a dedicated trust layer.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first hop.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	return r.RemoteAddr
}
