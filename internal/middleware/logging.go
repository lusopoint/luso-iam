package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// statusRecorder wraps ResponseWriter to capture the status code and bytes
// written for access logging, the zero value of status (200) is the
// default Go behavior when WriteHeader is never called
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

// AccessLog emits one structured log line per request after the handler completes
// logs are at info level for normal traffic, warn for 4xx, error for 5xx
// the trustedProxies argument controls how the client IP is derived from X-Forwarded-For headers
func AccessLog(logger *slog.Logger, trustedProxies *TrustedProxies) Middleware {
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
				"remote", clientIPFromTrustedProxies(trustedProxies, r),
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

// clientIPFromTrustedProxies returns the best client IP given a trusted proxy registry
// when tp is nil, falls back to the raw peer address
// the strictly correct default when no proxy is configured
//
// this used to be a standalone `clientIP` that unconditionally trusted X-Forwarded-For
// that was a security bug (any internet user could spoof their logged IP by setting the header)
// use TrustedProxies configured from the TRUSTED_PROXIES env var, or accept that audit
// logs and rate limits will key off the raw peer
func clientIPFromTrustedProxies(tp *TrustedProxies, r *http.Request) string {
	if tp == nil {
		return stripPort(r.RemoteAddr)
	}
	return tp.ClientIP(r)
}
