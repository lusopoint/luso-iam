package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// whats exposed:
//   - Go runtime + process collectors (free, via client_golang defaults)
//   - http_request_duration_seconds  histogram {method, route, status}
//   - http_requests_in_flight        gauge
//   - auth_logins_total              counter {result}
//   - auth_tokens_issued_total       counter {type}
//   - auth_mfa_challenges_total      counter {result}
//   - db_pool_*                      gauges (read from pgxpool.Stat())

type Metrics struct {
	registry *prometheus.Registry

	httpDuration *prometheus.HistogramVec
	httpInFlight prometheus.Gauge

	logins        *prometheus.CounterVec
	tokensIssued  *prometheus.CounterVec
	mfaChallenges *prometheus.CounterVec

	// db pool gauges, refreshed by a collector closure on each scrape
	dbPoolTotal    prometheus.Gauge
	dbPoolAcquired prometheus.Gauge
	dbPoolIdle     prometheus.Gauge
	dbPoolMax      prometheus.Gauge
}

// PoolStat is a transport struct mirroring the pgxpool stats
type PoolStat struct {
	Total    int32
	Acquired int32
	Idle     int32
	Max      int32
}

// PoolStatProvider is the subset of pgxpool.Pool we need for the db metrics
type PoolStatProvider interface {
	Stat() PoolStat
}

// statusCapture is a minimal ResponseWriter wrapper that records the status code
// kept private to this package, the logging middleware has its own
// equivalent and we dont share to avoid coupling the two
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (s *statusCapture) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,

		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "Duration of HTTP requests, by method, matched route, and status code.",
			// Buckets tuned for a web auth server: sub-ms static/health
			// responses up through slow password-hash logins (argon2 is
			// intentionally ~100-300ms) and the occasional slow query.
			Buckets: []float64{
				0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
				0.25, 0.5, 1, 2.5, 5, 10,
			},
		}, []string{"method", "route", "status"}),

		httpInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "Number of HTTP requests currently being served.",
		}),

		logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_logins_total",
			Help: "Login attempts, by result (success, failure, locked).",
		}, []string{"result"}),

		tokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_tokens_issued_total",
			Help: "Tokens issued, by type (access, refresh, id, cas_ticket).",
		}, []string{"type"}),

		mfaChallenges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_mfa_challenges_total",
			Help: "MFA challenges, by result (success, failure).",
		}, []string{"result"}),

		dbPoolTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "db_pool_connections_total",
			Help: "Total connections currently in the pgx pool (acquired + idle).",
		}),
		dbPoolAcquired: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "db_pool_connections_acquired",
			Help: "Connections currently checked out of the pool.",
		}),
		dbPoolIdle: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "db_pool_connections_idle",
			Help: "Idle connections available in the pool.",
		}),
		dbPoolMax: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "db_pool_connections_max",
			Help: "Configured maximum pool size.",
		}),
	}

	// Free tier: Go runtime + process stats.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	reg.MustRegister(
		m.httpDuration,
		m.httpInFlight,
		m.logins,
		m.tokensIssued,
		m.mfaChallenges,
		m.dbPoolTotal,
		m.dbPoolAcquired,
		m.dbPoolIdle,
		m.dbPoolMax,
	)
	return m
}

// wired at GET /metrics
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// BindPool wires a pgx pools live stats into the DB gauges, the gauges are
// refreshed on every scrape via a registered collector func, so the values
// are always current at read time rather than sampled on a timer
func (m *Metrics) BindPool(p PoolStatProvider) {
	if p == nil {
		return
	}
	// register a collector that refreshes the gauges right before they get
	// prometheus calls the gauges collect on scrape
	// we hook in by wrapping with a custom collector closure
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "db_pool_scrape_refresh",
		Help: "Internal: refreshes db pool gauges on scrape. Value is always 1.",
	}, func() float64 {
		st := p.Stat()
		m.dbPoolTotal.Set(float64(st.Total))
		m.dbPoolAcquired.Set(float64(st.Acquired))
		m.dbPoolIdle.Set(float64(st.Idle))
		m.dbPoolMax.Set(float64(st.Max))
		return 1
	}))
}

// HTTPMiddleware records request duration and in-flight count
// must run inside the mux match so r.Pattern is populated!
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.httpInFlight.Inc()
		defer m.httpInFlight.Dec()

		rec := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		route := r.Pattern
		if route == "" {
			route = "<unmatched>"
		}

		m.httpDuration.WithLabelValues(
			r.Method,
			route,
			strconv.Itoa(rec.status),
		).Observe(time.Since(start).Seconds())
	})
}

// these are the only metrics that require touching auth code
// Each is a single call at a point the auth packages already branch on

// login result label values
const (
	LoginSuccess = "success"
	LoginFailure = "failure"
	LoginLocked  = "locked"
)

// token type label values
const (
	TokenAccess  = "access"
	TokenRefresh = "refresh"
	TokenID      = "id"
	TokenCAS     = "cas_ticket"
)

// MFA result label values
const (
	MFASuccess = "success"
	MFAFailure = "failure"
)

// RecordLogin increments the login counter for the given result
func (m *Metrics) RecordLogin(result string) {
	m.logins.WithLabelValues(result).Inc()
}

// RecordTokenIssued increments the token counter for the given type
func (m *Metrics) RecordTokenIssued(tokenType string) {
	m.tokensIssued.WithLabelValues(tokenType).Inc()
}

// RecordMFAChallenge increments the MFA counter for the given result
func (m *Metrics) RecordMFAChallenge(result string) {
	m.mfaChallenges.WithLabelValues(result).Inc()
}
