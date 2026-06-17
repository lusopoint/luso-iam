package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// construct once at server start, share across handlers
type TrustedProxies struct {
	nets []*net.IPNet
}

// NewTrustedProxies parses a comma separated list of CIDR(Classless Inter-Domain Routing) ranges
// invalid entries are skipped silently
// (caller should validate the config upstream if strict behaviour is required)
func NewTrustedProxies(csv string) *TrustedProxies {
	tp := &TrustedProxies{}
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// bare IP (no /mask), treat as /32 for IPv4 or /128 for IPv6.
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				item += "/32"
			} else {
				item += "/128"
			}
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			continue
		}
		tp.nets = append(tp.nets, n)
	}
	return tp
}

// Contains reports whether the given IP address is in any trusted range
func (t *TrustedProxies) Contains(ip net.IP) bool {
	if t == nil || ip == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the real source IP of the request
// if the remote address (r.RemoteAddr) is a trusted proxy, walks X-Forwarded-For from
// right to left, returning the first IP that isn't itself a trusted proxy
// otherwise returns RemoteAddr directly
//
// right-to-left, because XFF accumulates proxies left-to-right, with the
// real client at the leftmost position we trust only entries appended by our own proxies
func (t *TrustedProxies) ClientIP(r *http.Request) string {
	peer := stripPort(r.RemoteAddr)
	peerIP := net.ParseIP(peer)

	// untrusted peer, ignore any XFF they sent
	if !t.Contains(peerIP) {
		return peer
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}

	// walk XFF right to left, the closest to us entries are the most
	// trustworthy because they were appended by proxies we trust
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		if !t.Contains(ip) {
			// first non trusted entry walking back, real client
			return candidate
		}
	}

	// return the leftmost entry as the best guess.
	return strings.TrimSpace(parts[0])
}

func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// bucket is one rate limit window for a single key (IP, client_id, ...)
// using a fixed window counter rather than a token bucket:
// - simpler to reason about
// - good for the brute force protection use case
type bucket struct {
	count       int
	windowStart time.Time
	lastSeen    time.Time
}

// Limiter is a fixed window rate limiter keyed
// the KeyFunc passed to Middleware decides what to limit on:
// IP, client ID, username
//
// a background go routine revokes buckets idle > evictAfter
// even at 100k unique daily users, each entry is ~64 bytes, so under 10 MB
type Limiter struct {
	limit      int
	window     time.Duration
	evictAfter time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
	// closed by Close() to signal the evictor to quit
	stop chan struct{}
}

// limit, requests permitted per window
// window, duration of the counting window (example 1 minute)
func NewLimiter(limit int, window time.Duration) *Limiter {
	l := &Limiter{
		limit:      limit,
		window:     window,
		evictAfter: window * 10, // bucket idle for 10x the window, evicted
		buckets:    make(map[string]*bucket),
		stop:       make(chan struct{}),
	}
	go l.evictLoop()
	return l
}

// Close stops the background eviction goroutine
// we should be careful when closing, because limiter still functions
// make the memory grwo without bounds!
func (l *Limiter) Close() {
	close(l.stop)
}

// Allow throws if no more requests can go throuhg if false, retryAfter(s) is the suggested
func (l *Limiter) Allow(key string) (allowed bool, retryAfter int) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{count: 1, windowStart: now, lastSeen: now}
		return true, 0
	}

	// window expired, we should reset
	if now.Sub(b.windowStart) >= l.window {
		b.count = 1
		b.windowStart = now
		b.lastSeen = now
		return true, 0
	}

	b.lastSeen = now
	if b.count < l.limit {
		b.count++
		return true, 0
	}

	// over the limit, tell the caller how long until the window resets
	remain := l.window - now.Sub(b.windowStart)
	secs := int(remain.Seconds())
	if remain%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return false, secs
}

// evictLoop periodically removes buckets that have not been touched in evictAfter
// tuns at every evictAfter/4 so even short lived limiters get cleaned up
func (l *Limiter) evictLoop() {
	interval := l.evictAfter / 4
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			l.mu.Lock()
			for k, b := range l.buckets {
				if now.Sub(b.lastSeen) > l.evictAfter {
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

// KeyFunc decides what to rate limit on for a given request
type KeyFunc func(r *http.Request) string

// Middleware wraps an http.Handler with rate limit
// returns 429 with a Retry-After header
func (l *Limiter) Middleware(keyFn KeyFunc) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				// empty key, skip rate limiting for this request
				next.ServeHTTP(w, r)
				return
			}
			ok, retry := l.Allow(key)
			if !ok {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"type":"about:blank","title":"Too Many Requests","status":429,"detail":"rate limit exceeded; retry after the period in the Retry-After header"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
