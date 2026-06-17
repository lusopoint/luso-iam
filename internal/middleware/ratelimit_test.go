package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestTrustedProxies_Contains pins the CIDR parsing and IP-matching rules.
// Bare IPs become /32 (or /128 for v6), CIDR ranges work, garbage is
// silently dropped (caller validates upstream).
func TestTrustedProxies_Contains(t *testing.T) {
	t.Parallel()

	tp := NewTrustedProxies("10.0.0.0/8, 192.168.1.1, 127.0.0.1, ::1, bogus, 2001:db8::/32")

	cases := []struct {
		ip   string
		want bool
	}{
		// /8 range
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		// bare IP → /32
		{"192.168.1.1", true},
		{"192.168.1.2", false},
		// loopback
		{"127.0.0.1", true},
		{"127.0.0.2", false},
		// IPv6
		{"::1", true},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
		// invalid
		{"not an ip", false},
		{"", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.ip, func(t *testing.T) {
			t.Parallel()
			got := tp.Contains(net.ParseIP(c.ip))
			if got != c.want {
				t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

// TestTrustedProxies_Nil: zero-value / nil receivers don't panic. Lets
// callers skip configuration without crashing the server.
func TestTrustedProxies_Nil(t *testing.T) {
	t.Parallel()
	var tp *TrustedProxies
	if tp.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("nil receiver should return false, not panic")
	}
}

// TestClientIP_NoXFF: the simple case. No X-Forwarded-For, return the
// TCP peer address (sans port).
func TestClientIP_NoXFF(t *testing.T) {
	t.Parallel()
	tp := NewTrustedProxies("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	if got := tp.ClientIP(r); got != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want 10.0.0.5", got)
	}
}

// TestClientIP_UntrustedPeerIgnoresXFF: if the immediate peer is NOT
// in TrustedProxies, the XFF header is ignored entirely. This is the
// crucial security property: an internet user can't forge their IP by
// setting X-Forwarded-For.
func TestClientIP_UntrustedPeerIgnoresXFF(t *testing.T) {
	t.Parallel()
	tp := NewTrustedProxies("10.0.0.0/8") // only LAN trusted
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:54321"           // attacker on the internet
	r.Header.Set("X-Forwarded-For", "10.0.0.99") // attacker tries to claim LAN origin
	got := tp.ClientIP(r)
	if got != "203.0.113.5" {
		t.Errorf("untrusted peer XFF was honored, bypass possible. got %q", got)
	}
}

// TestClientIP_TrustedProxyHonorsXFF: when the peer IS a trusted
// proxy, walk XFF right-to-left and return the first non-trusted IP.
// Real-world: the immediate peer is the LB, XFF chain is [client, lb1].
func TestClientIP_TrustedProxyHonorsXFF(t *testing.T) {
	t.Parallel()
	tp := NewTrustedProxies("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.1")
	got := tp.ClientIP(r)
	if got != "203.0.113.42" {
		t.Errorf("expected real client 203.0.113.42, got %q", got)
	}
}

// TestClientIP_AllProxiesTrusted: edge case, every hop in XFF is
// internal. Probably means the request is fully internal too. Return
// the leftmost XFF entry as the best available guess.
func TestClientIP_AllProxiesTrusted(t *testing.T) {
	t.Parallel()
	tp := NewTrustedProxies("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	r.Header.Set("X-Forwarded-For", "10.0.0.50, 10.0.0.51")
	got := tp.ClientIP(r)
	if got != "10.0.0.50" {
		t.Errorf("expected leftmost of trusted chain (10.0.0.50), got %q", got)
	}
}

// TestClientIP_ChainedUntrustedSpoof: defense against the more
// sophisticated attack, the attacker is behind a trusted proxy AND
// sends a forged X-Forwarded-For. We walk from the right, so any IPs
// the attacker prepended themselves get ignored once we hit a
// non-trusted IP (which is them).
func TestClientIP_ChainedUntrustedSpoof(t *testing.T) {
	t.Parallel()
	tp := NewTrustedProxies("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	// Attacker at 203.0.113.42 sends "X-Forwarded-For: 1.2.3.4" trying
	// to look like 1.2.3.4. The trusted proxy appends 203.0.113.42 (the
	// real source) to the end. Final chain: "1.2.3.4, 203.0.113.42".
	// We walk right-to-left, first non-trusted is 203.0.113.42, the
	// real source. Spoof defeated.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.42")
	got := tp.ClientIP(r)
	if got != "203.0.113.42" {
		t.Errorf("XFF spoof not defeated, got %q, want 203.0.113.42", got)
	}
}

// ─── Limiter ──────────────────────────────────────────────────────────────

// TestLimiter_BelowLimit: requests under the cap all pass. Pretty
// basic; mostly here to anchor the API.
func TestLimiter_BelowLimit(t *testing.T) {
	t.Parallel()
	l := NewLimiter(5, time.Minute)
	defer l.Close()

	for i := 0; i < 5; i++ {
		ok, _ := l.Allow("ip:1.2.3.4")
		if !ok {
			t.Errorf("request %d was rejected; expected all 5 to pass", i+1)
		}
	}
}

// TestLimiter_ExceedsLimit: the 6th request in a 5/min window gets
// rejected with a sensible Retry-After.
func TestLimiter_ExceedsLimit(t *testing.T) {
	t.Parallel()
	l := NewLimiter(5, time.Minute)
	defer l.Close()

	for i := 0; i < 5; i++ {
		l.Allow("k")
	}
	ok, retry := l.Allow("k")
	if ok {
		t.Error("6th request was allowed; expected rejection")
	}
	if retry < 1 || retry > 60 {
		t.Errorf("Retry-After = %d, expected 1..60", retry)
	}
}

// TestLimiter_WindowReset: after the window passes, counts reset. Use
// a short window to keep the test fast.
func TestLimiter_WindowReset(t *testing.T) {
	t.Parallel()
	l := NewLimiter(2, 100*time.Millisecond)
	defer l.Close()

	l.Allow("k")
	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("3rd request should have been rejected")
	}

	time.Sleep(150 * time.Millisecond)

	if ok, _ := l.Allow("k"); !ok {
		t.Error("after window reset, request should be allowed again")
	}
}

// TestLimiter_KeysAreIndependent: different keys don't share buckets.
// Important: if we accidentally key on a constant, the limiter would
// apply globally and DOS the entire server when one key gets noisy.
func TestLimiter_KeysAreIndependent(t *testing.T) {
	t.Parallel()
	l := NewLimiter(2, time.Minute)
	defer l.Close()

	l.Allow("a")
	l.Allow("a")
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a's 3rd should be rejected")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Error("b's 1st should be allowed; key isolation broken")
	}
}

// TestLimiter_Middleware_Allow: green path through the middleware
// returns the inner handler's response untouched.
func TestLimiter_Middleware_Allow(t *testing.T) {
	t.Parallel()
	l := NewLimiter(5, time.Minute)
	defer l.Close()

	mw := l.Middleware(func(r *http.Request) string { return "k" })
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	srv := mw(inner)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest("POST", "/", nil))
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Errorf("inner handler not invoked: code=%d body=%q", rr.Code, rr.Body.String())
	}
}

// TestLimiter_Middleware_Reject: when over the limit, the inner
// handler must NOT be invoked, and we return 429 + Retry-After +
// problem+json body.
func TestLimiter_Middleware_Reject(t *testing.T) {
	t.Parallel()
	l := NewLimiter(1, time.Minute)
	defer l.Close()

	innerCalls := 0
	mw := l.Middleware(func(r *http.Request) string { return "k" })
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalls++
		w.WriteHeader(200)
	})
	srv := mw(inner)

	// First request consumes the quota.
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	if innerCalls != 1 {
		t.Fatalf("first request must reach inner; got %d calls", innerCalls)
	}

	// Second request must be rejected.
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest("POST", "/", nil))
	if rr.Code != 429 {
		t.Errorf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header on 429")
	}
	if got, _ := strconv.Atoi(rr.Header().Get("Retry-After")); got < 1 {
		t.Errorf("Retry-After should be ≥ 1 second; got %d", got)
	}
	if rr.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("expected problem+json body type, got %q", rr.Header().Get("Content-Type"))
	}
	if innerCalls != 1 {
		t.Errorf("inner handler invoked on rejected request: %d calls (should be 1)", innerCalls)
	}
}

// TestLimiter_Middleware_EmptyKeySkips: returning "" from the key
// function means "don't rate-limit this request." Useful for health
// endpoints, internal callers, etc.
func TestLimiter_Middleware_EmptyKeySkips(t *testing.T) {
	t.Parallel()
	l := NewLimiter(1, time.Minute)
	defer l.Close()

	calls := 0
	mw := l.Middleware(func(r *http.Request) string { return "" })
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++ })
	srv := mw(inner)

	// 10 requests, all should pass, empty key disables rate limiting.
	for i := 0; i < 10; i++ {
		srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	}
	if calls != 10 {
		t.Errorf("empty key should skip limiter; got %d calls expected 10", calls)
	}
}

// TestLimiter_ConcurrentAccess: race detector check. Hammer the
// limiter from multiple goroutines and ensure neither map corruption
// nor crash occurs.
func TestLimiter_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	l := NewLimiter(1000, time.Minute)
	defer l.Close()

	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "g" + strconv.Itoa(id)
			for i := 0; i < 100; i++ {
				l.Allow(key)
			}
		}(g)
	}
	wg.Wait()
	// Test passes if -race didn't complain.
}
