package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestSlidingWindowLimiterPerClient(t *testing.T) {
	limiter := newSlidingWindowLimiter(1, 1)
	if !limiter.Allow("client-a") {
		t.Fatal("first client request was rejected")
	}
	if !limiter.Allow("client-b") {
		t.Fatal("different client should have its own burst")
	}
}

func TestSlidingWindowLimiterWindowIsolation(t *testing.T) {
	limiter := newSlidingWindowLimiter(2, 2)
	if !limiter.Allow("alpha") || !limiter.Allow("alpha") {
		t.Fatal("initial burst should be accepted")
	}
	if !limiter.Allow("beta") {
		t.Fatal("another client must not inherit alpha's count")
	}
}

func TestRateLimitKeyUsesFirstForwardedClient(t *testing.T) {
	req := httptest.NewRequest("GET", "/v1/secrets", nil)
	req.Header.Set("X-Forwarded-For", "Tenant-A, 10.0.0.2")
	if got, want := rateLimitKeyFromRequest(req), "tenant-a"; got != want {
		t.Fatalf("rate limit key = %q, want %q", got, want)
	}
}
