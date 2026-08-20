package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientPreservesHTTPStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-9")
		w.Header().Set("Retry-After", "3")
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	var target *HTTPStatusError
	err := NewClient(server.URL, "", "").Do(context.Background(), http.MethodGet, "/secret", nil, nil)
	if !errors.As(err, &target) || target.StatusCode != http.StatusForbidden || target.Body == "" || target.RequestID != "req-9" || target.RetryAfter != "3" || target.Kind != "forbidden" || !errors.Is(err, ErrForbidden) || target.Temporary() {
		t.Fatalf("lost status error: %v", err)
	}
}
