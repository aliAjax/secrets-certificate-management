package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

var (
	errUnauthorized    = errors.New("unauthorized")
	errForbidden       = errors.New("forbidden")
	errTooManyRequests = errors.New("rate limit exceeded")
	errInternal        = errors.New("internal server error")
)

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get(s.config.Auth.TokenHeader)
		identity := r.Header.Get(s.config.Auth.IdentityHeader)
		if token == "" && identity == "" {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		actor := identity
		if token == s.config.Auth.AdminToken {
			actor = "admin"
		}
		if actor == "" {
			actor = token
		}
		ctx := context.WithValue(r.Context(), actorKey, strings.TrimSpace(actor))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func normalizeRateLimitIdentity(value string) string {
	value = firstForwardedIdentity(value)
	if value == "" {
		return "anonymous"
	}
	return value
}
