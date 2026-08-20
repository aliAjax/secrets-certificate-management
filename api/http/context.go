package httpapi

import (
	"context"
	"net/http"
)

type contextKey string

const (
	actorKey     contextKey = "actor"
	requestIDKey contextKey = "request_id"
)

func actorFromContext(ctx context.Context) string {
	value, _ := ctx.Value(actorKey).(string)
	if value == "" {
		return "anonymous"
	}
	return value
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func rateLimitKeyFromRequest(r *http.Request) string {
	if r == nil {
		return "anonymous"
	}
	if value := r.Header.Get("X-Forwarded-For"); value != "" {
		return normalizeRateLimitIdentity(value)
	}
	return normalizeRateLimitIdentity(r.RemoteAddr)
}
