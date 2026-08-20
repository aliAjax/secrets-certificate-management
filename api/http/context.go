package httpapi

import "context"

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
