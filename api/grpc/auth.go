package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const actorKey contextKey = "actor"

func (s *Server) authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	token := firstMetadata(md, s.config.Auth.TokenHeader)
	identity := firstMetadata(md, s.config.Auth.IdentityHeader)
	if token == "" && identity == "" {
		return nil, status.Error(codes.Unauthenticated, "missing credentials")
	}
	actor := identity
	if token == s.config.Auth.AdminToken {
		actor = "admin"
	}
	if actor == "" {
		actor = token
	}
	ctx = context.WithValue(ctx, actorKey, strings.TrimSpace(actor))
	return handler(ctx, req)
}

func actorFromContext(ctx context.Context) string {
	value, _ := ctx.Value(actorKey).(string)
	if value == "" {
		return "anonymous"
	}
	return value
}

func firstMetadata(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
