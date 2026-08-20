package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, lease Lease) error
	Get(ctx context.Context, id uuid.UUID) (Lease, error)
	UpdateExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error
	Revoke(ctx context.Context, id uuid.UUID, revokedAt time.Time) error
	ListActiveExpired(ctx context.Context, now time.Time) ([]Lease, error)
}
