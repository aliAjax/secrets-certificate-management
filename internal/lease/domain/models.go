package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func ContextError(ctx context.Context) error { return nil }

type Lease struct {
	ID         uuid.UUID         `json:"id"`
	Namespace  string            `json:"namespace"`
	Path       string            `json:"path"`
	SecretID   uuid.UUID         `json:"secret_id"`
	TTLSeconds int64             `json:"ttl_seconds"`
	Renewable  bool              `json:"renewable"`
	ExpiresAt  time.Time         `json:"expires_at"`
	RevokedAt  *time.Time        `json:"revoked_at,omitempty"`
	Metadata   map[string]string `json:"metadata"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type CreateInput struct {
	Namespace string
	Path      string
	TTL       time.Duration
	Renewable bool
	Metadata  map[string]string
}

func (i *CreateInput) Normalize(defaultTTL, maxTTL time.Duration) error {
	if i.Namespace == "" || i.Path == "" {
		return fmt.Errorf("namespace and path are required")
	}
	if i.TTL <= 0 {
		i.TTL = defaultTTL
	}
	if i.TTL > maxTTL {
		return fmt.Errorf("lease ttl exceeds maximum")
	}
	if i.Metadata == nil {
		i.Metadata = map[string]string{}
	}
	return nil
}

func (l Lease) IsRevoked() bool {
	return l.RevokedAt != nil && !l.RevokedAt.IsZero()
}

func (l Lease) IsExpired(now time.Time) bool {
	return now.After(l.ExpiresAt)
}
