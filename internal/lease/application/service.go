package application

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	leasedomain "github.com/example/secrets-cert-platform/internal/lease/domain"
	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

type Service struct {
	leases     leasedomain.Repository
	secrets    secretdomain.Repository
	defaultTTL time.Duration
	maxTTL     time.Duration
}

func NewService(leases leasedomain.Repository, secrets secretdomain.Repository, defaultTTL, maxTTL time.Duration) *Service {
	return &Service{leases: leases, secrets: secrets, defaultTTL: defaultTTL, maxTTL: maxTTL}
}

func (s *Service) Create(ctx context.Context, input leasedomain.CreateInput) (leasedomain.Lease, error) {
	if err := input.Normalize(s.defaultTTL, s.maxTTL); err != nil {
		return leasedomain.Lease{}, err
	}
	secret, err := s.secrets.GetSecret(ctx, input.Namespace, input.Path)
	if err != nil {
		return leasedomain.Lease{}, fmt.Errorf("secret must exist before creating lease: %w", err)
	}
	if secret.Type != secretdomain.SecretTypeDynamic {
		return leasedomain.Lease{}, fmt.Errorf("leases can only be created for dynamic secrets")
	}
	now := time.Now().UTC()
	lease := leasedomain.Lease{
		ID:         uuid.New(),
		Namespace:  input.Namespace,
		Path:       input.Path,
		SecretID:   secret.ID,
		TTLSeconds: int64(input.TTL.Seconds()),
		Renewable:  input.Renewable,
		ExpiresAt:  now.Add(input.TTL),
		Metadata:   input.Metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.leases.Create(ctx, lease); err != nil {
		return leasedomain.Lease{}, fmt.Errorf("create lease: %w", err)
	}
	return lease, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (leasedomain.Lease, error) {
	return s.leases.Get(ctx, id)
}

func (s *Service) Renew(ctx context.Context, id uuid.UUID, ttl time.Duration) (leasedomain.Lease, error) {
	lease, err := s.leases.Get(ctx, id)
	if err != nil {
		return leasedomain.Lease{}, err
	}
	if !lease.Renewable {
		return leasedomain.Lease{}, fmt.Errorf("lease is not renewable")
	}
	if lease.IsRevoked() {
		return leasedomain.Lease{}, fmt.Errorf("lease is revoked")
	}
	if lease.IsExpired(time.Now().UTC()) {
		return leasedomain.Lease{}, fmt.Errorf("lease has expired")
	}
	if ttl <= 0 {
		ttl = time.Duration(lease.TTLSeconds) * time.Second
	}
	if ttl > s.maxTTL {
		return leasedomain.Lease{}, fmt.Errorf("renewal ttl exceeds maximum")
	}
	expiresAt := time.Now().UTC().Add(ttl)
	if err := s.leases.UpdateExpiry(ctx, id, expiresAt); err != nil {
		return leasedomain.Lease{}, err
	}
	lease.ExpiresAt = expiresAt
	lease.TTLSeconds = int64(ttl.Seconds())
	lease.UpdatedAt = time.Now().UTC()
	return lease, nil
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID) (leasedomain.Lease, error) {
	lease, err := s.leases.Get(ctx, id)
	if err != nil {
		return leasedomain.Lease{}, err
	}
	if lease.IsRevoked() {
		return lease, nil
	}
	now := time.Now().UTC()
	if err := s.leases.Revoke(ctx, id, now); err != nil {
		return leasedomain.Lease{}, err
	}
	lease.RevokedAt = &now
	lease.UpdatedAt = now
	return lease, nil
}

func (s *Service) ExpireDue(ctx context.Context, now time.Time) (int, error) {
	leases, err := s.leases.ListActiveExpired(ctx, now)
	if err != nil {
		return 0, err
	}
	for _, lease := range leases {
		if err := s.leases.Revoke(ctx, lease.ID, lease.ExpiresAt); err != nil {
			return 0, err
		}
	}
	return len(leases), nil
}
