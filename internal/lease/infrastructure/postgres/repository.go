package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	leasedomain "github.com/example/secrets-cert-platform/internal/lease/domain"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(ctx context.Context, lease leasedomain.Lease) error {
	metadata, _ := json.Marshal(lease.Metadata)
	_, err := r.pool.Exec(ctx,
		`INSERT INTO leases
		 (id, namespace, path, secret_id, ttl_seconds, renewable, expires_at, revoked_at, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		lease.ID, lease.Namespace, lease.Path, lease.SecretID, lease.TTLSeconds, lease.Renewable,
		lease.ExpiresAt, lease.RevokedAt, metadata, lease.CreatedAt, lease.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert lease: %w", err)
	}
	return nil
}

func (r *Repository) Get(ctx context.Context, id uuid.UUID) (leasedomain.Lease, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, namespace, path, secret_id, ttl_seconds, renewable, expires_at, revoked_at, metadata, created_at, updated_at
		 FROM leases WHERE id = $1`, id,
	)
	return scanLease(row)
}

func (r *Repository) UpdateExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE leases SET expires_at = $2, updated_at = $3 WHERE id = $1`,
		id, expiresAt, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("update lease expiry: %w", err)
	}
	return nil
}

func (r *Repository) Revoke(ctx context.Context, id uuid.UUID, revokedAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE leases SET revoked_at = $2, updated_at = $3 WHERE id = $1`,
		id, revokedAt, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("revoke lease: %w", err)
	}
	return nil
}

func (r *Repository) ListActiveExpired(ctx context.Context, now time.Time) ([]leasedomain.Lease, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, namespace, path, secret_id, ttl_seconds, renewable, expires_at, revoked_at, metadata, created_at, updated_at
		 FROM leases WHERE revoked_at IS NULL AND expires_at <= $1`, now,
	)
	if err != nil {
		return nil, fmt.Errorf("list expired leases: %w", err)
	}
	defer rows.Close()

	var out []leasedomain.Lease
	for rows.Next() {
		lease, err := scanLease(rows)
		if err != nil {
			return nil, fmt.Errorf("scan expired lease: %w", err)
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanLease(row rowScanner) (leasedomain.Lease, error) {
	var l leasedomain.Lease
	var metadata []byte
	if err := row.Scan(&l.ID, &l.Namespace, &l.Path, &l.SecretID, &l.TTLSeconds, &l.Renewable,
		&l.ExpiresAt, &l.RevokedAt, &metadata, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return leasedomain.Lease{}, fmt.Errorf("lease not found: %w", err)
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &l.Metadata)
	}
	if l.Metadata == nil {
		l.Metadata = map[string]string{}
	}
	return l, nil
}
