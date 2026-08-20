package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(ctx context.Context, policy policydomain.Policy) error {
	caps := make([]string, 0, len(policy.Capabilities))
	for _, c := range policy.Capabilities {
		caps = append(caps, string(c))
	}
	conditions, _ := json.Marshal(policy.Conditions)
	_, err := r.pool.Exec(ctx,
		`INSERT INTO policies
		 (id, name, namespace, path_prefix, identity, capabilities, conditions, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		policy.ID, policy.Name, policy.Namespace, policy.PathPrefix, policy.Identity,
		caps, conditions, policy.CreatedAt, policy.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}
	return nil
}

func (r *Repository) Get(ctx context.Context, name string) (policydomain.Policy, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, name, namespace, path_prefix, identity, capabilities, conditions, created_at, updated_at
		 FROM policies WHERE name = $1`, name,
	)
	return scanPolicy(row)
}

func (r *Repository) List(ctx context.Context, namespace string) ([]policydomain.Policy, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, namespace, path_prefix, identity, capabilities, conditions, created_at, updated_at
		 FROM policies WHERE namespace = $1 ORDER BY length(path_prefix) DESC`, namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []policydomain.Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *Repository) Delete(ctx context.Context, id interface{}) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanPolicy(row rowScanner) (policydomain.Policy, error) {
	var p policydomain.Policy
	var caps []string
	var conditions []byte
	if err := row.Scan(&p.ID, &p.Name, &p.Namespace, &p.PathPrefix, &p.Identity,
		&caps, &conditions, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return policydomain.Policy{}, fmt.Errorf("policy not found: %w", err)
	}
	for _, c := range caps {
		p.Capabilities = append(p.Capabilities, policydomain.Capability(c))
	}
	if len(conditions) > 0 {
		_ = json.Unmarshal(conditions, &p.Conditions)
	}
	if p.Conditions == nil {
		p.Conditions = map[string]string{}
	}
	return p, nil
}

var _ = time.Now
