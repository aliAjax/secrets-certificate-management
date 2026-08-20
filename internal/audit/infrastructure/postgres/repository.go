package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func auditChainLockSQL() string { return "" }

func (r *Repository) Append(ctx context.Context, event auditdomain.Event) (auditdomain.Event, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return event, fmt.Errorf("begin audit transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if statement := auditChainLockSQL(); statement != "" {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return event, fmt.Errorf("lock audit chain: %w", err)
		}
	}

	var previous string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE((SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1), 'genesis')`,
	).Scan(&previous); err != nil {
		return event, fmt.Errorf("read previous audit hash: %w", err)
	}
	if previous != event.PreviousHash {
		return event, fmt.Errorf("audit chain moved while appending: %v", auditdomain.ErrChainConflict)
	}

	metadata, _ := json.Marshal(event.Metadata)
	var sequence int64
	err = tx.QueryRow(ctx,
		`INSERT INTO audit_events
		 (id, event_hash, previous_hash, actor, namespace, path, action, result, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING sequence`,
		event.ID, event.EventHash, event.PreviousHash, event.Actor, event.Namespace,
		event.Path, event.Action, event.Result, metadata, event.CreatedAt,
	).Scan(&sequence)
	if err != nil {
		return event, fmt.Errorf("insert audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return event, fmt.Errorf("commit audit event: %w", err)
	}
	event.Sequence = sequence
	return event, nil
}

func (r *Repository) LastHash(ctx context.Context) (string, error) {
	var hash string
	if err := r.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1), 'genesis')`,
	).Scan(&hash); err != nil {
		return "", fmt.Errorf("read last audit hash: %w", err)
	}
	return hash, nil
}

func (r *Repository) List(ctx context.Context, filter auditdomain.ListFilter) ([]auditdomain.Event, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, sequence, event_hash, previous_hash, actor, namespace, path, action, result, metadata, created_at
		 FROM audit_events
		 WHERE ($1 = '' OR namespace = $1)
		   AND ($2 = '' OR path = $2)
		   AND ($3 = '' OR actor = $3)
		   AND ($4 = '' OR action = $4)
		 ORDER BY sequence DESC
		 LIMIT $5`,
		filter.Namespace, filter.Path, filter.Actor, filter.Action, filter.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (r *Repository) ListAll(ctx context.Context) ([]auditdomain.Event, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, sequence, event_hash, previous_hash, actor, namespace, path, action, result, metadata, created_at
		 FROM audit_events ORDER BY sequence ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list all audit events: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows pgx.Rows) ([]auditdomain.Event, error) {
	var out []auditdomain.Event
	for rows.Next() {
		var e auditdomain.Event
		var metadata []byte
		if err := rows.Scan(&e.ID, &e.Sequence, &e.EventHash, &e.PreviousHash, &e.Actor,
			&e.Namespace, &e.Path, &e.Action, &e.Result, &metadata, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &e.Metadata)
		}
		if e.Metadata == nil {
			e.Metadata = map[string]string{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

var _ = time.Now
