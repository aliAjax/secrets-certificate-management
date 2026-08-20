package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) CreateNamespace(ctx context.Context, ns secretdomain.Namespace) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO namespaces (id, name, description, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		ns.ID, ns.Name, ns.Description, ns.CreatedAt, ns.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert namespace: %w", err)
	}
	return nil
}

func (r *Repository) GetNamespace(ctx context.Context, name string) (secretdomain.Namespace, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, name, description, created_at, updated_at
		 FROM namespaces WHERE name = $1`, name,
	)
	var ns secretdomain.Namespace
	if err := row.Scan(&ns.ID, &ns.Name, &ns.Description, &ns.CreatedAt, &ns.UpdatedAt); err != nil {
		return secretdomain.Namespace{}, fmt.Errorf("namespace %q not found: %w", name, err)
	}
	return ns, nil
}

func (r *Repository) ListNamespaces(ctx context.Context) ([]secretdomain.Namespace, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, description, created_at, updated_at
		 FROM namespaces ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	defer rows.Close()

	var out []secretdomain.Namespace
	for rows.Next() {
		var ns secretdomain.Namespace
		if err := rows.Scan(&ns.ID, &ns.Name, &ns.Description, &ns.CreatedAt, &ns.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan namespace: %w", err)
		}
		out = append(out, ns)
	}
	return out, rows.Err()
}

func (r *Repository) CreateSecretWithVersion(ctx context.Context, secret secretdomain.Secret, version secretdomain.SecretVersion) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO secrets (id, namespace, path, type, current_version, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		secret.ID, secret.Namespace, secret.Path, string(secret.Type), secret.CurrentVersion, secret.CreatedAt, secret.UpdatedAt,
	); err != nil {
		return fmt.Errorf("insert secret: %w", err)
	}
	if err := insertVersion(ctx, tx, version); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit secret transaction: %w", err)
	}
	return nil
}

func (r *Repository) GetSecret(ctx context.Context, namespace, path string) (secretdomain.Secret, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, namespace, path, type, current_version, created_at, updated_at
		 FROM secrets WHERE namespace = $1 AND path = $2`, namespace, path,
	)
	var s secretdomain.Secret
	var typ string
	if err := row.Scan(&s.ID, &s.Namespace, &s.Path, &typ, &s.CurrentVersion, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return secretdomain.Secret{}, fmt.Errorf("secret %s/%s not found: %w", namespace, path, err)
	}
	s.Type = secretdomain.SecretType(typ)
	return s, nil
}

func (r *Repository) ListSecrets(ctx context.Context, namespace string) ([]secretdomain.Secret, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, namespace, path, type, current_version, created_at, updated_at
		 FROM secrets WHERE namespace = $1 ORDER BY path`, namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()

	var out []secretdomain.Secret
	for rows.Next() {
		var s secretdomain.Secret
		var typ string
		if err := rows.Scan(&s.ID, &s.Namespace, &s.Path, &typ, &s.CurrentVersion, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		s.Type = secretdomain.SecretType(typ)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repository) CreateVersion(ctx context.Context, version secretdomain.SecretVersion) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO secret_versions
		 (id, secret_id, version, encrypted_value, value_sha256, key_version, state, delete_after, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		version.ID, version.SecretID, version.Version, version.EncryptedValue, version.ValueSHA256,
		version.KeyVersion, string(version.State), version.DeleteAfter, version.CreatedAt, version.UpdatedAt,
	); err != nil {
		return fmt.Errorf("insert secret version: %w", err)
	}
	return nil
}

func (r *Repository) GetVersion(ctx context.Context, secretID uuid.UUID, version int64) (secretdomain.SecretVersion, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, secret_id, version, encrypted_value, value_sha256, key_version, state, delete_after, created_at, updated_at
		 FROM secret_versions WHERE secret_id = $1 AND version = $2`, secretID, version,
	)
	return scanVersion(row)
}

func (r *Repository) ListVersions(ctx context.Context, secretID uuid.UUID) ([]secretdomain.SecretVersion, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, secret_id, version, encrypted_value, value_sha256, key_version, state, delete_after, created_at, updated_at
		 FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC`, secretID,
	)
	if err != nil {
		return nil, fmt.Errorf("list secret versions: %w", err)
	}
	defer rows.Close()

	var out []secretdomain.SecretVersion
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *Repository) SetVersionState(ctx context.Context, versionID uuid.UUID, state secretdomain.VersionState, deleteAfter *time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE secret_versions SET state = $2, delete_after = $3, updated_at = $4 WHERE id = $1`,
		versionID, string(state), deleteAfter, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("update version state: %w", err)
	}
	return nil
}

func (r *Repository) SetCurrentVersion(ctx context.Context, secretID uuid.UUID, version int64) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE secrets SET current_version = $2, updated_at = $3 WHERE id = $1`,
		secretID, version, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("update current version: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanVersion(row rowScanner) (secretdomain.SecretVersion, error) {
	var v secretdomain.SecretVersion
	var state string
	if err := row.Scan(&v.ID, &v.SecretID, &v.Version, &v.EncryptedValue, &v.ValueSHA256,
		&v.KeyVersion, &state, &v.DeleteAfter, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return secretdomain.SecretVersion{}, fmt.Errorf("version not found: %w", err)
	}
	v.State = secretdomain.VersionState(state)
	return v, nil
}

func insertVersion(ctx context.Context, tx pgx.Tx, version secretdomain.SecretVersion) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO secret_versions
		 (id, secret_id, version, encrypted_value, value_sha256, key_version, state, delete_after, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		version.ID, version.SecretID, version.Version, version.EncryptedValue, version.ValueSHA256,
		version.KeyVersion, string(version.State), version.DeleteAfter, version.CreatedAt, version.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert secret version: %w", err)
	}
	return nil
}
