package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	pkidomain "github.com/example/secrets-cert-platform/internal/pki/domain"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func initializeCAPolicy(ca pkidomain.CA) pkidomain.CA {
	if ca.Policy == nil {
		ca.Policy = map[string]string{}
	}
	return ca
}

func (r *Repository) CreateCA(ctx context.Context, ca pkidomain.CA) error {
	ca = initializeCAPolicy(ca)
	policy, _ := json.Marshal(ca.Policy)
	_, err := r.pool.Exec(ctx,
		`INSERT INTO pki_cas
		 (id, name, namespace, ca_type, parent_id, certificate_pem, encrypted_private_key, key_version,
		  serial_number, policy, not_before, not_after, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		ca.ID, ca.Name, ca.Namespace, string(ca.Type), ca.ParentID, ca.CertificatePEM,
		ca.EncryptedPrivateKey, ca.KeyVersion, ca.SerialNumber, policy, ca.NotBefore, ca.NotAfter,
		string(ca.Status), ca.CreatedAt, ca.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert ca: %w", err)
	}
	return nil
}

func (r *Repository) GetCA(ctx context.Context, name string) (pkidomain.CA, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, name, namespace, ca_type, parent_id, certificate_pem, encrypted_private_key, key_version,
		 serial_number, policy, not_before, not_after, status, created_at, updated_at
		 FROM pki_cas WHERE name = $1`, name,
	)
	return scanCA(row)
}

func (r *Repository) GetCAByID(ctx context.Context, id uuid.UUID) (pkidomain.CA, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, name, namespace, ca_type, parent_id, certificate_pem, encrypted_private_key, key_version,
		 serial_number, policy, not_before, not_after, status, created_at, updated_at
		 FROM pki_cas WHERE id = $1`, id,
	)
	return scanCA(row)
}

func (r *Repository) ListCAs(ctx context.Context, namespace string) ([]pkidomain.CA, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, namespace, ca_type, parent_id, certificate_pem, encrypted_private_key, key_version,
		 serial_number, policy, not_before, not_after, status, created_at, updated_at
		 FROM pki_cas WHERE namespace = $1 ORDER BY name`, namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("list cas: %w", err)
	}
	defer rows.Close()

	var out []pkidomain.CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ca: %w", err)
		}
		out = append(out, ca)
	}
	return out, rows.Err()
}

func (r *Repository) CreateCertificate(ctx context.Context, cert pkidomain.Certificate) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO certificates
		 (id, namespace, ca_id, common_name, serial_number, certificate_pem, encrypted_private_key, key_version,
		  status, not_before, not_after, revoked_at, revocation_reason, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		cert.ID, cert.Namespace, cert.CAID, cert.CommonName, cert.SerialNumber, cert.CertificatePEM,
		cert.EncryptedPrivateKey, cert.KeyVersion, string(cert.Status), cert.NotBefore, cert.NotAfter,
		cert.RevokedAt, cert.RevocationReason, cert.CreatedAt, cert.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert certificate: %w", err)
	}
	return nil
}

func (r *Repository) GetCertificate(ctx context.Context, namespace, serial string) (pkidomain.Certificate, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, namespace, ca_id, common_name, serial_number, certificate_pem, encrypted_private_key, key_version,
		 status, not_before, not_after, revoked_at, revocation_reason, created_at, updated_at
		 FROM certificates WHERE namespace = $1 AND serial_number = $2`, namespace, serial,
	)
	return scanCertificate(row)
}

func (r *Repository) GetCertificateBySerial(ctx context.Context, serial string) (pkidomain.Certificate, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, namespace, ca_id, common_name, serial_number, certificate_pem, encrypted_private_key, key_version,
		 status, not_before, not_after, revoked_at, revocation_reason, created_at, updated_at
		 FROM certificates WHERE serial_number = $1`, serial,
	)
	return scanCertificate(row)
}

func (r *Repository) ListCertificates(ctx context.Context, namespace string) ([]pkidomain.Certificate, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, namespace, ca_id, common_name, serial_number, certificate_pem, encrypted_private_key, key_version,
		 status, not_before, not_after, revoked_at, revocation_reason, created_at, updated_at
		 FROM certificates WHERE namespace = $1 ORDER BY created_at DESC`, namespace,
	)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var out []pkidomain.Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, rows.Err()
}

func (r *Repository) RevokeCertificate(ctx context.Context, id uuid.UUID, revokedAt time.Time, reason string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE certificates SET status = $2, revoked_at = $3, revocation_reason = $4, updated_at = $5
		 WHERE id = $1`,
		id, string(pkidomain.CertificateRevoked), revokedAt, reason, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	return nil
}

func (r *Repository) CreateRevocation(ctx context.Context, revocation pkidomain.Revocation) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO revocations (id, certificate_id, serial_number, reason, revoked_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		revocation.ID, revocation.CertificateID, revocation.SerialNumber, revocation.Reason,
		revocation.RevokedAt, revocation.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert revocation: %w", err)
	}
	return nil
}

func (r *Repository) ListRevocations(ctx context.Context, caID uuid.UUID) ([]pkidomain.Revocation, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT r.id, r.certificate_id, r.serial_number, r.reason, r.revoked_at, r.created_at
		 FROM revocations r
		 JOIN certificates c ON c.id = r.certificate_id
		 WHERE c.ca_id = $1 ORDER BY r.revoked_at DESC`, caID,
	)
	if err != nil {
		return nil, fmt.Errorf("list revocations: %w", err)
	}
	defer rows.Close()

	var out []pkidomain.Revocation
	for rows.Next() {
		var rev pkidomain.Revocation
		if err := rows.Scan(&rev.ID, &rev.CertificateID, &rev.SerialNumber, &rev.Reason, &rev.RevokedAt, &rev.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan revocation: %w", err)
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanCA(row rowScanner) (pkidomain.CA, error) {
	var ca pkidomain.CA
	var typ string
	var status string
	var policy []byte
	if err := row.Scan(&ca.ID, &ca.Name, &ca.Namespace, &typ, &ca.ParentID, &ca.CertificatePEM,
		&ca.EncryptedPrivateKey, &ca.KeyVersion, &ca.SerialNumber, &policy, &ca.NotBefore, &ca.NotAfter,
		&status, &ca.CreatedAt, &ca.UpdatedAt); err != nil {
		return pkidomain.CA{}, fmt.Errorf("ca not found: %w", err)
	}
	ca.Type = pkidomain.CAType(typ)
	ca.Status = pkidomain.Status(status)
	if len(policy) > 0 {
		_ = json.Unmarshal(policy, &ca.Policy)
	}
	if ca.Policy == nil {
		ca.Policy = map[string]string{}
	}
	return ca, nil
}

func scanCertificate(row rowScanner) (pkidomain.Certificate, error) {
	var cert pkidomain.Certificate
	var status string
	if err := row.Scan(&cert.ID, &cert.Namespace, &cert.CAID, &cert.CommonName, &cert.SerialNumber,
		&cert.CertificatePEM, &cert.EncryptedPrivateKey, &cert.KeyVersion, &status, &cert.NotBefore,
		&cert.NotAfter, &cert.RevokedAt, &cert.RevocationReason, &cert.CreatedAt, &cert.UpdatedAt); err != nil {
		return pkidomain.Certificate{}, fmt.Errorf("certificate not found: %w", err)
	}
	cert.Status = pkidomain.CertificateStatus(status)
	return cert, nil
}
