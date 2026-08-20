package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	CreateCA(ctx context.Context, ca CA) error
	GetCA(ctx context.Context, name string) (CA, error)
	GetCAByID(ctx context.Context, id uuid.UUID) (CA, error)
	ListCAs(ctx context.Context, namespace string) ([]CA, error)

	CreateCertificate(ctx context.Context, cert Certificate) error
	GetCertificate(ctx context.Context, namespace, serial string) (Certificate, error)
	GetCertificateBySerial(ctx context.Context, serial string) (Certificate, error)
	ListCertificates(ctx context.Context, namespace string) ([]Certificate, error)
	RevokeCertificate(ctx context.Context, id uuid.UUID, revokedAt time.Time, reason string) error
	CreateRevocation(ctx context.Context, revocation Revocation) error
	ListRevocations(ctx context.Context, caID uuid.UUID) ([]Revocation, error)
}
