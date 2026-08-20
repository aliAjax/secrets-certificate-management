package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	CreateNamespace(ctx context.Context, ns Namespace) error
	GetNamespace(ctx context.Context, name string) (Namespace, error)
	ListNamespaces(ctx context.Context) ([]Namespace, error)

	CreateSecretWithVersion(ctx context.Context, secret Secret, version SecretVersion) error
	GetSecret(ctx context.Context, namespace, path string) (Secret, error)
	ListSecrets(ctx context.Context, namespace string) ([]Secret, error)
	CreateVersion(ctx context.Context, version SecretVersion) error
	GetVersion(ctx context.Context, secretID uuid.UUID, version int64) (SecretVersion, error)
	ListVersions(ctx context.Context, secretID uuid.UUID) ([]SecretVersion, error)
	SetVersionState(ctx context.Context, versionID uuid.UUID, state VersionState, deleteAfter *time.Time) error
	SetCurrentVersion(ctx context.Context, secretID uuid.UUID, version int64) error
}
