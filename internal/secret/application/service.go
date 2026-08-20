package application

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
	"github.com/example/secrets-cert-platform/internal/crypto/application"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

type Service struct {
	repo        secretdomain.Repository
	crypto      *application.Service
	deletionTTL time.Duration
}

func NewService(repo secretdomain.Repository, cryptoService *application.Service, deletionTTL time.Duration) *Service {
	return &Service{repo: repo, crypto: cryptoService, deletionTTL: deletionTTL}
}

func (s *Service) CreateNamespace(ctx context.Context, name, description string) (secretdomain.Namespace, error) {
	name, err := secretdomain.NormalizeNamespace(name)
	if err != nil {
		return secretdomain.Namespace{}, err
	}
	if _, err := s.repo.GetNamespace(ctx, name); err == nil {
		return secretdomain.Namespace{}, fmt.Errorf("namespace already exists")
	}
	now := time.Now().UTC()
	ns := secretdomain.Namespace{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.repo.CreateNamespace(ctx, ns); err != nil {
		return secretdomain.Namespace{}, fmt.Errorf("create namespace: %w", err)
	}
	return ns, nil
}

func (s *Service) GetNamespace(ctx context.Context, name string) (secretdomain.Namespace, error) {
	name, err := secretdomain.NormalizeNamespace(name)
	if err != nil {
		return secretdomain.Namespace{}, err
	}
	return s.repo.GetNamespace(ctx, name)
}

func (s *Service) ListNamespaces(ctx context.Context) ([]secretdomain.Namespace, error) {
	return s.repo.ListNamespaces(ctx)
}

func (s *Service) PutSecret(ctx context.Context, input secretdomain.PutSecretInput) (secretdomain.VersionMetadata, error) {
	namespace, err := secretdomain.NormalizeNamespace(input.Namespace)
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	path, err := secretdomain.NormalizePath(input.Path)
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	secretType, err := secretdomain.ValidateType(string(input.Type))
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	if len(input.Value) == 0 {
		return secretdomain.VersionMetadata{}, fmt.Errorf("secret value is required")
	}
	if _, err := s.repo.GetNamespace(ctx, namespace); err != nil {
		return secretdomain.VersionMetadata{}, fmt.Errorf("namespace must exist: %w", err)
	}

	encrypted, err := s.crypto.Encrypt(ctx, cryptodomain.EncryptRequest{Plaintext: input.Value})
	if err != nil {
		return secretdomain.VersionMetadata{}, fmt.Errorf("encrypt secret value: %w", err)
	}
	digest := sha256.Sum256(input.Value)
	now := time.Now().UTC()
	secret, err := s.repo.GetSecret(ctx, namespace, path)
	if err != nil {
		secret = secretdomain.Secret{
			ID:             uuid.New(),
			Namespace:      namespace,
			Path:           path,
			Type:           secretType,
			CurrentVersion: 0,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		version := secretdomain.SecretVersion{
			ID:             uuid.New(),
			SecretID:       secret.ID,
			Version:        1,
			EncryptedValue: encrypted.Data,
			ValueSHA256:    digest[:],
			KeyVersion:     encrypted.KeyVersion,
			State:          secretdomain.VersionStateActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		secret.CurrentVersion = 1
		if err := s.repo.CreateSecretWithVersion(ctx, secret, version); err != nil {
			return secretdomain.VersionMetadata{}, fmt.Errorf("create secret with version: %w", err)
		}
		return metadataFromVersion(version), nil
	}

	if secret.Type != secretType {
		return secretdomain.VersionMetadata{}, fmt.Errorf("secret type cannot be changed")
	}
	next := secret.CurrentVersion + 1
	version := secretdomain.SecretVersion{
		ID:             uuid.New(),
		SecretID:       secret.ID,
		Version:        next,
		EncryptedValue: encrypted.Data,
		ValueSHA256:    digest[:],
		KeyVersion:     encrypted.KeyVersion,
		State:          secretdomain.VersionStateActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.repo.CreateVersion(ctx, version); err != nil {
		return secretdomain.VersionMetadata{}, fmt.Errorf("create secret version: %w", err)
	}
	if err := s.repo.SetCurrentVersion(ctx, secret.ID, next); err != nil {
		return secretdomain.VersionMetadata{}, fmt.Errorf("set current version: %w", err)
	}
	return metadataFromVersion(version), nil
}

func (s *Service) GetSecret(ctx context.Context, namespace, path string, version int64) ([]byte, secretdomain.VersionMetadata, error) {
	namespace, err := secretdomain.NormalizeNamespace(namespace)
	if err != nil {
		return nil, secretdomain.VersionMetadata{}, err
	}
	path, err = secretdomain.NormalizePath(path)
	if err != nil {
		return nil, secretdomain.VersionMetadata{}, err
	}
	secret, err := s.repo.GetSecret(ctx, namespace, path)
	if err != nil {
		return nil, secretdomain.VersionMetadata{}, fmt.Errorf("get secret: %w", err)
	}
	if version == 0 {
		version = secret.CurrentVersion
	}
	stored, err := s.repo.GetVersion(ctx, secret.ID, version)
	if err != nil {
		return nil, secretdomain.VersionMetadata{}, fmt.Errorf("get version: %w", err)
	}
	if stored.State != secretdomain.VersionStateActive {
		return nil, secretdomain.VersionMetadata{}, fmt.Errorf("version is not active")
	}
	plaintext, err := s.crypto.Decrypt(ctx, cryptodomain.DecryptRequest{Ciphertext: toCiphertext(stored)})
	if err != nil {
		return nil, secretdomain.VersionMetadata{}, fmt.Errorf("decrypt secret value: %w", err)
	}
	return plaintext, metadataFromVersion(stored), nil
}

func (s *Service) GetSecretMetadata(ctx context.Context, namespace, path string) (secretdomain.Secret, error) {
	namespace, err := secretdomain.NormalizeNamespace(namespace)
	if err != nil {
		return secretdomain.Secret{}, err
	}
	path, err = secretdomain.NormalizePath(path)
	if err != nil {
		return secretdomain.Secret{}, err
	}
	return s.repo.GetSecret(ctx, namespace, path)
}

func (s *Service) ListSecrets(ctx context.Context, namespace string) ([]secretdomain.Secret, error) {
	namespace, err := secretdomain.NormalizeNamespace(namespace)
	if err != nil {
		return nil, err
	}
	return s.repo.ListSecrets(ctx, namespace)
}

func (s *Service) ListVersions(ctx context.Context, namespace, path string) ([]secretdomain.VersionMetadata, error) {
	namespace, err := secretdomain.NormalizeNamespace(namespace)
	if err != nil {
		return nil, err
	}
	path, err = secretdomain.NormalizePath(path)
	if err != nil {
		return nil, err
	}
	secret, err := s.repo.GetSecret(ctx, namespace, path)
	if err != nil {
		return nil, err
	}
	versions, err := s.repo.ListVersions(ctx, secret.ID)
	if err != nil {
		return nil, err
	}
	out := make([]secretdomain.VersionMetadata, 0, len(versions))
	for _, v := range versions {
		out = append(out, metadataFromVersion(v))
	}
	return out, nil
}

func (s *Service) SoftDeleteVersion(ctx context.Context, namespace, path string, version int64) (secretdomain.VersionMetadata, error) {
	v, _, err := s.resolveVersion(ctx, namespace, path, version)
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	after := time.Now().UTC().Add(s.deletionTTL)
	if err := s.repo.SetVersionState(ctx, v.ID, secretdomain.VersionStateDeleted, &after); err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	v.State = secretdomain.VersionStateDeleted
	v.DeleteAfter = &after
	return metadataFromVersion(v), nil
}

func (s *Service) RestoreVersion(ctx context.Context, namespace, path string, version int64) (secretdomain.VersionMetadata, error) {
	v, _, err := s.resolveVersion(ctx, namespace, path, version)
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	if err := s.repo.SetVersionState(ctx, v.ID, secretdomain.VersionStateActive, nil); err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	v.State = secretdomain.VersionStateActive
	v.DeleteAfter = nil
	return metadataFromVersion(v), nil
}

func (s *Service) DestroyVersion(ctx context.Context, namespace, path string, version int64) error {
	v, _, err := s.resolveVersion(ctx, namespace, path, version)
	if err != nil {
		return err
	}
	if err := s.repo.SetVersionState(ctx, v.ID, secretdomain.VersionStateDestroyed, nil); err != nil {
		return err
	}
	return nil
}

func (s *Service) Rollback(ctx context.Context, namespace, path string, version int64) (secretdomain.VersionMetadata, error) {
	secret, err := s.GetSecretMetadata(ctx, namespace, path)
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	if _, err := s.repo.GetVersion(ctx, secret.ID, version); err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	if err := s.repo.SetCurrentVersion(ctx, secret.ID, version); err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	v, err := s.repo.GetVersion(ctx, secret.ID, version)
	if err != nil {
		return secretdomain.VersionMetadata{}, err
	}
	return metadataFromVersion(v), nil
}

func (s *Service) resolveVersion(ctx context.Context, namespace, path string, version int64) (secretdomain.SecretVersion, secretdomain.Secret, error) {
	namespace, err := secretdomain.NormalizeNamespace(namespace)
	if err != nil {
		return secretdomain.SecretVersion{}, secretdomain.Secret{}, err
	}
	path, err = secretdomain.NormalizePath(path)
	if err != nil {
		return secretdomain.SecretVersion{}, secretdomain.Secret{}, err
	}
	secret, err := s.repo.GetSecret(ctx, namespace, path)
	if err != nil {
		return secretdomain.SecretVersion{}, secretdomain.Secret{}, err
	}
	if version == 0 {
		version = secret.CurrentVersion
	}
	v, err := s.repo.GetVersion(ctx, secret.ID, version)
	if err != nil {
		return secretdomain.SecretVersion{}, secretdomain.Secret{}, err
	}
	return v, secret, nil
}

func toCiphertext(v secretdomain.SecretVersion) backenddomain.Ciphertext {
	return backenddomain.Ciphertext{Data: v.EncryptedValue, KeyVersion: v.KeyVersion}
}

func metadataFromVersion(v secretdomain.SecretVersion) secretdomain.VersionMetadata {
	return secretdomain.VersionMetadata{
		ID:          v.ID,
		Version:     v.Version,
		State:       v.State,
		KeyVersion:  v.KeyVersion,
		CreatedAt:   v.CreatedAt,
		DeleteAfter: v.DeleteAfter,
	}
}
