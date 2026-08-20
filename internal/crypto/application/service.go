package application

import (
	"context"
	"fmt"

	"github.com/example/secrets-cert-platform/internal/backend/domain"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
)

type Service struct {
	provider domain.Provider
	aad      []byte
}

func NewService(provider domain.Provider, aad string) *Service {
	return &Service{provider: provider, aad: []byte(aad)}
}

func (s *Service) ProviderName() string {
	return s.provider.Name()
}

func (s *Service) Encrypt(ctx context.Context, req cryptodomain.EncryptRequest) (domain.Ciphertext, error) {
	if len(req.Plaintext) == 0 {
		return domain.Ciphertext{}, fmt.Errorf("plaintext is required")
	}
	out, err := s.provider.Encrypt(ctx, req.Plaintext, append([]byte(nil), s.aad...))
	if err != nil {
		return domain.Ciphertext{}, fmt.Errorf("encrypt: %w", err)
	}
	return out, nil
}

func (s *Service) Decrypt(ctx context.Context, req cryptodomain.DecryptRequest) ([]byte, error) {
	if len(req.Ciphertext.Data) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}
	plaintext, err := s.provider.Decrypt(ctx, req.Ciphertext, append([]byte(nil), s.aad...))
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}
	return plaintext, nil
}

func (s *Service) Sign(ctx context.Context, req cryptodomain.SignRequest) (domain.Signature, error) {
	if len(req.Data) == 0 {
		return domain.Signature{}, fmt.Errorf("data is required")
	}
	return s.provider.Sign(ctx, req.Data)
}

func (s *Service) Verify(ctx context.Context, req cryptodomain.VerifyRequest) (bool, error) {
	if len(req.Data) == 0 {
		return false, fmt.Errorf("data is required")
	}
	ok, err := s.provider.Verify(ctx, req.Data, req.Signature)
	if err != nil {
		return false, fmt.Errorf("verify signature: %w", err)
	}
	return ok, nil
}

func (s *Service) DeriveKey(ctx context.Context, req cryptodomain.DeriveRequest) ([]byte, error) {
	if len(req.Material) == 0 {
		return nil, fmt.Errorf("derivation material is required")
	}
	return s.provider.DeriveKey(ctx, req.Material, req.Salt, req.Length)
}

func (s *Service) Random(ctx context.Context, req cryptodomain.RandomRequest) ([]byte, error) {
	return s.provider.Random(ctx, req.Length)
}
