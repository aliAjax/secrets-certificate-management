package application

import (
	"context"
	"errors"
	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
	"testing"
)

type failProvider struct{}

func (failProvider) Name() string                           { return "fail" }
func (failProvider) Supports(backenddomain.Capability) bool { return true }
func (failProvider) Encrypt(context.Context, []byte, []byte) (backenddomain.Ciphertext, error) {
	return backenddomain.Ciphertext{}, cryptodomain.ErrProviderUnavailable
}
func (failProvider) Decrypt(context.Context, backenddomain.Ciphertext, []byte) ([]byte, error) {
	return nil, cryptodomain.ErrProviderUnavailable
}
func (failProvider) Sign(context.Context, []byte) (backenddomain.Signature, error) {
	return backenddomain.Signature{}, cryptodomain.ErrProviderUnavailable
}
func (failProvider) Verify(context.Context, []byte, backenddomain.Signature) (bool, error) {
	return false, cryptodomain.ErrProviderUnavailable
}
func (failProvider) DeriveKey(context.Context, []byte, []byte, int) ([]byte, error) {
	return nil, cryptodomain.ErrProviderUnavailable
}
func (failProvider) Random(context.Context, int) ([]byte, error) {
	return nil, cryptodomain.ErrProviderUnavailable
}
func TestEncryptPreservesProviderError(t *testing.T) {
	_, err := NewService(failProvider{}, "aad").Encrypt(context.Background(), cryptodomain.EncryptRequest{Plaintext: []byte("secret")})
	if !errors.Is(err, cryptodomain.ErrProviderUnavailable) {
		t.Fatalf("lost provider error: %v", err)
	}
}
