package adapter

import (
	"context"
	"fmt"

	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
)

type StubHSMProvider struct {
	software *SoftwareProvider
}

func NewStubHSMProvider(masterKey, auditKey string) *StubHSMProvider {
	return &StubHSMProvider{software: NewSoftwareProvider(masterKey, auditKey)}
}

func (p *StubHSMProvider) Name() string {
	return "stub-hsm"
}

func (p *StubHSMProvider) Supports(capability backenddomain.Capability) bool {
	return p.software.Supports(capability)
}

func (p *StubHSMProvider) Encrypt(ctx context.Context, plaintext, aad []byte) (backenddomain.Ciphertext, error) {
	return p.software.Encrypt(ctx, plaintext, aad)
}

func (p *StubHSMProvider) Decrypt(ctx context.Context, ciphertext backenddomain.Ciphertext, aad []byte) ([]byte, error) {
	return p.software.Decrypt(ctx, ciphertext, aad)
}

func (p *StubHSMProvider) Sign(ctx context.Context, data []byte) (backenddomain.Signature, error) {
	sig, err := p.software.Sign(ctx, data)
	sig.Algorithm = "STUB-HSM-HMAC-SHA256"
	return sig, err
}

func (p *StubHSMProvider) Verify(ctx context.Context, data []byte, sig backenddomain.Signature) (bool, error) {
	if sig.Algorithm == "STUB-HSM-HMAC-SHA256" {
		sig.Algorithm = "HMAC-SHA256"
	}
	return p.software.Verify(ctx, data, sig)
}

func (p *StubHSMProvider) DeriveKey(ctx context.Context, material, salt []byte, length int) ([]byte, error) {
	return p.software.DeriveKey(ctx, material, salt, length)
}

func (p *StubHSMProvider) Random(ctx context.Context, length int) ([]byte, error) {
	return p.software.Random(ctx, length)
}

var _ backenddomain.Provider = (*StubHSMProvider)(nil)
var _ = fmt.Sprintf
