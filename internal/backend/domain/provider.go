package domain

import "context"

type Capability string

const (
	CapabilityEncrypt   Capability = "encrypt"
	CapabilityDecrypt   Capability = "decrypt"
	CapabilitySign      Capability = "sign"
	CapabilityVerify    Capability = "verify"
	CapabilityDeriveKey Capability = "derive"
	CapabilityRandom    Capability = "random"
)

type Ciphertext struct {
	Data       []byte `json:"data"`
	KeyVersion string `json:"key_version"`
}

type Signature struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm"`
}

type Provider interface {
	Name() string
	Supports(Capability) bool
	Encrypt(ctx context.Context, plaintext, aad []byte) (Ciphertext, error)
	Decrypt(ctx context.Context, ciphertext Ciphertext, aad []byte) ([]byte, error)
	Sign(ctx context.Context, data []byte) (Signature, error)
	Verify(ctx context.Context, data []byte, sig Signature) (bool, error)
	DeriveKey(ctx context.Context, material []byte, salt []byte, length int) ([]byte, error)
	Random(ctx context.Context, length int) ([]byte, error)
}
