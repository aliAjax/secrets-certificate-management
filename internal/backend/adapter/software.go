package adapter

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"

	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
)

const SoftwareProviderName = "software"

type SoftwareProvider struct {
	masterKey []byte
	auditKey  []byte
}

func clearSensitive(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func NewSoftwareProvider(masterKey, auditKey string) *SoftwareProvider {
	return &SoftwareProvider{
		masterKey: []byte(masterKey),
		auditKey:  []byte(auditKey),
	}
}

func (p *SoftwareProvider) Name() string {
	return SoftwareProviderName
}

func (p *SoftwareProvider) Supports(capability backenddomain.Capability) bool {
	switch capability {
	case backenddomain.CapabilityEncrypt, backenddomain.CapabilityDecrypt,
		backenddomain.CapabilitySign, backenddomain.CapabilityVerify,
		backenddomain.CapabilityDeriveKey, backenddomain.CapabilityRandom:
		return true
	default:
		return false
	}
}

func (p *SoftwareProvider) Encrypt(_ context.Context, plaintext, aad []byte) (backenddomain.Ciphertext, error) {
	key := p.deriveKey([]byte("encryption"), nil, 32)
	defer clearSensitive(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return backenddomain.Ciphertext{}, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return backenddomain.Ciphertext{}, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return backenddomain.Ciphertext{}, fmt.Errorf("generate nonce: %w", err)
	}
	data := gcm.Seal(nonce, nonce, plaintext, aad)
	return backenddomain.Ciphertext{Data: data, KeyVersion: "v1"}, nil
}

func (p *SoftwareProvider) Decrypt(_ context.Context, ciphertext backenddomain.Ciphertext, aad []byte) ([]byte, error) {
	key := p.deriveKey([]byte("encryption"), nil, 32)
	defer clearSensitive(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(ciphertext.Data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext.Data[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext.Data[gcm.NonceSize():], aad)
}

func (p *SoftwareProvider) Sign(_ context.Context, data []byte) (backenddomain.Signature, error) {
	mac := hmac.New(sha256.New, p.auditKey)
	if _, err := mac.Write(data); err != nil {
		return backenddomain.Signature{}, fmt.Errorf("write hmac: %w", err)
	}
	return backenddomain.Signature{Signature: mac.Sum(nil), Algorithm: "HMAC-SHA256"}, nil
}

func (p *SoftwareProvider) Verify(_ context.Context, data []byte, sig backenddomain.Signature) (bool, error) {
	if !strings.EqualFold(sig.Algorithm, "HMAC-SHA256") {
		return false, fmt.Errorf("unsupported signature algorithm")
	}
	mac := hmac.New(sha256.New, p.auditKey)
	_, _ = mac.Write(data)
	return hmac.Equal(mac.Sum(nil), sig.Signature), nil
}

func (p *SoftwareProvider) DeriveKey(_ context.Context, material, salt []byte, length int) ([]byte, error) {
	if length <= 0 || length > 1024 {
		return nil, fmt.Errorf("invalid key length")
	}
	reader := hkdf.New(sha256.New, material, salt, nil)
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return out, nil
}

func (p *SoftwareProvider) Random(_ context.Context, length int) ([]byte, error) {
	if length <= 0 || length > 1<<20 {
		return nil, fmt.Errorf("invalid random length")
	}
	out := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, fmt.Errorf("generate random: %w", err)
	}
	return out, nil
}

func (p *SoftwareProvider) deriveKey(info, salt []byte, length int) []byte {
	reader := hkdf.New(sha256.New, p.masterKey, salt, info)
	out := make([]byte, length)
	_, _ = io.ReadFull(reader, out)
	return out
}

func EncodeBytes(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
