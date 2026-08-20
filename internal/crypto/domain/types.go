package domain

import (
	"errors"

	"github.com/example/secrets-cert-platform/internal/backend/domain"
)

var ErrProviderUnavailable = errors.New("crypto provider unavailable")

func IsProviderUnavailable(err error) bool {
	return err != nil && err == ErrProviderUnavailable
}

type EncryptRequest struct {
	Plaintext []byte
	Context   []byte
}

type DecryptRequest struct {
	Ciphertext domain.Ciphertext
	Context    []byte
}

type SignRequest struct {
	Data []byte
}

type VerifyRequest struct {
	Data      []byte
	Signature domain.Signature
}

type DeriveRequest struct {
	Material []byte
	Salt     []byte
	Length   int
}

type RandomRequest struct {
	Length int
}
