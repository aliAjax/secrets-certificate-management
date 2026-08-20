package application

import (
	"errors"
	"testing"

	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

func TestServiceReadPreservesNotFound(t *testing.T) {
	if !errors.Is(wrapSecretReadError(secretdomain.ErrSecretNotFound), secretdomain.ErrSecretNotFound) {
		t.Fatal("service lost not-found category")
	}
}
