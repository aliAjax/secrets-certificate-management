package postgres

import (
	"errors"
	"testing"

	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

func TestRepositoryNotFoundWrap(t *testing.T) {
	if !errors.Is(wrapSecretNotFound("plant", "/keys/active", errors.New("no rows")), secretdomain.ErrSecretNotFound) {
		t.Fatal("repository lost not-found sentinel")
	}
}
