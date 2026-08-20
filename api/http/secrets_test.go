package httpapi

import (
	"fmt"
	"net/http"
	"testing"

	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

func TestSecretReadNotFoundMapsTo404(t *testing.T) {
	if got := secretReadStatus(fmt.Errorf("read: %w", secretdomain.ErrSecretNotFound)); got != http.StatusNotFound {
		t.Fatalf("status=%d want=%d", got, http.StatusNotFound)
	}
}
