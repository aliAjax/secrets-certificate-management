package postgres

import (
	pkidomain "github.com/example/secrets-cert-platform/internal/pki/domain"
	"testing"
)

func TestInitializeCAPolicyMakesWritableMap(t *testing.T) {
	ca := initializeCAPolicy(pkidomain.CA{})
	if ca.Policy == nil {
		t.Fatal("CA policy map is nil")
	}
	ca.Policy["profile"] = "server"
}
