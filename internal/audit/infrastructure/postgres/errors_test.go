package postgres

import (
	"errors"
	"testing"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
)

func TestAuditConflictErrorWrap(t *testing.T) {
	if !errors.Is(chainConflictError("new", "old"), auditdomain.ErrChainConflict) {
		t.Fatal("chain conflict sentinel was lost")
	}
}
