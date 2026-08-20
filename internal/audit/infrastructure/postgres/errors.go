package postgres

import (
	"fmt"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
)

func chainConflictError(actual, expected string) error {
	return fmt.Errorf("audit chain moved from %q to %q: %w", expected, actual, auditdomain.ErrChainConflict)
}
