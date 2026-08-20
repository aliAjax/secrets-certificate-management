package postgres

import (
	"strings"
	"testing"
)

func TestAuditAppendUsesTransactionChainLock(t *testing.T) {
	if !strings.Contains(auditChainLockSQL(), "pg_advisory_xact_lock") {
		t.Fatal("audit append does not use a transaction-scoped chain lock")
	}
}
