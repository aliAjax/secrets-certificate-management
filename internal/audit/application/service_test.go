package application

import (
	"context"
	"sync"
	"testing"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
	backendadapter "github.com/example/secrets-cert-platform/internal/backend/adapter"
	cryptoapplication "github.com/example/secrets-cert-platform/internal/crypto/application"
)

type retryRepo struct {
	mu sync.Mutex
	appends int
	start chan struct{}
}

func (r *retryRepo) LastHash(context.Context) (string, error) { return "genesis", nil }

func (r *retryRepo) Append(_ context.Context, e auditdomain.Event) (auditdomain.Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appends++
	if r.appends == 1 {
		return e, auditdomain.ErrChainConflict
	}
	return e, nil
}
func (r *retryRepo) List(context.Context, auditdomain.ListFilter) ([]auditdomain.Event, error) {
	return nil, nil
}
func (r *retryRepo) ListAll(context.Context) ([]auditdomain.Event, error) { return nil, nil }
func TestRecordRetriesChainConflict(t *testing.T) {
	repo := &retryRepo{start: make(chan struct{})}
	start := make(chan struct{})
	provider := backendadapter.NewSoftwareProvider("0123456789abcdef", "fedcba9876543210")
	svc := NewService(repo, cryptoapplication.NewService(provider, "audit-test"))
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := svc.Record(context.Background(), auditdomain.RecordInput{Actor: "operator", Namespace: "plant", Path: "/keys", Action: "rotate", Result: "ok"})
			errs <- err
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("record should retry chain conflict: %v", err)
		}
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.appends < 3 {
		t.Fatalf("append attempts = %d, want a retry after concurrent conflict", repo.appends)
	}
}
