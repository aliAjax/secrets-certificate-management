package postgres

import (
	"context"
	"testing"
)

func TestCanceledStorageContextIsPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	select {
	case <-repositoryContext(ctx).Done():
	default:
		t.Fatal("repository replaced canceled context")
	}
}
