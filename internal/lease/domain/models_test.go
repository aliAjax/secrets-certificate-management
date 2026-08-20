package domain

import (
	"context"
	"errors"
	"testing"
)

func TestContextErrorSeesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(ContextError(ctx), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
