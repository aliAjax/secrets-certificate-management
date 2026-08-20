package application

import (
	"context"
	"testing"
)

func TestRenewalContextKeepsDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	select {
	case <-renewalContext(ctx).Done():
	default:
		t.Fatal("renewal discarded request context")
	}
}
